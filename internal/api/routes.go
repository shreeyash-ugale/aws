package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/go-chi/chi/v5"

	"github.com/shreeyash-ugale/secureFile/internal/auth"
	"github.com/shreeyash-ugale/secureFile/internal/awsx"
	"github.com/shreeyash-ugale/secureFile/internal/config"
	"github.com/shreeyash-ugale/secureFile/internal/crypto"
	"github.com/shreeyash-ugale/secureFile/internal/metadata"
	"github.com/shreeyash-ugale/secureFile/internal/storage"
)

func RegisterRoutes(r *chi.Mux, cfg *config.Config) {
	clients, err := awsx.New(cfg.Region)
	if err != nil {
		log.Fatalf("aws clients: %v", err)
	}
	cipher := crypto.NewEnvelopeCipher(clients.KMS, cfg.KMSKeyID)
	store := storage.NewS3Store(clients.S3, cfg.Bucket, cipher)
	tokens := auth.NewTokenStore(clients.S3, cfg.Bucket)

	// Optional DynamoDB metadata store
	var metaStore *metadata.Store
	if cfg.DynamoTable != "" && clients.DDB != nil {
		metaStore = metadata.NewStore(cfg.DynamoTable, clients.DDB)
	}

	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK); w.Write([]byte("ok")) })

	// Simple test route to verify server and config
	r.Get("/test/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"status": "ok",
			"region": cfg.Region,
			"bucket": cfg.Bucket,
			"time":   time.Now().UTC().Format(time.RFC3339),
		})
	})

	// Legacy JSON upload API retained
	r.Group(func(gr chi.Router) {
		gr.Use(tokens.Middleware)
		gr.Post("/files", func(w http.ResponseWriter, r *http.Request) {
			id := r.URL.Query().Get("id")
			if id == "" {
				id = time.Now().Format("20060102T150405Z")
			}
			b, _ := io.ReadAll(r.Body)
			ct := r.Header.Get("Content-Type")
			rec, err := store.Upload(r.Context(), id, bytes.NewReader(b), ct)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if metaStore != nil {
				mh := &metadata.FileRecord{FileID: rec.ObjectKey, TokenHint: "legacy", SizeBytes: rec.Size, StoredKeyArn: cfg.KMSKeyID, EncryptedObjectKey: rec.ObjectKey, Bucket: cfg.Bucket, CipherSuite: rec.Meta.Alg, DataKeyEncryptedLen: len(rec.Meta.EncryptedDataKey), NonceLen: len(rec.Meta.Nonce), Tags: []string{"legacy"}}
				_ = metaStore.PutFileRecord(r.Context(), mh)
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(rec)
		})
		gr.Get("/files/{id}", func(w http.ResponseWriter, r *http.Request) {
			id := chi.URLParam(r, "id")
			if id == "" {
				http.Error(w, "missing id", http.StatusBadRequest)
				return
			}

			if err := store.Download(r.Context(), id, w); err != nil {
				log.Printf("Download error for id=%s: %v", id, err)
				status := http.StatusInternalServerError
				if strings.Contains(strings.ToLower(err.Error()), "not found") {
					status = http.StatusNotFound
				}
				http.Error(w, err.Error(), status)
				return
			}

			if metaStore != nil {
				// increment access counter
				_, _ = metaStore.IncrementAccess(r.Context(), fmt.Sprintf("files/%s.bin", id))
			}
		})
	})

	// Multipart upload using /upload
	r.Post("/upload", func(w http.ResponseWriter, r *http.Request) {
		userToken := r.Header.Get("Authorization")
		if !strings.HasPrefix(strings.ToLower(userToken), "bearer ") {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "missing bearer token")
			return
		}
		tokVal := strings.TrimSpace(strings.TrimPrefix(userToken, "Bearer "))
		if !tokens.Validate(tokVal) {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "invalid token")
			return
		}
		file, header, err := r.FormFile("file")
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, err.Error())
			return
		}
		defer file.Close()
		filename := header.Filename
		storedRec, err := store.Upload(r.Context(), filename, file, header.Header.Get("Content-Type"))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, err.Error())
			return
		}
		if metaStore != nil {
			th := ""
			if len(tokVal) >= 8 {
				th = tokVal[:8]
			}
			mr := &metadata.FileRecord{FileID: storedRec.ObjectKey, TokenHint: th, SizeBytes: storedRec.Size, StoredKeyArn: cfg.KMSKeyID, EncryptedObjectKey: storedRec.ObjectKey, Bucket: cfg.Bucket, CipherSuite: storedRec.Meta.Alg, DataKeyEncryptedLen: len(storedRec.Meta.EncryptedDataKey), NonceLen: len(storedRec.Meta.Nonce), Tags: []string{"upload"}}
			_ = metaStore.PutFileRecord(r.Context(), mr)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(storedRec)
	})

	// Token-protected download route supporting either raw id or full object key
	r.Group(func(gr chi.Router) {
		gr.Use(tokens.Middleware)
		// GET /download/{id} -> expects bare id, decrypts and streams
		gr.Get("/download/{id}", func(w http.ResponseWriter, r *http.Request) {
			id := chi.URLParam(r, "id")
			if id == "" {
				http.Error(w, "missing id", http.StatusBadRequest)
				return
			}

			if err := store.Download(r.Context(), id, w); err != nil {
				log.Printf("Download error for id=%s: %v", id, err)
				status := http.StatusInternalServerError
				if strings.Contains(strings.ToLower(err.Error()), "not found") {
					status = http.StatusNotFound
				}
				http.Error(w, err.Error(), status)
				return
			}

			if metaStore != nil {
				// increment using canonical key
				_, _ = metaStore.IncrementAccess(r.Context(), fmt.Sprintf("files/%s.bin", id))
			}
		})

		// GET /download/key/* catches full S3 key after /download/key/
		gr.Get("/download/key/*", func(w http.ResponseWriter, r *http.Request) {
			wild := chi.URLParam(r, "*")
			key := strings.TrimPrefix(wild, "/")
			if key == "" {
				http.Error(w, "missing key", http.StatusBadRequest)
				return
			}

			if err := store.Download(r.Context(), key, w); err != nil {
				log.Printf("Download error for key=%s: %v", key, err)
				status := http.StatusInternalServerError
				if strings.Contains(strings.ToLower(err.Error()), "not found") {
					status = http.StatusNotFound
				}
				http.Error(w, err.Error(), status)
				return
			}

			if metaStore != nil {
				_, _ = metaStore.IncrementAccess(r.Context(), key)
			}
		})
	})

	// Admin endpoints
	r.Group(func(ar chi.Router) {
		ar.Use(func(next http.Handler) http.Handler { return auth.AdminMiddleware(cfg.AdminToken, next) })
		ar.Get("/admin/tokens", func(w http.ResponseWriter, r *http.Request) {
			list, _ := tokens.List(r.Context())
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(list)
		})
		ar.Post("/admin/tokens", func(w http.ResponseWriter, r *http.Request) {
			id, token, exp, err := tokens.CreateToken(r.Context())
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"id": id, "token": token, "expiresAt": exp})
		})
		ar.Post("/admin/tokens/{id}/revoke", func(w http.ResponseWriter, r *http.Request) {
			id := chi.URLParam(r, "id")
			if err := tokens.Revoke(r.Context(), id); err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		})
		// Write a tiny object to S3 to verify end-to-end AWS integration (shows in S3 and CloudTrail)
		ar.Post("/admin/test/s3-ping", func(w http.ResponseWriter, r *http.Request) {
			key := "test/ping-" + time.Now().UTC().Format("20060102T150405Z") + ".txt"
			contentType := "text/plain"
			body := []byte("ping\n")
			_, err := clients.S3.PutObject(r.Context(), &s3.PutObjectInput{
				Bucket:      &cfg.Bucket,
				Key:         &key,
				ContentType: &contentType,
				Body:        bytes.NewReader(body),
			})
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"bucket": cfg.Bucket, "key": key, "writtenAt": time.Now().UTC().Format(time.RFC3339)})
		})
		// CloudTrail logs guidance (use console/CLI to query events)
		ar.Get("/admin/logs", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"message": "CloudTrail is configured at the account level. Query events with AWS Console > CloudTrail > Event history, or via AWS CLI: aws cloudtrail lookup-events --lookup-attributes AttributeKey=ResourceName,AttributeValue=<your S3 bucket/object>",
			})
		})
		ar.Get("/admin/files", func(w http.ResponseWriter, r *http.Request) {
			if metaStore == nil {
				http.Error(w, "metadata store disabled", http.StatusNotImplemented)
				return
			}
			list, err := metaStore.ListFiles(r.Context(), 200)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(list)
		})
	})
}
