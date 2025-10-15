package auth

import (
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type TokenRecord struct {
	ID        string `json:"id"`
	Hash      string `json:"hash"`
	CreatedAt int64  `json:"createdAt"`
	ExpiresAt int64  `json:"expiresAt,omitempty"`
	Revoked   bool   `json:"revoked"`
}

type TokenStore struct {
	s3     *s3.Client
	bucket string
	key    string
	cache  map[string]TokenRecord
}

func NewTokenStore(s3c *s3.Client, bucket string) *TokenStore {
	return &TokenStore{s3: s3c, bucket: bucket, key: "config/tokens.json", cache: map[string]TokenRecord{}}
}

// defaultTokenTTL defines how long a token remains valid from creation
var defaultTokenTTL = 24 * time.Hour

func init() {
	if v := os.Getenv("TOKEN_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			defaultTokenTTL = d
			return
		}
	}
	if v := os.Getenv("TOKEN_TTL_HOURS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			defaultTokenTTL = time.Duration(n) * time.Hour
		}
	}
}

func (t *TokenStore) load(ctx context.Context) error {
	out, err := t.s3.GetObject(ctx, &s3.GetObjectInput{Bucket: &t.bucket, Key: &t.key})
	if err != nil {
		// treat as empty if not found
		t.cache = map[string]TokenRecord{}
		return nil
	}
	defer out.Body.Close()
	var list []TokenRecord
	if err := json.NewDecoder(out.Body).Decode(&list); err != nil {
		return err
	}
	t.cache = map[string]TokenRecord{}
	for _, r := range list {
		t.cache[r.ID] = r
	}
	return nil
}

func (t *TokenStore) save(ctx context.Context) error {
	list := make([]TokenRecord, 0, len(t.cache))
	for _, r := range t.cache {
		list = append(list, r)
	}
	b, _ := json.MarshalIndent(list, "", "  ")
	_, err := t.s3.PutObject(ctx, &s3.PutObjectInput{Bucket: &t.bucket, Key: &t.key, Body: strings.NewReader(string(b)), ContentType: ptr("application/json")})
	return err
}

func (t *TokenStore) CreateToken(ctx context.Context) (id string, token string, expiresAt int64, err error) {
	_ = t.load(ctx)
	id = fmt.Sprintf("tok_%d", time.Now().UnixNano())
	// token 32 bytes random hex
	b := make([]byte, 32)
	if _, err := crand.Read(b); err != nil {
		return "", "", 0, err
	}
	token = hex.EncodeToString(b)
	h := sha256.Sum256([]byte(token))
	now := time.Now()
	expiresAt = now.Add(defaultTokenTTL).Unix()
	t.cache[id] = TokenRecord{ID: id, Hash: hex.EncodeToString(h[:]), CreatedAt: now.Unix(), ExpiresAt: expiresAt}
	err = t.save(ctx)
	return
}

func (t *TokenStore) Revoke(ctx context.Context, id string) error {
	_ = t.load(ctx)
	rec, ok := t.cache[id]
	if !ok {
		return errors.New("not found")
	}
	rec.Revoked = true
	t.cache[id] = rec
	return t.save(ctx)
}

func (t *TokenStore) List(ctx context.Context) ([]TokenRecord, error) {
	_ = t.load(ctx)
	list := make([]TokenRecord, 0, len(t.cache))
	for _, r := range t.cache {
		list = append(list, r)
	}
	return list, nil
}

func (t *TokenStore) Validate(token string) bool {
	// Ensure we have a cache; lazy-load on first use to avoid per-request S3 calls
	if len(t.cache) == 0 {
		_ = t.load(context.Background())
	}
	h := sha256.Sum256([]byte(token))
	hh := hex.EncodeToString(h[:])
	for _, r := range t.cache {
		if r.Revoked {
			continue
		}
		if r.Hash != hh {
			continue
		}
		// Determine expiry: prefer explicit ExpiresAt; otherwise derive from CreatedAt
		var exp int64
		if r.ExpiresAt > 0 {
			exp = r.ExpiresAt
		} else if r.CreatedAt > 0 {
			exp = r.CreatedAt + int64(defaultTokenTTL.Seconds())
		}
		if exp > 0 {
			if time.Now().Unix() > exp {
				continue
			}
		}
		return true
	}
	return false
}

func ptr[T any](v T) *T { return &v }

// Middleware for bearer token auth
func (t *TokenStore) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(strings.ToLower(auth), "bearer ") {
			http.Error(w, "missing token", http.StatusUnauthorized)
			return
		}
		tok := strings.TrimSpace(auth[len("Bearer "):])
		// load latest tokens from S3 in background; ignore error to avoid latency
		_ = t.load(r.Context())
		if !t.Validate(tok) {
			http.Error(w, "invalid or expired token", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Admin middleware with static ADMIN_TOKEN
func AdminMiddleware(adminToken string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("X-Admin-Token")
		if token == "" {
			auth := r.Header.Get("Authorization")
			if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
				token = strings.TrimSpace(auth[len("Bearer "):])
			}
		}
		if token != adminToken {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
