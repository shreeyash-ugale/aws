package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	cryptoenvelope "github.com/shreeyash-ugale/secureFile/internal/crypto"
)

type S3Store struct {
	s3     *s3.Client
	bucket string
	cipher *cryptoenvelope.EnvelopeCipher
}

type FileRecord struct {
	ID          string                          `json:"id"`
	Size        int64                           `json:"size"`
	Meta        cryptoenvelope.EnvelopeMetadata `json:"meta"`
	ObjectKey   string                          `json:"objectKey"`
	ContentType string                          `json:"contentType"`
}

func NewS3Store(s3c *s3.Client, bucket string, cipher *cryptoenvelope.EnvelopeCipher) *S3Store {
	return &S3Store{s3: s3c, bucket: bucket, cipher: cipher}
}

func (s *S3Store) Upload(ctx context.Context, id string, r io.Reader, contentType string) (*FileRecord, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	ct, meta, err := s.cipher.Encrypt(ctx, data, []byte(id))
	if err != nil {
		return nil, err
	}
	key := fmt.Sprintf("files/%s.bin", id)
	_, err = s.s3.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      &s.bucket,
		Key:         &key,
		ContentType: &contentType,
		Body:        bytes.NewReader(ct),
		Metadata: map[string]string{
			"alg":   meta.Alg,
			"edk":   meta.EncryptedDataKey,
			"nonce": meta.Nonce,
		},
		StorageClass:         s3types.StorageClassStandard,
		ServerSideEncryption: s3types.ServerSideEncryptionAwsKms,
	})
	if err != nil {
		return nil, err
	}
	rec := &FileRecord{ID: id, Size: int64(len(ct)), Meta: meta, ObjectKey: key, ContentType: contentType}
	// also store a small JSON metadata object
	metaKey := fmt.Sprintf("files/%s.json", id)
	b, _ := json.Marshal(rec)
	_, _ = s.s3.PutObject(ctx, &s3.PutObjectInput{Bucket: &s.bucket, Key: &metaKey, Body: bytes.NewReader(b), ContentType: ptr("application/json")})
	return rec, nil
}

func (s *S3Store) Download(ctx context.Context, id string, w http.ResponseWriter) error {
	// Allow callers to pass either a bare id (e.g., "myfile.txt") or a full key (e.g., "files/myfile.txt.bin")
	key := id
	aad := id // AAD must match what was used during Encrypt (the bare id)
	if strings.HasPrefix(key, "files/") && strings.HasSuffix(strings.ToLower(key), ".bin") {
		// derive bare id from full key to use as AAD
		// key format: files/{id}.bin
		trimmed := strings.TrimPrefix(key, "files/")
		aad = strings.TrimSuffix(trimmed, ".bin")
	} else {
		// construct full key from bare id
		key = fmt.Sprintf("files/%s.bin", id)
	}

	// Get object from S3
	// KMS decryption happens automatically if the IAM role has kms:Decrypt permissions
	out, err := s.s3.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &s.bucket,
		Key:    &key,
		// No need to specify SSECustomerAlgorithm for KMS encryption
		// KMS decryption is automatic if permissions are correct
	})
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "not found") {
			return fmt.Errorf("not found")
		}
		return fmt.Errorf("failed to get object: %w", err)
	}
	defer out.Body.Close()

	// Extract envelope encryption metadata from S3 object metadata
	meta := cryptoenvelope.EnvelopeMetadata{
		Alg:              out.Metadata["alg"],
		EncryptedDataKey: out.Metadata["edk"],
		Nonce:            out.Metadata["nonce"],
	}

	// Read the encrypted data from S3 (S3-side KMS decryption already happened)
	ct, err := io.ReadAll(out.Body)
	if err != nil {
		return fmt.Errorf("failed to read object body: %w", err)
	}

	// Decrypt the envelope-encrypted data using our cipher
	pt, err := s.cipher.Decrypt(ctx, ct, meta, []byte(aad))
	if err != nil {
		return fmt.Errorf("failed to decrypt data: %w", err)
	}

	// Set appropriate response headers
	if out.ContentType != nil {
		w.Header().Set("Content-Type", *out.ContentType)
	} else {
		w.Header().Set("Content-Type", "application/octet-stream")
	}

	// Set Content-Disposition for file download
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", aad))

	// Set Content-Length based on the decrypted data
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(pt)))

	w.WriteHeader(http.StatusOK)

	// Write the decrypted data to the response
	_, err = w.Write(pt)
	if err != nil {
		return fmt.Errorf("failed to write response: %w", err)
	}

	return nil
}

func ptr[T any](v T) *T { return &v }
