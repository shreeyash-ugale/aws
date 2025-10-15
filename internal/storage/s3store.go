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
	key := fmt.Sprintf("files/%s.bin", id)
	out, err := s.s3.GetObject(ctx, &s3.GetObjectInput{Bucket: &s.bucket, Key: &key})
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "not found") {
			return fmt.Errorf("not found")
		}
		return err
	}
	defer out.Body.Close()
	meta := cryptoenvelope.EnvelopeMetadata{
		Alg:              out.Metadata["alg"],
		EncryptedDataKey: out.Metadata["edk"],
		Nonce:            out.Metadata["nonce"],
	}
	ct, err := io.ReadAll(out.Body)
	if err != nil {
		return err
	}
	pt, err := s.cipher.Decrypt(ctx, ct, meta, []byte(id))
	if err != nil {
		return err
	}
	if out.ContentType != nil {
		w.Header().Set("Content-Type", *out.ContentType)
	}
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(pt)
	return err
}

func ptr[T any](v T) *T { return &v }
