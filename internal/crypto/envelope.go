package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"time"

	"context"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// KMSAPI abstracts the subset of KMS operations used by EnvelopeCipher.
type KMSAPI interface {
    GenerateDataKey(ctx context.Context, params *kms.GenerateDataKeyInput, optFns ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error)
    Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

type EnvelopeCipher struct {
    kms       KMSAPI
    kmsKeyID  string
}

type EnvelopeMetadata struct {
    // Base64-encoded KMS-encrypted data key
    EncryptedDataKey string `json:"edk"`
    // Base64-encoded nonce (12 bytes) used for AES-GCM
    Nonce string `json:"n"`
    // Algorithm marker
    Alg   string `json:"alg"`
    // Timestamp
    Ts    int64  `json:"ts"`
}

func NewEnvelopeCipher(kmsClient KMSAPI, kmsKeyID string) *EnvelopeCipher {
    return &EnvelopeCipher{kms: kmsClient, kmsKeyID: kmsKeyID}
}

func (e *EnvelopeCipher) Encrypt(ctx context.Context, plaintext []byte, aad []byte) (ciphertext []byte, meta EnvelopeMetadata, err error) {
    // Generate a data key via KMS
    out, err := e.kms.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
        KeyId:   &e.kmsKeyID,
        KeySpec: kmstypes.DataKeySpecAes256,
    })
    if err != nil {
        return nil, EnvelopeMetadata{}, fmt.Errorf("GenerateDataKey: %w", err)
    }
    // out.Plaintext is the raw data key (32 bytes)
    block, err := aes.NewCipher(out.Plaintext)
    if err != nil {
        return nil, EnvelopeMetadata{}, fmt.Errorf("NewCipher: %w", err)
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, EnvelopeMetadata{}, fmt.Errorf("NewGCM: %w", err)
    }
    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return nil, EnvelopeMetadata{}, fmt.Errorf("nonce: %w", err)
    }
    ct := gcm.Seal(nil, nonce, plaintext, aad)

    meta = EnvelopeMetadata{
        EncryptedDataKey: base64.StdEncoding.EncodeToString(out.CiphertextBlob),
        Nonce:            base64.StdEncoding.EncodeToString(nonce),
        Alg:              "KMS+AES256-GCM",
        Ts:               time.Now().Unix(),
    }
    // zero plaintext key
    for i := range out.Plaintext {
        out.Plaintext[i] = 0
    }
    return ct, meta, nil
}

func (e *EnvelopeCipher) Decrypt(ctx context.Context, ciphertext []byte, meta EnvelopeMetadata, aad []byte) ([]byte, error) {
    if meta.Alg == "" {
        return nil, fmt.Errorf("missing alg")
    }
    edk, err := base64.StdEncoding.DecodeString(meta.EncryptedDataKey)
    if err != nil {
        return nil, fmt.Errorf("edk base64: %w", err)
    }
    nonce, err := base64.StdEncoding.DecodeString(meta.Nonce)
    if err != nil {
        return nil, fmt.Errorf("nonce base64: %w", err)
    }
    decOut, err := e.kms.Decrypt(ctx, &kms.DecryptInput{CiphertextBlob: edk})
    if err != nil {
        return nil, fmt.Errorf("KMS Decrypt: %w", err)
    }
    block, err := aes.NewCipher(decOut.Plaintext)
    if err != nil {
        return nil, fmt.Errorf("NewCipher: %w", err)
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, fmt.Errorf("NewGCM: %w", err)
    }
    pt, err := gcm.Open(nil, nonce, ciphertext, aad)
    if err != nil {
        return nil, fmt.Errorf("GCM open: %w", err)
    }
    // zero plaintext key
    for i := range decOut.Plaintext {
        decOut.Plaintext[i] = 0
    }
    return pt, nil
}
