package crypto

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

type fakeKMS struct{}

func (f *fakeKMS) GenerateDataKey(ctx context.Context, in *kms.GenerateDataKeyInput, optFns ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error) {
    key := make([]byte, 32)
    rand.Read(key)
    // Encrypt data key with a simple XOR for test, to be "decrypted" later
    edk := make([]byte, len(key))
    for i := range key { edk[i] = key[i] ^ 0xAA }
    return &kms.GenerateDataKeyOutput{Plaintext: key, CiphertextBlob: edk}, nil
}

func (f *fakeKMS) Decrypt(ctx context.Context, in *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error) {
    // reverse XOR
    pt := make([]byte, len(in.CiphertextBlob))
    for i := range in.CiphertextBlob { pt[i] = in.CiphertextBlob[i] ^ 0xAA }
    return &kms.DecryptOutput{Plaintext: pt}, nil
}

func TestEnvelopeEncryptDecrypt(t *testing.T) {
    e := NewEnvelopeCipher(&fakeKMS{}, "test-key")
    msg := []byte("hello world")
    aad := []byte("id123")
    ct, meta, err := e.Encrypt(context.Background(), msg, aad)
    if err != nil { t.Fatalf("encrypt: %v", err) }
    if len(ct) == 0 || meta.EncryptedDataKey == "" || meta.Nonce == "" { t.Fatal("missing fields") }
    pt, err := e.Decrypt(context.Background(), ct, meta, aad)
    if err != nil { t.Fatalf("decrypt: %v", err) }
    if string(pt) != string(msg) { t.Fatalf("roundtrip mismatch: %q != %q", pt, msg) }

    // tamper tag
    if len(ct) > 0 { ct[len(ct)-1] ^= 0xFF }
    if _, err := e.Decrypt(context.Background(), ct, meta, aad); err == nil {
        t.Fatal("expected auth failure")
    }
}
