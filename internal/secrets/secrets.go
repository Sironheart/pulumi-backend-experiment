package secrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// KMSAPI is the subset of the KMS client the Crypter needs.
type KMSAPI interface {
	GenerateDataKey(ctx context.Context, in *kms.GenerateDataKeyInput, optFns ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error)
	Decrypt(ctx context.Context, in *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

var _ KMSAPI = (*kms.Client)(nil)

// Crypter implements envelope encryption: a fresh KMS data key per value,
// AES-256-GCM for the payload. Ciphertext format:
//
//	v1:<keyID>:<base64 encryptedDataKey>:<base64 nonce+ciphertext>
type Crypter struct {
	kms   KMSAPI
	keyID string
}

func NewCrypter(kmsClient KMSAPI, keyID string) *Crypter {
	return &Crypter{kms: kmsClient, keyID: keyID}
}

func (c *Crypter) Encrypt(ctx context.Context, plaintext []byte) (string, error) {
	dk, err := c.kms.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
		KeyId:   aws.String(c.keyID),
		KeySpec: types.DataKeySpecAes256,
	})
	if err != nil {
		return "", fmt.Errorf("generate data key: %w", err)
	}
	gcm, err := newAESGCM(dk.Plaintext)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, plaintext, nil)
	return strings.Join([]string{
		"v1",
		c.keyID,
		base64.StdEncoding.EncodeToString(dk.CiphertextBlob),
		base64.StdEncoding.EncodeToString(sealed),
	}, ":"), nil
}

func (c *Crypter) Decrypt(ctx context.Context, ciphertext string) ([]byte, error) {
	parts := strings.Split(ciphertext, ":")
	if len(parts) < 4 || parts[0] != "v1" {
		return nil, errors.New("not a v1 envelope ciphertext")
	}
	keyID := strings.Join(parts[1:len(parts)-2], ":")
	edk, err := base64.StdEncoding.DecodeString(parts[len(parts)-2])
	if err != nil {
		return nil, fmt.Errorf("decode data key: %w", err)
	}
	sealed, err := base64.StdEncoding.DecodeString(parts[len(parts)-1])
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	dk, err := c.kms.Decrypt(ctx, &kms.DecryptInput{
		KeyId:          aws.String(keyID),
		CiphertextBlob: edk,
	})
	if err != nil {
		return nil, fmt.Errorf("decrypt data key: %w", err)
	}
	gcm, err := newAESGCM(dk.Plaintext)
	if err != nil {
		return nil, err
	}
	if len(sealed) < gcm.NonceSize() {
		return nil, errors.New("payload too short")
	}
	return gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], nil)
}

func newAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
