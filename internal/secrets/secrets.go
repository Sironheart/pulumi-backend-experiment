package secrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

const (
	keySize          = 32
	ciphertextPrefix = "v2:"
	rootKeyInfo      = "pulumi-backend/secrets/root/v2"
	stackKeyPrefix   = "pulumi-backend/secrets/stack/v2"
)

// Crypter encrypts values with an AES-256-GCM key derived for each stack.
// Ciphertext format:
//
//	v2:<base64 nonce+ciphertext>
type Crypter struct {
	rootKey []byte
}

// NewCrypter creates a service-managed crypter. An explicit secretsKey must
// be a base64-encoded 32-byte key. When it is empty, the root key is derived
// from signingKey so normal deployments need no additional configuration.
func NewCrypter(signingKey, secretsKey string) (*Crypter, error) {
	if secretsKey == "" {
		if signingKey == "" {
			return nil, errors.New("signingKey is required when secretsKey is empty")
		}
		key, err := hkdf.Key(sha256.New, []byte(signingKey), nil, rootKeyInfo, keySize)
		if err != nil {
			return nil, fmt.Errorf("derive root key: %w", err)
		}
		return &Crypter{rootKey: key}, nil
	}

	key, err := base64.StdEncoding.DecodeString(secretsKey)
	if err != nil {
		return nil, fmt.Errorf("decode secretsKey: %w", err)
	}
	if len(key) != keySize {
		return nil, fmt.Errorf("secretsKey must decode to %d bytes", keySize)
	}
	return &Crypter{rootKey: key}, nil
}

func (c *Crypter) Encrypt(_ context.Context, org, project, stack string, plaintext []byte) (string, error) {
	gcm, scope, err := c.gcm(org, project, stack)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, plaintext, []byte(scope))
	return ciphertextPrefix + base64.StdEncoding.EncodeToString(sealed), nil
}

func (c *Crypter) Decrypt(_ context.Context, org, project, stack, ciphertext string) ([]byte, error) {
	payload, ok := strings.CutPrefix(ciphertext, ciphertextPrefix)
	if !ok {
		return nil, errors.New("not a v2 ciphertext")
	}
	sealed, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	gcm, scope, err := c.gcm(org, project, stack)
	if err != nil {
		return nil, err
	}
	if len(sealed) < gcm.NonceSize() {
		return nil, errors.New("payload too short")
	}
	return gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], []byte(scope))
}

func (c *Crypter) gcm(org, project, stack string) (cipher.AEAD, string, error) {
	scope := stackScope(org, project, stack)
	key, err := hkdf.Key(sha256.New, c.rootKey, nil, scope, keySize)
	if err != nil {
		return nil, "", fmt.Errorf("derive stack key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, "", err
	}
	return gcm, scope, nil
}

func stackScope(org, project, stack string) string {
	return fmt.Sprintf("%s\x00%d:%s%d:%s%d:%s", stackKeyPrefix, len(org), org, len(project), project, len(stack), stack)
}
