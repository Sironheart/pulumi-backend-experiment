package secrets

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"
	"testing"
)

const (
	testOrg        = "acme"
	testProject    = "api"
	testStack      = "dev"
	testSecretsKey = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
)

func newTestCrypter(t *testing.T, secretsKey string) *Crypter {
	t.Helper()
	c, err := NewCrypter(secretsKey)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCrypterRoundTrip(t *testing.T) {
	c := newTestCrypter(t, testSecretsKey)
	plaintext := []byte("my-secret-value")

	ciphertext, err := c.Encrypt(context.Background(), testOrg, testProject, testStack, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if !strings.HasPrefix(ciphertext, ciphertextPrefix) {
		t.Errorf("ciphertext missing %q prefix: %q", ciphertextPrefix, ciphertext)
	}
	if strings.Contains(ciphertext, string(plaintext)) {
		t.Error("ciphertext contains plaintext")
	}

	// A new instance must decrypt persisted ciphertext with the same key.
	restarted := newTestCrypter(t, testSecretsKey)
	got, err := restarted.Decrypt(context.Background(), testOrg, testProject, testStack, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("Decrypt = %q, want %q", got, plaintext)
	}
}

func TestCrypterUsesUniqueNonces(t *testing.T) {
	c := newTestCrypter(t, testSecretsKey)
	ctx := context.Background()
	a, err := c.Encrypt(ctx, testOrg, testProject, testStack, []byte("same"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Encrypt(ctx, testOrg, testProject, testStack, []byte("same"))
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Error("identical ciphertexts for identical plaintexts — nonce reused")
	}
}

func TestCrypterBindsCiphertextToStack(t *testing.T) {
	c := newTestCrypter(t, testSecretsKey)
	ctx := context.Background()
	ciphertext, err := c.Encrypt(ctx, testOrg, testProject, testStack, []byte("my-secret-value"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Decrypt(ctx, testOrg, testProject, "other", ciphertext); err == nil {
		t.Fatal("Decrypt succeeded for a different stack")
	}
}

func TestNewCrypterRejectsInvalidKeys(t *testing.T) {
	for name, secretsKey := range map[string]string{
		"missing secrets key": "",
		"invalid base64":      "not-base64",
		"wrong key length":    base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, keySize-1)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewCrypter(secretsKey); err == nil {
				t.Fatal("NewCrypter succeeded")
			}
		})
	}
}

func TestCrypterRejectsInvalidCiphertext(t *testing.T) {
	c := newTestCrypter(t, testSecretsKey)
	ctx := context.Background()
	ciphertext, err := c.Encrypt(ctx, testOrg, testProject, testStack, []byte("my-secret-value"))
	if err != nil {
		t.Fatal(err)
	}
	tampered := ciphertext[:len(ciphertext)-1] + "A"
	if strings.HasSuffix(ciphertext, "A") {
		tampered = ciphertext[:len(ciphertext)-1] + "B"
	}

	for _, input := range []string{"", "not-a-ciphertext", "v1:legacy", "v2:!!!", tampered} {
		if _, err := c.Decrypt(ctx, testOrg, testProject, testStack, input); err == nil {
			t.Errorf("Decrypt(%q) succeeded", input)
		}
	}
}
