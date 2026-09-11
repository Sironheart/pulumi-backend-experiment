package secrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

type decryptKMS struct {
	plaintextKey []byte
	keyID        string
}

func (*decryptKMS) GenerateDataKey(context.Context, *kms.GenerateDataKeyInput, ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error) {
	panic("unexpected GenerateDataKey call")
}

func (f *decryptKMS) Decrypt(_ context.Context, in *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	f.keyID = aws.ToString(in.KeyId)
	return &kms.DecryptOutput{Plaintext: f.plaintextKey}, nil
}

func flociKMS(t *testing.T) (*kms.Client, string) {
	t.Helper()
	ctx := context.Background()
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "floci/floci:2.0.1",
			ExposedPorts: []string{"4566/tcp"},
			WaitingFor:   wait.ForListeningPort("4566/tcp"),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("start floci: %v", err)
	}
	t.Cleanup(func() { _ = container.Terminate(ctx) })
	endpoint, err := container.Endpoint(ctx, "http")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion("us-east-1"),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "")),
	)
	if err != nil {
		t.Fatal(err)
	}
	client := kms.NewFromConfig(cfg, func(o *kms.Options) {
		o.BaseEndpoint = aws.String(endpoint)
	})
	key, err := client.CreateKey(ctx, &kms.CreateKeyInput{Description: aws.String("test")})
	if err != nil {
		t.Fatalf("create key: %v", err)
	}
	return client, *key.KeyMetadata.Arn
}

func TestDecryptEnvelopeWithKeyARN(t *testing.T) {
	key := make([]byte, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("my-secret-value")
	nonce := make([]byte, gcm.NonceSize())
	sealed := gcm.Seal(nonce, nonce, plaintext, nil)
	keyARN := "arn:aws:kms:eu-central-1:123456789012:key/01234567-89ab-cdef-0123-456789abcdef"
	ciphertext := strings.Join([]string{
		"v1",
		keyARN,
		base64.StdEncoding.EncodeToString([]byte("encrypted-data-key")),
		base64.StdEncoding.EncodeToString(sealed),
	}, ":")
	kmsClient := &decryptKMS{plaintextKey: key}

	got, err := NewCrypter(kmsClient, keyARN).Decrypt(context.Background(), ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Errorf("Decrypt = %q, want %q", got, plaintext)
	}
	if kmsClient.keyID != keyARN {
		t.Errorf("KMS key ID = %q, want %q", kmsClient.keyID, keyARN)
	}
}

func TestEnvelopeRoundTrip(t *testing.T) {
	client, keyARN := flociKMS(t)
	c := NewCrypter(client, keyARN)
	ctx := context.Background()

	plaintext := []byte("my-secret-value")
	ciphertext, err := c.Encrypt(ctx, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if !strings.HasPrefix(ciphertext, "v1:") {
		t.Errorf("ciphertext missing v1 prefix: %q", ciphertext)
	}
	if strings.Contains(ciphertext, string(plaintext)) {
		t.Error("ciphertext contains plaintext")
	}

	got, err := c.Decrypt(ctx, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Errorf("round trip = %q", got)
	}
}

func TestDecryptRejectsGarbage(t *testing.T) {
	client, keyARN := flociKMS(t)
	c := NewCrypter(client, keyARN)
	for _, input := range []string{"", "not-envelope", "v2:abc:def:ghi", "v1:!!:aa:bb"} {
		if _, err := c.Decrypt(context.Background(), input); err == nil {
			t.Errorf("Decrypt(%q) succeeded", input)
		}
	}
}

func TestEncryptUniqueDataKeys(t *testing.T) {
	client, keyARN := flociKMS(t)
	c := NewCrypter(client, keyARN)
	ctx := context.Background()
	a, err := c.Encrypt(ctx, []byte("same"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Encrypt(ctx, []byte("same"))
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Error("identical ciphertexts for identical plaintexts — data key or nonce reused")
	}
}
