package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const validYAML = `
issuer: https://sso.example.com
clientId: app-client-id
signingKey: env:TEST_SIGNING_KEY
listen: ":9090"
tokenTTL: 720h
leaseDuration: 6m
bucket: my-state-bucket
region: eu-central-1
kmsKeyArn: arn:aws:kms:eu-central-1:111122223333:key/abc
`

func TestLoadValidConfig(t *testing.T) {
	t.Setenv("TEST_SIGNING_KEY", "supersecret")
	cfg, err := Load(writeTempConfig(t, validYAML))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Issuer != "https://sso.example.com" {
		t.Errorf("issuer = %q", cfg.Issuer)
	}
	if cfg.SigningKey != "supersecret" {
		t.Errorf("signingKey env ref not resolved, got %q", cfg.SigningKey)
	}
	if cfg.Listen != ":9090" {
		t.Errorf("listen = %q", cfg.Listen)
	}
	if cfg.TokenTTL != 720*time.Hour {
		t.Errorf("tokenTTL = %v", cfg.TokenTTL)
	}
	if cfg.LeaseDuration != 6*time.Minute {
		t.Errorf("leaseDuration = %v", cfg.LeaseDuration)
	}
	if cfg.Bucket != "my-state-bucket" || cfg.Region != "eu-central-1" {
		t.Errorf("bucket/region = %q/%q", cfg.Bucket, cfg.Region)
	}
	if cfg.KMSKeyArn == "" {
		t.Error("kmsKeyArn empty")
	}
}

func TestDefaults(t *testing.T) {
	t.Setenv("TEST_SIGNING_KEY", "x")
	cfg, err := Load(writeTempConfig(t, `
issuer: https://example.com
clientId: id
signingKey: env:TEST_SIGNING_KEY
bucket: b
region: r
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Listen != ":8080" {
		t.Errorf("default listen = %q, want :8080", cfg.Listen)
	}
	if cfg.TokenTTL != 720*time.Hour {
		t.Errorf("default tokenTTL = %v, want 720h", cfg.TokenTTL)
	}
	if cfg.LeaseDuration != 5*time.Minute {
		t.Errorf("default leaseDuration = %v, want 5m", cfg.LeaseDuration)
	}
}

func TestRejectsUnknownFields(t *testing.T) {
	t.Setenv("TEST_SIGNING_KEY", "x")
	_, err := Load(writeTempConfig(t, `
issuer: https://example.com
clientId: id
signingKey: env:TEST_SIGNING_KEY
bucket: b
region: r
kmsKeyARN: typo
`))
	if err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestRejectsMultipleDocuments(t *testing.T) {
	t.Setenv("TEST_SIGNING_KEY", "x")
	_, err := Load(writeTempConfig(t, `
issuer: https://example.com
clientId: id
signingKey: env:TEST_SIGNING_KEY
bucket: b
region: r
---
bucket: ignored
`))
	if err == nil {
		t.Fatal("second YAML document accepted")
	}
}

func TestRejectsInvalidDurations(t *testing.T) {
	t.Setenv("TEST_SIGNING_KEY", "x")
	for name, duration := range map[string]string{
		"negative token TTL":      "tokenTTL: -1s",
		"zero token TTL":          "tokenTTL: 0s",
		"subsecond token TTL":     "tokenTTL: 999ms",
		"one-second token TTL":    "tokenTTL: 1s",
		"negative lease duration": "leaseDuration: -1s",
		"zero lease duration":     "leaseDuration: 0s",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Load(writeTempConfig(t, `
issuer: https://example.com
clientId: id
signingKey: env:TEST_SIGNING_KEY
bucket: b
region: r
`+duration))
			if err == nil {
				t.Fatal("invalid duration accepted")
			}
		})
	}
}

func TestRejectsLeaseShorterThanCLILease(t *testing.T) {
	t.Setenv("TEST_SIGNING_KEY", "x")
	_, err := Load(writeTempConfig(t, `
issuer: https://example.com
clientId: id
signingKey: env:TEST_SIGNING_KEY
bucket: b
region: r
leaseDuration: 4m
`))
	if err == nil {
		t.Fatal("lease shorter than five minutes accepted")
	}
}

func TestRejectsPlaceholderClientID(t *testing.T) {
	t.Setenv("TEST_SIGNING_KEY", "x")
	_, err := Load(writeTempConfig(t, `
issuer: https://example.com
clientId: replace-with-client-id
signingKey: env:TEST_SIGNING_KEY
bucket: b
region: r
`))
	if err == nil {
		t.Fatal("placeholder clientId accepted")
	}
}

func TestValidationErrors(t *testing.T) {
	t.Setenv("TEST_SIGNING_KEY", "x")
	cases := map[string]string{
		"missing issuer": `
clientId: id
signingKey: env:TEST_SIGNING_KEY
bucket: b
region: r
`,
		"missing signingKey": `
issuer: https://example.com
clientId: id
bucket: b
region: r
`,
		"missing bucket": `
issuer: https://example.com
clientId: id
signingKey: env:TEST_SIGNING_KEY
region: r
`,
		"missing region": `
issuer: https://example.com
clientId: id
signingKey: env:TEST_SIGNING_KEY
bucket: b
`,
	}
	for name, yaml := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(writeTempConfig(t, yaml)); err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestSigningKeyEnvMissing(t *testing.T) {
	_, err := Load(writeTempConfig(t, `
issuer: https://example.com
clientId: id
signingKey: env:DEFINITELY_NOT_SET_VAR
bucket: b
region: r
`))
	if err == nil {
		t.Error("expected error for missing env var")
	}
}

func TestNoAuthSkipsOIDCAndSigningKey(t *testing.T) {
	cfg, err := Load(writeTempConfig(t, `
noAuth: true
bucket: b
region: r
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.NoAuth {
		t.Error("NoAuth = false, want true")
	}
	if cfg.SigningKey != defaultLocalSigningKey {
		t.Errorf("signingKey = %q, want default local key", cfg.SigningKey)
	}
}

func TestNoAuthKeepsExplicitSigningKey(t *testing.T) {
	cfg, err := Load(writeTempConfig(t, `
noAuth: true
signingKey: explicit-dev-key
bucket: b
region: r
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.SigningKey != "explicit-dev-key" {
		t.Errorf("signingKey = %q", cfg.SigningKey)
	}
}
