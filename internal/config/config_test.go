package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testSecretsKey = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="

const validYAML = `
issuer: https://sso.example.com
clientId: app-client-id
signingKeys:
  - id: current
    key: env:TEST_SIGNING_KEY
activeSigningKey: current
secretsKey: env:TEST_SECRETS_KEY
authorization:
  - groups: [pulumi-admins]
    organizations: ["*"]
    projects: ["*"]
    stacks: ["*"]
    actions: [read, write, delete, secrets]
bucket: my-state-bucket
region: eu-central-1
`

func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func setTestKeys(t *testing.T) {
	t.Helper()
	t.Setenv("TEST_SIGNING_KEY", strings.Repeat("s", minimumSigningKeyBytes))
	t.Setenv("TEST_SECRETS_KEY", testSecretsKey)
}

func TestLoadValidConfig(t *testing.T) {
	setTestKeys(t)
	cfg, err := Load(writeTempConfig(t, validYAML+`listen: ":9090"
tokenTTL: 12h
leaseDuration: 6m
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Issuer != "https://sso.example.com" || cfg.ClientID != "app-client-id" {
		t.Errorf("OIDC config = %q/%q", cfg.Issuer, cfg.ClientID)
	}
	if len(cfg.SigningKeys) != 1 || cfg.SigningKeys[0].Key != strings.Repeat("s", minimumSigningKeyBytes) {
		t.Errorf("signingKeys = %+v", cfg.SigningKeys)
	}
	if cfg.ActiveSigningKey != "current" || cfg.SecretsKey != testSecretsKey {
		t.Errorf("active/secrets key = %q/%q", cfg.ActiveSigningKey, cfg.SecretsKey)
	}
	if len(cfg.Authorization) != 1 || cfg.Authorization[0].Groups[0] != "pulumi-admins" {
		t.Errorf("authorization = %+v", cfg.Authorization)
	}
	if cfg.Listen != ":9090" || cfg.TokenTTL != 12*time.Hour || cfg.LeaseDuration != 6*time.Minute {
		t.Errorf("listen/TTL/lease = %q/%v/%v", cfg.Listen, cfg.TokenTTL, cfg.LeaseDuration)
	}
	if cfg.Bucket != "my-state-bucket" || cfg.Region != "eu-central-1" {
		t.Errorf("bucket/region = %q/%q", cfg.Bucket, cfg.Region)
	}
}

func TestDefaults(t *testing.T) {
	setTestKeys(t)
	cfg, err := Load(writeTempConfig(t, validYAML))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Listen != ":8080" || cfg.TokenTTL != 24*time.Hour || cfg.LeaseDuration != 5*time.Minute {
		t.Errorf("defaults = %q/%v/%v", cfg.Listen, cfg.TokenTTL, cfg.LeaseDuration)
	}
}

func TestRejectsUnknownFields(t *testing.T) {
	setTestKeys(t)
	if _, err := Load(writeTempConfig(t, validYAML+"unexpectedField: typo\n")); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestRejectsMultipleDocuments(t *testing.T) {
	setTestKeys(t)
	if _, err := Load(writeTempConfig(t, validYAML+"---\nbucket: ignored\n")); err == nil {
		t.Fatal("second YAML document accepted")
	}
}

func TestRejectsInvalidDurations(t *testing.T) {
	setTestKeys(t)
	for name, duration := range map[string]string{
		"negative token TTL":      "tokenTTL: -1s",
		"zero token TTL":          "tokenTTL: 0s",
		"subsecond token TTL":     "tokenTTL: 999ms",
		"one-second token TTL":    "tokenTTL: 1s",
		"short lease duration":    "leaseDuration: 4m",
		"negative lease duration": "leaseDuration: -1s",
		"zero lease duration":     "leaseDuration: 0s",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(writeTempConfig(t, validYAML+duration)); err == nil {
				t.Fatal("Load succeeded")
			}
		})
	}
}

func TestRejectsMissingSecurityConfiguration(t *testing.T) {
	setTestKeys(t)
	for name, yaml := range map[string]string{
		"missing signing key":   strings.Replace(validYAML, "signingKeys:\n  - id: current\n    key: env:TEST_SIGNING_KEY\n", "", 1),
		"missing active key":    strings.Replace(validYAML, "activeSigningKey: current\n", "", 1),
		"missing secrets key":   strings.Replace(validYAML, "secretsKey: env:TEST_SECRETS_KEY\n", "", 1),
		"invalid secrets key":   strings.Replace(validYAML, "secretsKey: env:TEST_SECRETS_KEY", "secretsKey: not-base64", 1),
		"short secrets key":     strings.Replace(validYAML, "secretsKey: env:TEST_SECRETS_KEY", "secretsKey: AQE=", 1),
		"missing authorization": strings.Replace(validYAML, "authorization:\n  - groups: [pulumi-admins]\n    organizations: [\"*\"]\n    projects: [\"*\"]\n    stacks: [\"*\"]\n    actions: [read, write, delete, secrets]\n", "", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(writeTempConfig(t, yaml)); err == nil {
				t.Fatal("Load succeeded")
			}
		})
	}
}

func TestRejectsInvalidSigningKeyring(t *testing.T) {
	setTestKeys(t)
	for name, yaml := range map[string]string{
		"short key":          strings.Replace(validYAML, "key: env:TEST_SIGNING_KEY", "key: short", 1),
		"duplicate ID":       strings.Replace(validYAML, "activeSigningKey: current", "  - id: current\n    key: env:TEST_SIGNING_KEY\nactiveSigningKey: current", 1),
		"unknown active key": strings.Replace(validYAML, "activeSigningKey: current", "activeSigningKey: next", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(writeTempConfig(t, yaml)); err == nil {
				t.Fatal("Load succeeded")
			}
		})
	}
}

func TestRejectsPlaceholderClientID(t *testing.T) {
	setTestKeys(t)
	yaml := strings.Replace(validYAML, "clientId: app-client-id", "clientId: replace-with-client-id", 1)
	if _, err := Load(writeTempConfig(t, yaml)); err == nil {
		t.Fatal("placeholder clientId accepted")
	}
}

func TestValidationErrors(t *testing.T) {
	setTestKeys(t)
	for name, yaml := range map[string]string{
		"missing issuer": strings.Replace(validYAML, "issuer: https://sso.example.com\n", "", 1),
		"missing bucket": strings.Replace(validYAML, "bucket: my-state-bucket\n", "", 1),
		"missing region": strings.Replace(validYAML, "region: eu-central-1\n", "", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(writeTempConfig(t, yaml)); err == nil {
				t.Fatal("Load succeeded")
			}
		})
	}
}

func TestSigningKeyEnvMissing(t *testing.T) {
	setTestKeys(t)
	t.Setenv("TEST_SIGNING_KEY", "")
	if _, err := Load(writeTempConfig(t, validYAML)); err == nil {
		t.Error("expected error for missing signing key env var")
	}
}

func TestSecretsKeyEnvMissing(t *testing.T) {
	setTestKeys(t)
	t.Setenv("TEST_SECRETS_KEY", "")
	if _, err := Load(writeTempConfig(t, validYAML)); err == nil {
		t.Error("expected error for missing secretsKey env var")
	}
}

func TestNoAuthRequiresExplicitKeysAndLoopback(t *testing.T) {
	setTestKeys(t)
	noAuthYAML := `
noAuth: true
listen: 127.0.0.1:8080
signingKeys:
  - id: local
    key: env:TEST_SIGNING_KEY
activeSigningKey: local
secretsKey: env:TEST_SECRETS_KEY
bucket: b
region: r
`
	cfg, err := Load(writeTempConfig(t, noAuthYAML))
	if err != nil {
		t.Fatalf("Load noAuth config: %v", err)
	}
	if !cfg.NoAuth || len(cfg.Authorization) != 0 {
		t.Errorf("noAuth config = %+v", cfg)
	}

	for name, yaml := range map[string]string{
		"wildcard listen": strings.Replace(noAuthYAML, "127.0.0.1:8080", ":8080", 1),
		"missing key":     strings.Replace(noAuthYAML, "signingKeys:\n  - id: local\n    key: env:TEST_SIGNING_KEY\n", "", 1),
		"missing secrets": strings.Replace(noAuthYAML, "secretsKey: env:TEST_SECRETS_KEY\n", "", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(writeTempConfig(t, yaml)); err == nil {
				t.Fatal("Load succeeded")
			}
		})
	}
}
