package config

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"forgejo.siron.casa/sironheart/pulumi-backend-experiment/internal/authz"
	"gopkg.in/yaml.v3"
)

const (
	minimumSigningKeyBytes = 32
	secretsKeyBytes        = 32
)

// SigningKey is one entry in the backend token-signing keyring. Retain old
// keys until all tokens they signed have expired, then remove them.
type SigningKey struct {
	ID  string `yaml:"id"`
	Key string `yaml:"key"`
}

type Config struct {
	NoAuth           bool          `yaml:"noAuth"`
	Issuer           string        `yaml:"issuer"`
	ClientID         string        `yaml:"clientId"`
	SigningKeys      []SigningKey  `yaml:"signingKeys"`
	ActiveSigningKey string        `yaml:"activeSigningKey"`
	SecretsKey       string        `yaml:"secretsKey"`
	Authorization    []authz.Rule  `yaml:"authorization"`
	Listen           string        `yaml:"listen"`
	TokenTTL         time.Duration `yaml:"tokenTTL"`
	LeaseDuration    time.Duration `yaml:"leaseDuration"`

	Bucket string `yaml:"bucket"`
	Region string `yaml:"region"`
}

func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- the operator explicitly selects the config path.
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg := Config{
		Listen:        ":8080",
		TokenTTL:      24 * time.Hour,
		LeaseDuration: 5 * time.Minute,
	}
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
		return nil, fmt.Errorf("parse config: multiple YAML documents are not supported")
	}
	if cfg.Listen == "" {
		cfg.Listen = ":8080"
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) validate() error {
	if !c.NoAuth {
		if c.Issuer == "" {
			return fmt.Errorf("issuer is required")
		}
		if c.ClientID == "" {
			return fmt.Errorf("clientId is required")
		}
		if c.ClientID == "replace-with-client-id" {
			return fmt.Errorf("clientId must not be a placeholder")
		}
	}
	if c.NoAuth && !isLoopbackListen(c.Listen) {
		return fmt.Errorf("noAuth requires a loopback listen address")
	}
	if err := c.resolveSigningKeys(); err != nil {
		return err
	}
	if c.SecretsKey == "" {
		return fmt.Errorf("secretsKey is required")
	}
	var err error
	c.SecretsKey, err = resolveEnvRef("secretsKey", c.SecretsKey)
	if err != nil {
		return err
	}
	if err := validateSecretsKey(c.SecretsKey); err != nil {
		return err
	}
	if !c.NoAuth {
		if err := authz.ValidateRules(c.Authorization); err != nil {
			return err
		}
	}
	if c.Bucket == "" {
		return fmt.Errorf("bucket is required")
	}
	if c.Region == "" {
		return fmt.Errorf("region is required")
	}
	if c.TokenTTL < 2*time.Second {
		return fmt.Errorf("tokenTTL must be at least 2s")
	}
	if c.LeaseDuration < 5*time.Minute {
		return fmt.Errorf("leaseDuration must be at least 5m")
	}
	return nil
}

func validateSecretsKey(value string) error {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return fmt.Errorf("secretsKey must be valid base64: %w", err)
	}
	if len(decoded) != secretsKeyBytes {
		return fmt.Errorf("secretsKey must decode to %d bytes", secretsKeyBytes)
	}
	return nil
}

func (c *Config) resolveSigningKeys() error {
	if len(c.SigningKeys) == 0 {
		return fmt.Errorf("at least one signingKey is required")
	}
	if c.ActiveSigningKey == "" {
		return fmt.Errorf("activeSigningKey is required")
	}
	seen := make(map[string]struct{}, len(c.SigningKeys))
	foundActive := false
	for i := range c.SigningKeys {
		key := &c.SigningKeys[i]
		if key.ID == "" {
			return fmt.Errorf("signingKeys[%d].id is required", i)
		}
		if _, ok := seen[key.ID]; ok {
			return fmt.Errorf("duplicate signing key ID %q", key.ID)
		}
		seen[key.ID] = struct{}{}
		resolved, err := resolveEnvRef(fmt.Sprintf("signingKeys[%d].key", i), key.Key)
		if err != nil {
			return err
		}
		if len(resolved) < minimumSigningKeyBytes {
			return fmt.Errorf("signingKeys[%d].key must be at least %d bytes", i, minimumSigningKeyBytes)
		}
		key.Key = resolved
		if key.ID == c.ActiveSigningKey {
			foundActive = true
		}
	}
	if !foundActive {
		return fmt.Errorf("activeSigningKey %q is not configured", c.ActiveSigningKey)
	}
	return nil
}

func isLoopbackListen(listen string) bool {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func resolveEnvRef(field, value string) (string, error) {
	v, ok := strings.CutPrefix(value, "env:")
	if !ok {
		return value, nil
	}
	key := os.Getenv(v)
	if key == "" {
		return "", fmt.Errorf("%s env var %q is not set", field, v)
	}
	return key, nil
}
