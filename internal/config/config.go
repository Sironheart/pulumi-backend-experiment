package config

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const defaultLocalSigningKey = "insecure-local-dev-key"

type Config struct {
	NoAuth        bool          `yaml:"noAuth"`
	Issuer        string        `yaml:"issuer"`
	ClientID      string        `yaml:"clientId"`
	SigningKey    string        `yaml:"signingKey"`
	Listen        string        `yaml:"listen"`
	TokenTTL      time.Duration `yaml:"tokenTTL"`
	LeaseDuration time.Duration `yaml:"leaseDuration"`

	Bucket    string `yaml:"bucket"`
	Region    string `yaml:"region"`
	KMSKeyArn string `yaml:"kmsKeyArn"`
}

func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg := Config{
		Listen:        ":8080",
		TokenTTL:      720 * time.Hour,
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
	if c.SigningKey == "" {
		if !c.NoAuth {
			return fmt.Errorf("signingKey is required")
		}
		c.SigningKey = defaultLocalSigningKey
	}
	if v, ok := strings.CutPrefix(c.SigningKey, "env:"); ok {
		key := os.Getenv(v)
		if key == "" {
			return fmt.Errorf("signingKey env var %q is not set", v)
		}
		c.SigningKey = key
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
