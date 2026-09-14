package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"forgejo.siron.casa/sironheart/pulumi-backend-experiment/internal/api"
	"forgejo.siron.casa/sironheart/pulumi-backend-experiment/internal/authn"
	"forgejo.siron.casa/sironheart/pulumi-backend-experiment/internal/config"
	"forgejo.siron.casa/sironheart/pulumi-backend-experiment/internal/secrets"
	"forgejo.siron.casa/sironheart/pulumi-backend-experiment/internal/store"
)

func main() {
	configPath := flag.String("config", "", "path to config file (falls back to PULUMI_BACKEND_CONFIG, then config.yaml)")
	flag.Parse()

	var level slog.Level
	_ = level.UnmarshalText([]byte(os.Getenv("LOG_LEVEL"))) // invalid/empty → info
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})))

	path := *configPath
	if path == "" {
		path = os.Getenv("PULUMI_BACKEND_CONFIG")
	}
	if path == "" {
		path = "config.yaml"
	}

	cfg, err := config.Load(path)
	if err != nil {
		slog.Error("load config", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var oidcValidator api.OIDCValidator
	if cfg.NoAuth {
		slog.Warn("noAuth enabled: OIDC disabled, all requests accepted on loopback only", "addr", cfg.Listen)
	} else {
		var err error
		oidcValidator, err = authn.NewOIDCValidator(ctx, cfg.Issuer, cfg.ClientID)
		if err != nil {
			slog.Error("oidc validator", "error", err)
			os.Exit(1)
		}
	}

	crypter, err := secrets.NewCrypter(cfg.SecretsKey)
	if err != nil {
		slog.Error("secrets crypter", "error", err)
		os.Exit(1)
	}

	// Ambient credential chain (env, AWS_PROFILE, IRSA, ...).
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(cfg.Region))
	if err != nil {
		slog.Error("aws config", "error", err)
		os.Exit(1)
	}
	st := store.NewS3Store(s3.NewFromConfig(awsCfg), cfg.Bucket)

	keys := make(map[string][]byte, len(cfg.SigningKeys))
	for _, key := range cfg.SigningKeys {
		keys[key.ID] = []byte(key.Key)
	}
	issuer := &authn.TokenIssuer{
		Keys: keys, ActiveKeyID: cfg.ActiveSigningKey, TTL: cfg.TokenTTL,
	}
	handler := api.NewServer(cfg, issuer, oidcValidator, st, crypter)
	server := newHTTPServer(cfg.Listen, handler)
	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		slog.Error("listen", "error", err)
		os.Exit(1)
	}

	slog.Info("listening", "addr", cfg.Listen)
	if err := serve(ctx, server, listener); err != nil {
		slog.Error("serve", "error", err)
		os.Exit(1)
	}
}

func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       time.Minute,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    1 << 20,
	}
}

func serve(ctx context.Context, server *http.Server, listener net.Listener) error {
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(listener)
	}()

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		shutdownErr := server.Shutdown(shutdownCtx)
		if shutdownErr != nil {
			closeErr := server.Close()
			serveErr := <-errCh
			if errors.Is(serveErr, http.ErrServerClosed) {
				serveErr = nil
			}
			return errors.Join(shutdownErr, closeErr, serveErr)
		}
		err := <-errCh
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
