package api

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"forgejo.siron.casa/sironheart/pulumi-backend-experiment/internal/authn"
	"forgejo.siron.casa/sironheart/pulumi-backend-experiment/internal/config"
	"forgejo.siron.casa/sironheart/pulumi-backend-experiment/internal/secrets"
	"forgejo.siron.casa/sironheart/pulumi-backend-experiment/internal/store"
)

// Crypter encrypts/decrypts secret values.
type Crypter interface {
	Encrypt(ctx context.Context, plaintext []byte) (string, error)
	Decrypt(ctx context.Context, ciphertext string) ([]byte, error)
}

// OIDCValidator validates ID tokens from an OIDC provider.
type OIDCValidator interface {
	Validate(ctx context.Context, raw string) (authn.Identity, error)
}

// Conformance checks live here: the implementing packages are imported by
// this one, so checks on their side would create import cycles.
var (
	_ Crypter       = (*secrets.Crypter)(nil)
	_ OIDCValidator = (*authn.OIDCValidator)(nil)
	_ http.Handler  = (*Server)(nil)
)

type Server struct {
	cfg     *config.Config
	issuer  *authn.TokenIssuer
	oidc    OIDCValidator
	store   store.Store
	crypter Crypter
	mux     *http.ServeMux
}

const maxRequestBodyBytes = 32 << 20

var errRequestTooLarge = errors.New("request body too large")

func NewServer(cfg *config.Config, issuer *authn.TokenIssuer, oidc OIDCValidator, st store.Store, crypter Crypter) *Server {
	s := &Server{cfg: cfg, issuer: issuer, oidc: oidc, store: st, crypter: crypter, mux: http.NewServeMux()}
	s.routes()
	return s
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.healthz)
	s.mux.HandleFunc("POST /api/token/exchange", s.tokenExchange)

	userAuthed := func(pattern string, h http.HandlerFunc) {
		s.mux.Handle(pattern, s.authMiddleware(false, http.HandlerFunc(h)))
	}
	updateAuthed := func(pattern string, h http.HandlerFunc) {
		s.mux.Handle(pattern, s.authMiddleware(true, http.HandlerFunc(h)))
	}

	userAuthed("GET /api/capabilities", s.capabilities)
	userAuthed("GET /api/user", s.whoami)
	userAuthed("GET /api/user/organizations/default", s.defaultOrg)
	userAuthed("GET /api/user/stacks", s.listUserStacks)

	userAuthed("GET /api/stacks/{org}", s.listOrgStacks)
	userAuthed("POST /api/stacks/{org}/{project}", s.createStack)
	userAuthed("HEAD /api/stacks/{org}/{project}", s.headProject)
	userAuthed("GET /api/stacks/{org}/{project}/{stack}", s.getStack)
	userAuthed("DELETE /api/stacks/{org}/{project}/{stack}", s.deleteStack)
	userAuthed("GET /api/stacks/{org}/{project}/{stack}/export", s.exportStack)
	userAuthed("GET /api/stacks/{org}/{project}/{stack}/export/{version}", s.exportStack)
	userAuthed("POST /api/stacks/{org}/{project}/{stack}/import", s.importStack)

	userAuthed("GET /api/stacks/{org}/{project}/{stack}/updates", s.getStackUpdates)
	userAuthed("GET /api/stacks/{org}/{project}/{stack}/updates/latest", s.getLatestUpdate)
	userAuthed("GET /api/stacks/{org}/{project}/{stack}/updates/{version}", s.getUpdateByVersion)

	userAuthed("POST /api/stacks/{org}/{project}/{stack}/encrypt", s.encryptValue)
	userAuthed("POST /api/stacks/{org}/{project}/{stack}/decrypt", s.decryptValue)
	userAuthed("POST /api/stacks/{org}/{project}/{stack}/batch-encrypt", s.batchEncrypt)
	userAuthed("POST /api/stacks/{org}/{project}/{stack}/batch-decrypt", s.batchDecrypt)

	userAuthed("POST /api/stacks/{org}/{project}/{stack}/{kind}", s.createUpdate)
	userAuthed("GET /api/stacks/{org}/{project}/{stack}/{kind}/{updateID}", s.getUpdateStatus)
	userAuthed("POST /api/stacks/{org}/{project}/{stack}/{kind}/{updateID}", s.startUpdate)
	updateAuthed("PATCH /api/stacks/{org}/{project}/{stack}/{kind}/{updateID}/checkpoint", s.patchCheckpoint)
	updateAuthed("PATCH /api/stacks/{org}/{project}/{stack}/{kind}/{updateID}/checkpointverbatim", s.patchCheckpointVerbatim)
	updateAuthed("POST /api/stacks/{org}/{project}/{stack}/{kind}/{updateID}/complete", s.completeUpdate)
	updateAuthed("POST /api/stacks/{org}/{project}/{stack}/{kind}/{updateID}/renew_lease", s.renewLease)
	userAuthed("POST /api/stacks/{org}/{project}/{stack}/{kind}/{updateID}/cancel", s.cancelUpdate)
	updateAuthed("POST /api/stacks/{org}/{project}/{stack}/{kind}/{updateID}/events", s.discardEvents)
	updateAuthed("POST /api/stacks/{org}/{project}/{stack}/{kind}/{updateID}/events/batch", s.discardEvents)
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	slog.Debug("request", "method", r.Method, "path", r.URL.Path)
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	s.mux.ServeHTTP(w, r)
}

// authMiddleware accepts a backend user token or an update-scoped token in the
// Authorization header. The Pulumi CLI uses the schemes "token" (user) and
// "update-token" (update lease); "Bearer" is accepted for convenience.
func (s *Server) authMiddleware(updateToken bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scheme, raw := authorizationToken(r.Header.Get("Authorization"))
		if !s.cfg.NoAuth && ((updateToken && scheme != "update-token") || (!updateToken && scheme == "update-token")) {
			writeError(w, http.StatusUnauthorized, "invalid or missing token")
			return
		}
		var (
			id  authn.Identity
			uc  *authn.UpdateClaims
			err error
		)
		if updateToken {
			id, uc, err = s.issuer.VerifyScoped(raw)
			if err == nil && uc == nil {
				err = errors.New("backend user token used as update token")
			}
		} else {
			id, err = s.issuer.Verify(raw)
		}
		if err != nil || raw == "" {
			if !s.cfg.NoAuth {
				if raw == "" {
					writeError(w, http.StatusUnauthorized, "missing token")
					return
				}
				writeError(w, http.StatusUnauthorized, "invalid token")
				return
			}
			id = authn.IdentityFromToken(raw)
			uc = nil
		}
		ctx := authn.ContextWithIdentity(r.Context(), id)
		if uc != nil {
			if uc.UpdateID != r.PathValue("updateID") ||
				uc.Org != r.PathValue("org") ||
				uc.Project != r.PathValue("project") ||
				uc.Stack != r.PathValue("stack") ||
				uc.Kind != r.PathValue("kind") {
				writeError(w, http.StatusForbidden, "invalid update token scope")
				return
			}
			ctx = authn.WithUpdateClaims(ctx, uc)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func authorizationToken(header string) (string, string) {
	parts := strings.SplitN(strings.TrimSpace(header), " ", 2)
	if len(parts) != 2 {
		return "", ""
	}
	switch parts[0] {
	case "update-token", "token", "Bearer":
		return parts[0], strings.TrimSpace(parts[1])
	default:
		return "", ""
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

type errorResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, errorResponse{Code: status, Message: message})
}

// internalError logs the underlying cause server-side; the client keeps the
// generic message so internals never leak into the API response.
func internalError(w http.ResponseWriter, r *http.Request, err error, message string) {
	slog.Error("internal error", "method", r.Method, "path", r.URL.Path, "error", err)
	writeError(w, http.StatusInternalServerError, message)
}

// storeError maps store errors to HTTP responses. Returns true if handled.
func (s *Server) storeError(w http.ResponseWriter, err error) bool {
	var held *store.LockHeldError
	switch {
	case errors.Is(err, store.ErrStackNotFound):
		writeError(w, http.StatusNotFound, "stack not found")
	case errors.Is(err, store.ErrStackExists):
		writeError(w, http.StatusConflict, "stack already exists")
	case errors.Is(err, store.ErrUpdateNotFound):
		writeError(w, http.StatusNotFound, "update not found")
	case errors.Is(err, store.ErrCheckpointNotFound):
		writeError(w, http.StatusNotFound, "no checkpoint available")
	case errors.Is(err, store.ErrInvalidUpdateState),
		errors.Is(err, store.ErrConcurrentMutation),
		errors.Is(err, store.ErrNoLock):
		writeError(w, http.StatusConflict, err.Error())
	case errors.As(err, &held):
		writeError(w, http.StatusConflict, "stack is locked by update "+held.Lock.UpdateID)
	default:
		return false
	}
	return true
}

func (s *Server) writeStoreError(w http.ResponseWriter, r *http.Request, err error, message string) {
	if s.storeError(w, err) {
		return
	}
	internalError(w, r, err, message)
}

// identity returns the authenticated identity; present on all authed routes.
func (s *Server) identity(r *http.Request) authn.Identity {
	id, _ := authn.IdentityFrom(r.Context())
	return id
}

// decodeBody reads a JSON request body, transparently handling gzip content
// encoding (the Pulumi CLI compresses larger payloads).
func decodeBody(r *http.Request, v any) error {
	body := r.Body
	if r.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(body)
		if err != nil {
			return err
		}
		defer func() { _ = gz.Close() }()
		body = io.NopCloser(gz)
	}
	limited := &io.LimitedReader{R: body, N: maxRequestBodyBytes + 1}
	decoder := json.NewDecoder(limited)
	if err := decoder.Decode(v); err != nil {
		if limited.N == 0 || isMaxBytesError(err) {
			return errRequestTooLarge
		}
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if limited.N == 0 || isMaxBytesError(err) {
			return errRequestTooLarge
		}
		return errors.New("request body must contain one JSON value")
	}
	if limited.N == 0 {
		return errRequestTooLarge
	}
	return nil
}

func isMaxBytesError(err error) bool {
	var maxErr *http.MaxBytesError
	return errors.As(err, &maxErr)
}

func writeDecodeError(w http.ResponseWriter, err error, message string) {
	if errors.Is(err, errRequestTooLarge) || isMaxBytesError(err) {
		writeError(w, http.StatusRequestEntityTooLarge, "request too large")
		return
	}
	writeError(w, http.StatusBadRequest, message)
}

func validUpdateKind(kind string) bool {
	switch kind {
	case "update", "preview", "refresh", "destroy":
		return true
	}
	return false
}

// requireUpdateScope verifies the request carries an update token matching the
// path's update and stack.
func (s *Server) requireUpdateScope(w http.ResponseWriter, r *http.Request) bool {
	uc, ok := authn.UpdateClaimsFrom(r.Context())
	if s.cfg.NoAuth && !ok {
		return true
	}
	if !ok ||
		uc.UpdateID != r.PathValue("updateID") ||
		uc.Org != r.PathValue("org") ||
		uc.Project != r.PathValue("project") ||
		uc.Stack != r.PathValue("stack") ||
		uc.Kind != r.PathValue("kind") {
		writeError(w, http.StatusForbidden, "invalid or missing update token")
		return false
	}
	return true
}
