package api

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"forgejo.siron.casa/sironheart/pulumi-backend-experiment/internal/authn"
	"forgejo.siron.casa/sironheart/pulumi-backend-experiment/internal/authz"
	"forgejo.siron.casa/sironheart/pulumi-backend-experiment/internal/config"
	"forgejo.siron.casa/sironheart/pulumi-backend-experiment/internal/secrets"
	"forgejo.siron.casa/sironheart/pulumi-backend-experiment/internal/store"
)

// --- fakes ---

var (
	_ store.Store   = (*fakeStore)(nil)
	_ Crypter       = fakeCrypter{}
	_ OIDCValidator = fakeOIDC{}
)

type fakeStore struct {
	mu                   sync.Mutex
	stacks               map[string]*store.Stack
	checkpoint           map[string]json.RawMessage
	history              map[string]json.RawMessage
	updates              map[string]*store.Update
	locks                map[string]*store.Lock
	checkpointErr        error
	saveCheckpointErr    error
	deleteErr            error
	beforeSaveCheckpoint func()
	deleteCalls          int
	renewGeneration      uint64
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		stacks:     map[string]*store.Stack{},
		checkpoint: map[string]json.RawMessage{},
		history:    map[string]json.RawMessage{},
		updates:    map[string]*store.Update{},
		locks:      map[string]*store.Lock{},
	}
}

func key(parts ...string) string { return strings.Join(parts, "/") }

func (f *fakeStore) CreateStack(_ context.Context, org, project, stack string) (*store.Stack, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := key(org, project, stack)
	if _, ok := f.stacks[k]; ok {
		return nil, store.ErrStackExists
	}
	st := &store.Stack{
		Org: org, Project: project, Name: stack,
		Incarnation: store.NewUpdateID(), Created: time.Now(),
	}
	f.stacks[k] = st
	cp := *st
	return &cp, nil
}

func (f *fakeStore) GetStack(_ context.Context, org, project, stack string) (*store.Stack, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	st, ok := f.stacks[key(org, project, stack)]
	if !ok {
		return nil, store.ErrStackNotFound
	}
	cp := *st
	return &cp, nil
}

func (f *fakeStore) ListStacks(_ context.Context, org string) ([]store.Stack, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []store.Stack
	for _, st := range f.stacks {
		if org == "" || st.Org == org {
			out = append(out, *st)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (f *fakeStore) DeleteStack(
	_ context.Context,
	org, project, stack, incarnation, updateID string,
	generation uint64,
) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleteCalls++
	k := key(org, project, stack)
	st, ok := f.stacks[k]
	if !ok {
		return store.ErrStackNotFound
	}
	if st.Incarnation != incarnation {
		return store.ErrConcurrentMutation
	}
	lock := f.locks[k]
	if lock == nil || lock.UpdateID != updateID || lock.Generation != generation {
		return store.ErrConcurrentMutation
	}
	if f.deleteErr != nil {
		return f.deleteErr
	}
	delete(f.stacks, k)
	delete(f.checkpoint, k)
	delete(f.locks, k)
	return nil
}

func (f *fakeStore) GetCheckpoint(_ context.Context, org, project, stack string) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.checkpointErr != nil {
		return nil, f.checkpointErr
	}
	cp, ok := f.checkpoint[key(org, project, stack)]
	if !ok {
		return nil, store.ErrCheckpointNotFound
	}
	return cp, nil
}

func (f *fakeStore) GetCheckpointVersion(_ context.Context, org, project, stack string, version int) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp, ok := f.history[fmt.Sprintf("%s/%d", key(org, project, stack), version)]
	if !ok {
		return nil, store.ErrCheckpointNotFound
	}
	return cp, nil
}

func (f *fakeStore) SaveCheckpoint(
	_ context.Context,
	org, project, stack, incarnation, updateID string,
	generation uint64,
	version int,
	deployment json.RawMessage,
) error {
	if f.beforeSaveCheckpoint != nil {
		f.beforeSaveCheckpoint()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.saveCheckpointErr != nil {
		return f.saveCheckpointErr
	}
	k := key(org, project, stack)
	st, ok := f.stacks[k]
	if !ok {
		return store.ErrStackNotFound
	}
	if st.Incarnation != incarnation {
		return store.ErrConcurrentMutation
	}
	if updateID == "" {
		if generation != 0 || version != 0 || st.Version != 0 {
			return store.ErrInvalidUpdateState
		}
	} else {
		lock := f.locks[k]
		if lock == nil ||
			lock.UpdateID != updateID ||
			lock.Generation != generation ||
			lock.Expired(time.Now()) ||
			st.Version != version {
			return store.ErrConcurrentMutation
		}
	}
	f.checkpoint[k] = deployment
	f.history[fmt.Sprintf("%s/%d", k, version)] = deployment
	return nil
}

func (f *fakeStore) CreateUpdate(_ context.Context, org, project, stack, kind, updateID string) (*store.Update, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := key(org, project, stack)
	st, ok := f.stacks[k]
	if !ok {
		return nil, store.ErrStackNotFound
	}
	updateKey := k + "/" + updateID
	if existing, ok := f.updates[updateKey]; ok {
		if existing.Kind != kind {
			return nil, store.ErrConcurrentMutation
		}
		if kind != "preview" {
			lock := f.locks[k]
			if lock == nil || lock.UpdateID != updateID || lock.Expired(time.Now()) {
				return nil, store.ErrNoLock
			}
			switch st.Version {
			case existing.Version:
			case existing.Version - 1:
				st.Version = existing.Version
			default:
				return nil, store.ErrConcurrentMutation
			}
		}
		cp := *existing
		return &cp, nil
	}
	version := st.Version
	if kind != "preview" {
		lock := f.locks[k]
		if lock == nil || lock.UpdateID != updateID || lock.Expired(time.Now()) {
			return nil, store.ErrNoLock
		}
		st.Version++
		version = st.Version
	}
	u := &store.Update{
		ID: updateID, Kind: kind, Status: "not-started", Version: version,
		Incarnation: st.Incarnation, StartTime: time.Now().Unix(),
	}
	f.updates[updateKey] = u
	return u, nil
}

func (f *fakeStore) GetUpdate(_ context.Context, org, project, stack, updateID string) (*store.Update, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.updates[key(org, project, stack)+"/"+updateID]
	if !ok {
		return nil, store.ErrUpdateNotFound
	}
	cp := *u
	return &cp, nil
}

func (f *fakeStore) StartUpdate(_ context.Context, org, project, stack, updateID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.updates[key(org, project, stack)+"/"+updateID]
	if !ok {
		return store.ErrUpdateNotFound
	}
	if u.Status != "not-started" {
		return store.ErrInvalidUpdateState
	}
	u.Status = "in-progress"
	return nil
}

func (f *fakeStore) CompleteUpdate(_ context.Context, org, project, stack, updateID, status, message string, resourceChanges map[string]int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.updates[key(org, project, stack)+"/"+updateID]
	if !ok {
		return store.ErrUpdateNotFound
	}
	if u.Status == status {
		return nil
	}
	if u.Status != "in-progress" && (u.Status != "not-started" || status != "cancelled") {
		return store.ErrInvalidUpdateState
	}
	u.Status = status
	u.Message = message
	u.ResourceChanges = resourceChanges
	u.EndTime = time.Now().Unix()
	return nil
}

func (f *fakeStore) ListUpdates(_ context.Context, org, project, stack string) ([]store.Update, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	prefix := key(org, project, stack) + "/"
	var out []store.Update
	for k, u := range f.updates {
		if strings.HasPrefix(k, prefix) {
			out = append(out, *u)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version > out[j].Version })
	return out, nil
}

func (f *fakeStore) AcquireLock(
	_ context.Context,
	org, project, stack, incarnation, updateID, owner string,
	ttl time.Duration,
) (*store.Lock, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := key(org, project, stack)
	st, ok := f.stacks[k]
	if !ok {
		return nil, store.ErrStackNotFound
	}
	if st.Incarnation != incarnation {
		return nil, store.ErrConcurrentMutation
	}
	if l, ok := f.locks[k]; ok && time.Now().Before(l.ExpiresAt) {
		if l.UpdateID == updateID && l.Owner == owner {
			l.ExpiresAt = time.Now().Add(ttl)
			cp := *l
			return &cp, nil
		}
		return nil, &store.LockHeldError{Lock: l}
	}
	st.Fence++
	l := &store.Lock{
		UpdateID: updateID, Owner: owner,
		ExpiresAt: time.Now().Add(ttl), Generation: st.Fence,
	}
	f.locks[k] = l
	return l, nil
}

func (f *fakeStore) RenewLock(_ context.Context, org, project, stack, updateID string, generation uint64, ttl time.Duration) (*store.Lock, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := key(org, project, stack)
	l, ok := f.locks[k]
	if !ok {
		return nil, store.ErrNoLock
	}
	if l.UpdateID != updateID || l.Generation != generation {
		return nil, &store.LockHeldError{Lock: l}
	}
	if f.renewGeneration != 0 {
		l.Generation = f.renewGeneration
	}
	l.ExpiresAt = time.Now().Add(ttl)
	return l, nil
}

func (f *fakeStore) ReleaseLock(_ context.Context, org, project, stack, updateID string, generation uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := key(org, project, stack)
	l, ok := f.locks[k]
	if !ok {
		return nil
	}
	if l.UpdateID != updateID || l.Generation != generation {
		return &store.LockHeldError{Lock: l}
	}
	delete(f.locks, k)
	return nil
}

func (f *fakeStore) GetLock(_ context.Context, org, project, stack string) (*store.Lock, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	l, ok := f.locks[key(org, project, stack)]
	if !ok {
		return nil, store.ErrNoLock
	}
	cp := *l
	return &cp, nil
}

type fakeCrypter struct{}

func (fakeCrypter) Encrypt(_ context.Context, _, _, _ string, plaintext []byte) (string, error) {
	return "v2:fake:" + string(plaintext), nil
}

func (fakeCrypter) Decrypt(_ context.Context, _, _, _, ciphertext string) ([]byte, error) {
	p, ok := strings.CutPrefix(ciphertext, "v2:fake:")
	if !ok {
		return nil, errors.New("bad ciphertext")
	}
	return []byte(p), nil
}

type fakeOIDC struct {
	identity authn.Identity
	err      error
}

func (f fakeOIDC) Validate(_ context.Context, raw string) (authn.Identity, error) {
	if raw != "valid-oidc-token" {
		return authn.Identity{}, errors.New("invalid oidc token")
	}
	return f.identity, f.err
}

// --- harness ---

type harness struct {
	server   http.Handler
	issuer   *authn.TokenIssuer
	store    *fakeStore
	identity authn.Identity
}

const testSigningKey = "0123456789abcdef0123456789abcdef"

func testIdentity(groups ...string) authn.Identity {
	return authn.Identity{
		Issuer:   "https://issuer.example.com",
		Subject:  "steffen-subject",
		Username: "steffen@example.com",
		Groups:   groups,
	}
}

func testAuthorization(groups ...string) []authz.Rule {
	return []authz.Rule{{
		Groups:        groups,
		Organizations: []string{"*"},
		Projects:      []string{"*"},
		Stacks:        []string{"*"},
		Actions:       []authz.Action{"*"},
	}}
}

func newHarness(t *testing.T) *harness {
	return newHarnessWithCrypter(t, fakeCrypter{})
}

func newHarnessWithCrypter(t *testing.T, crypter Crypter) *harness {
	return newHarnessWithRules(t, crypter, testAuthorization("admins"), testIdentity("admins"))
}

func newHarnessWithRules(t *testing.T, crypter Crypter, rules []authz.Rule, identity authn.Identity) *harness {
	t.Helper()
	cfg := &config.Config{
		Issuer:           "https://example.com",
		ClientID:         "cid",
		SigningKeys:      []config.SigningKey{{ID: "test", Key: testSigningKey}},
		ActiveSigningKey: "test",
		SecretsKey:       "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
		Authorization:    rules,
		Listen:           ":8080",
		TokenTTL:         time.Hour,
		LeaseDuration:    5 * time.Minute,
		Bucket:           "test-bucket",
		Region:           "us-east-1",
	}
	issuer := &authn.TokenIssuer{
		Keys: map[string][]byte{"test": []byte(testSigningKey)}, ActiveKeyID: "test", TTL: time.Hour,
	}
	fs := newFakeStore()
	srv := NewServer(cfg, issuer, fakeOIDC{identity: identity}, fs, crypter)
	return &harness{server: srv, issuer: issuer, store: fs, identity: identity}
}

func (h *harness) token(t *testing.T) string {
	t.Helper()
	tok, err := h.issuer.Issue(h.identity)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func (h *harness) do(t *testing.T, method, path string, body any, headers ...string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	rec := httptest.NewRecorder()
	h.server.ServeHTTP(rec, req)
	return rec
}

func (h *harness) authed(t *testing.T, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	return h.do(t, method, path, body, "Authorization", "token "+h.token(t))
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode %s: %v", rec.Body.String(), err)
	}
	return v
}

// --- auth tests ---

func TestTokenExchange(t *testing.T) {
	h := newHarness(t)
	rec := h.do(t, "POST", "/api/token/exchange", map[string]string{"token": "valid-oidc-token"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body)
	}
	resp := decode[map[string]any](t, rec)
	tok, _ := resp["token"].(string)
	if tok == "" {
		t.Fatal("no token in response")
	}
	id, err := h.issuer.Verify(tok)
	if err != nil {
		t.Fatalf("issued token does not verify: %v", err)
	}
	if id.Username != "steffen@example.com" {
		t.Errorf("username = %q", id.Username)
	}

	rec = h.do(t, "POST", "/api/token/exchange", map[string]string{"token": "wrong"})
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("invalid oidc token: status = %d", rec.Code)
	}
}

func TestWhoami(t *testing.T) {
	h := newHarness(t)
	rec := h.authed(t, "GET", "/api/user", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	resp := decode[map[string]any](t, rec)
	if resp["githubLogin"] != "steffen@example.com" {
		t.Errorf("githubLogin = %v", resp["githubLogin"])
	}
	orgs, _ := resp["organizations"].([]any)
	if len(orgs) != 0 {
		t.Errorf("organizations = %v, want empty", resp["organizations"])
	}
}

func TestWhoamiRequiresAuth(t *testing.T) {
	h := newHarness(t)
	if rec := h.do(t, "GET", "/api/user", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d", rec.Code)
	}
}

func newNoAuthHarness(t *testing.T) *harness {
	t.Helper()
	cfg := &config.Config{
		NoAuth:           true,
		SigningKeys:      []config.SigningKey{{ID: "test", Key: testSigningKey}},
		ActiveSigningKey: "test",
		SecretsKey:       "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
		Listen:           "127.0.0.1:8080",
		TokenTTL:         time.Hour,
		LeaseDuration:    5 * time.Minute,
		Bucket:           "test-bucket",
		Region:           "us-east-1",
	}
	issuer := &authn.TokenIssuer{
		Keys: map[string][]byte{"test": []byte(testSigningKey)}, ActiveKeyID: "test", TTL: cfg.TokenTTL,
	}
	fs := newFakeStore()
	srv := NewServer(cfg, issuer, nil, fs, fakeCrypter{})
	return &harness{server: srv, issuer: issuer, store: fs, identity: testIdentity("admins")}
}

func TestNoAuthWhoamiWithoutToken(t *testing.T) {
	h := newNoAuthHarness(t)
	rec := h.do(t, "GET", "/api/user", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body)
	}
	resp := decode[map[string]any](t, rec)
	if resp["githubLogin"] != "local" {
		t.Errorf("githubLogin = %v, want local", resp["githubLogin"])
	}
}

func TestNoAuthWhoamiUsesPresentedToken(t *testing.T) {
	h := newNoAuthHarness(t)
	rec := h.do(t, "GET", "/api/user", nil, "Authorization", "token alice")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body)
	}
	resp := decode[map[string]any](t, rec)
	if resp["githubLogin"] == "alice" || !strings.HasPrefix(resp["githubLogin"].(string), "local-") {
		t.Errorf("githubLogin leaks opaque token: %v", resp["githubLogin"])
	}
}

func TestNoAuthTokenExchangeAcceptsAnything(t *testing.T) {
	h := newNoAuthHarness(t)
	rec := h.do(t, "POST", "/api/token/exchange", map[string]string{"token": "not-an-oidc-jwt"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body)
	}
	resp := decode[map[string]any](t, rec)
	tok, _ := resp["token"].(string)
	id, err := h.issuer.Verify(tok)
	if err != nil {
		t.Fatalf("issued token does not verify: %v", err)
	}
	if id.Username == "not-an-oidc-jwt" || !strings.HasPrefix(id.Username, "local-") {
		t.Errorf("opaque token leaked as username %q", id.Username)
	}
}

func TestNoAuthAllowsStackOpsWithoutOIDC(t *testing.T) {
	h := newNoAuthHarness(t)
	rec := h.do(t, "POST", "/api/stacks/acme/api", map[string]any{"stackName": "dev"},
		"Authorization", "token local-dev")
	if rec.Code != http.StatusOK {
		t.Fatalf("create: status = %d, body = %s", rec.Code, rec.Body)
	}
	rec = h.do(t, "GET", "/api/stacks/acme/api/dev", nil, "Authorization", "token local-dev")
	if rec.Code != http.StatusOK {
		t.Fatalf("get: status = %d, body = %s", rec.Code, rec.Body)
	}
}

func TestRejectsUnsafeStackScopeSegments(t *testing.T) {
	h := newNoAuthHarness(t)
	for name, tc := range map[string]struct {
		method string
		path   string
		body   any
	}{
		"stack name slash": {
			method: http.MethodPost,
			path:   "/api/stacks/acme/api",
			body:   map[string]string{"stackName": "dev/prod"},
		},
		"encoded stack slash": {
			method: http.MethodGet,
			path:   "/api/stacks/acme/api/dev%2Fprod",
		},
		"encoded organization slash": {
			method: http.MethodHead,
			path:   "/api/stacks/acme%2Fother/api",
		},
	} {
		t.Run(name, func(t *testing.T) {
			rec := h.do(t, tc.method, tc.path, tc.body, "Authorization", "token local-dev")
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, body = %s", rec.Code, rec.Body)
			}
		})
	}
	if len(h.store.stacks) != 0 {
		t.Errorf("created stacks = %v", h.store.stacks)
	}
}

func TestAuthorizationScopesEveryStackAction(t *testing.T) {
	rules := []authz.Rule{{
		Groups:        []string{"developers"},
		Organizations: []string{"acme"},
		Projects:      []string{"api"},
		Stacks:        []string{"dev"},
		Actions:       []authz.Action{authz.Read, authz.Write},
	}}
	id := authn.Identity{
		Issuer: "https://issuer.example.com", Subject: "alice", Username: "alice", Groups: []string{"developers"},
	}
	h := newHarnessWithRules(t, fakeCrypter{}, rules, id)
	for _, stack := range []string{"dev", "prod"} {
		if _, err := h.store.CreateStack(t.Context(), "acme", "api", stack); err != nil {
			t.Fatal(err)
		}
	}

	if rec := h.authed(t, "GET", "/api/stacks/acme/api/dev", nil); rec.Code != http.StatusOK {
		t.Fatalf("allowed read: %d %s", rec.Code, rec.Body)
	}
	if rec := h.authed(t, http.MethodHead, "/api/stacks/acme/api", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("allowed project head: %d %s", rec.Code, rec.Body)
	}
	for name, tc := range map[string]struct {
		method string
		path   string
		body   any
	}{
		"other stack read":   {http.MethodGet, "/api/stacks/acme/api/prod", nil},
		"other project head": {http.MethodHead, "/api/stacks/acme/other", nil},
		"delete":             {http.MethodDelete, "/api/stacks/acme/api/dev?force=true", nil},
		"decrypt":            {http.MethodPost, "/api/stacks/acme/api/dev/decrypt", map[string]string{"ciphertext": "aGVsbG8="}},
		"create other":       {http.MethodPost, "/api/stacks/acme/api", map[string]string{"stackName": "prod"}},
	} {
		t.Run(name, func(t *testing.T) {
			if rec := h.authed(t, tc.method, tc.path, tc.body); rec.Code != http.StatusForbidden {
				t.Errorf("status = %d, body = %s", rec.Code, rec.Body)
			}
		})
	}

	rec := h.authed(t, "GET", "/api/user/stacks", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list stacks: %d %s", rec.Code, rec.Body)
	}
	stacks := decode[map[string][]map[string]string](t, rec)["stacks"]
	if len(stacks) != 1 || stacks[0]["stackName"] != "dev" {
		t.Errorf("visible stacks = %v", stacks)
	}
}

func TestAuthorizationRejectsUnmatchedIdentityAtTokenExchange(t *testing.T) {
	rules := testAuthorization("developers")
	h := newHarnessWithRules(t, fakeCrypter{}, rules, testIdentity("outsiders"))
	rec := h.do(t, "POST", "/api/token/exchange", map[string]string{"token": "valid-oidc-token"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body)
	}
}

func TestUpdateTokenStillRequiresWriteAuthorization(t *testing.T) {
	rules := []authz.Rule{{
		Groups:        []string{"readers"},
		Organizations: []string{"acme"},
		Projects:      []string{"api"},
		Stacks:        []string{"dev"},
		Actions:       []authz.Action{authz.Read},
	}}
	id := authn.Identity{
		Issuer: "https://issuer.example.com", Subject: "reader", Username: "reader", Groups: []string{"readers"},
	}
	h := newHarnessWithRules(t, fakeCrypter{}, rules, id)
	token, _, err := h.issuer.IssueUpdate(id, authn.UpdateClaims{
		UpdateID: "update-1", Org: "acme", Project: "api", Stack: "dev", Kind: "update",
	}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	rec := h.do(t, http.MethodPost, "/api/stacks/acme/api/dev/update/update-1/events",
		map[string]any{"event": map[string]any{}}, "Authorization", "update-token "+token)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body)
	}
}

func TestNoAuthUpdateLifecycleWithArbitraryToken(t *testing.T) {
	h := newNoAuthHarness(t)
	if rec := h.do(t, "POST", "/api/stacks/acme/api", map[string]any{"stackName": "dev"},
		"Authorization", "token local-dev"); rec.Code != http.StatusOK {
		t.Fatalf("create stack: %d %s", rec.Code, rec.Body)
	}

	rec := h.do(t, "POST", "/api/stacks/acme/api/dev/update", map[string]any{
		"name": "api", "runtime": "nodejs",
	}, "Authorization", "token local-dev")
	if rec.Code != http.StatusOK {
		t.Fatalf("create update: %d %s", rec.Code, rec.Body)
	}
	updateID := decode[map[string]any](t, rec)["updateID"].(string)

	rec = h.do(t, "POST", "/api/stacks/acme/api/dev/update/"+updateID, map[string]any{},
		"Authorization", "token local-dev")
	if rec.Code != http.StatusOK {
		t.Fatalf("start update: %d %s", rec.Code, rec.Body)
	}
	updateToken, _ := decode[map[string]any](t, rec)["token"].(string)

	rec = h.do(t, "PATCH", "/api/stacks/acme/api/dev/update/"+updateID+"/checkpoint",
		map[string]any{"version": 3, "deployment": map[string]any{}},
		"Authorization", "update-token "+updateToken)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("checkpoint with issued update token: %d %s", rec.Code, rec.Body)
	}

	rec = h.do(t, "POST", "/api/stacks/acme/api/dev/update/"+updateID+"/complete",
		map[string]any{"status": "succeeded"},
		"Authorization", "update-token garbage")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("complete with untrusted update token: %d %s", rec.Code, rec.Body)
	}
}

func TestHealthz(t *testing.T) {
	h := newHarness(t)
	rec := h.do(t, http.MethodGet, "/healthz", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if rec.Body.String() != "ok" {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

func TestCapabilities(t *testing.T) {
	h := newHarness(t)
	rec := h.authed(t, "GET", "/api/capabilities", nil)
	resp := decode[map[string]any](t, rec)
	caps, ok := resp["capabilities"].([]any)
	if !ok || len(caps) != 0 {
		t.Errorf("capabilities = %v", resp["capabilities"])
	}
}

func TestDefaultOrg404(t *testing.T) {
	h := newHarness(t)
	if rec := h.authed(t, "GET", "/api/user/organizations/default", nil); rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (legacy fallback)", rec.Code)
	}
}

// --- stack tests ---

func TestStackCRUD(t *testing.T) {
	h := newHarness(t)

	rec := h.authed(t, "POST", "/api/stacks/acme/api", map[string]any{"stackName": "dev"})
	if rec.Code != http.StatusOK {
		t.Fatalf("create: status = %d, body = %s", rec.Code, rec.Body)
	}

	// Duplicate → 409.
	if rec := h.authed(t, "POST", "/api/stacks/acme/api", map[string]any{"stackName": "dev"}); rec.Code != http.StatusConflict {
		t.Errorf("duplicate: status = %d", rec.Code)
	}

	rec = h.authed(t, "GET", "/api/stacks/acme/api/dev", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get: status = %d", rec.Code)
	}
	st := decode[map[string]any](t, rec)
	if st["orgName"] != "acme" || st["projectName"] != "api" || st["stackName"] != "dev" {
		t.Errorf("stack = %v", st)
	}

	// List org stacks.
	rec = h.authed(t, "GET", "/api/stacks/acme", nil)
	list := decode[map[string]any](t, rec)
	stacks, _ := list["stacks"].([]any)
	if len(stacks) != 1 {
		t.Errorf("list stacks = %v", list)
	}

	// Delete.
	if rec := h.authed(t, "DELETE", "/api/stacks/acme/api/dev?force=true", nil); rec.Code != http.StatusNoContent {
		t.Errorf("delete: status = %d", rec.Code)
	}
	if rec := h.authed(t, "GET", "/api/stacks/acme/api/dev", nil); rec.Code != http.StatusNotFound {
		t.Errorf("get after delete: status = %d", rec.Code)
	}
}

func TestCreateStackRollsBackFailedInitialState(t *testing.T) {
	h := newHarness(t)
	h.store.saveCheckpointErr = errors.New("checkpoint write failed")

	rec := h.authed(t, "POST", "/api/stacks/acme/api", map[string]any{
		"stackName": "dev",
		"state":     map[string]any{"version": 3, "deployment": map[string]any{}},
	})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("create with failed state: %d %s", rec.Code, rec.Body)
	}
	if _, err := h.store.GetStack(t.Context(), "acme", "api", "dev"); !errors.Is(err, store.ErrStackNotFound) {
		t.Fatalf("partial stack remained after failed create: %v", err)
	}
}

func TestCreateStackRetainsRollbackFenceAfterPartialCleanup(t *testing.T) {
	h := newHarness(t)
	h.store.saveCheckpointErr = errors.New("checkpoint write failed")
	h.store.deleteErr = errors.New("partial cleanup failed")

	rec := h.authed(t, "POST", "/api/stacks/acme/api", map[string]any{
		"stackName": "dev",
		"state":     map[string]any{"version": 3, "deployment": map[string]any{}},
	})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("create with failed rollback: %d %s", rec.Code, rec.Body)
	}
	lock, err := h.store.GetLock(t.Context(), "acme", "api", "dev")
	if err != nil {
		t.Fatalf("rollback fence missing: %v", err)
	}
	if !strings.HasPrefix(lock.UpdateID, "delete-") {
		t.Fatalf("rollback lock = %+v", lock)
	}
}

func TestCreateStackDoesNotSeedReplacementIncarnation(t *testing.T) {
	h := newHarness(t)
	h.store.beforeSaveCheckpoint = func() {
		h.store.mu.Lock()
		defer h.store.mu.Unlock()
		h.store.stacks[key("acme", "api", "dev")] = &store.Stack{
			Org:         "acme",
			Project:     "api",
			Name:        "dev",
			Incarnation: "replacement",
			Created:     time.Now(),
		}
	}

	rec := h.authed(t, "POST", "/api/stacks/acme/api", map[string]any{
		"stackName": "dev",
		"state":     map[string]any{"version": 3, "deployment": map[string]any{}},
	})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("create raced replacement: status = %d, body = %s", rec.Code, rec.Body)
	}
	st, err := h.store.GetStack(t.Context(), "acme", "api", "dev")
	if err != nil || st.Incarnation != "replacement" {
		t.Fatalf("replacement stack = %+v, error = %v", st, err)
	}
	if _, err := h.store.GetCheckpoint(t.Context(), "acme", "api", "dev"); !errors.Is(err, store.ErrCheckpointNotFound) {
		t.Fatalf("replacement checkpoint was seeded: %v", err)
	}
}

func TestCreateStackDoesNotRollbackConcurrentOwner(t *testing.T) {
	h := newHarness(t)
	h.store.saveCheckpointErr = errors.New("checkpoint write failed")
	h.store.beforeSaveCheckpoint = func() {
		h.store.mu.Lock()
		defer h.store.mu.Unlock()
		k := key("acme", "api", "dev")
		h.store.stacks[k].Fence++
		h.store.locks[k] = &store.Lock{
			UpdateID:   "concurrent-update",
			Owner:      "other",
			Generation: h.store.stacks[k].Fence,
			ExpiresAt:  time.Now().Add(time.Minute),
		}
	}

	rec := h.authed(t, "POST", "/api/stacks/acme/api", map[string]any{
		"stackName": "dev",
		"state":     map[string]any{"version": 3, "deployment": map[string]any{}},
	})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("create with failed state: %d %s", rec.Code, rec.Body)
	}
	if _, err := h.store.GetStack(t.Context(), "acme", "api", "dev"); err != nil {
		t.Fatalf("concurrently owned stack was deleted: %v", err)
	}
	if h.store.deleteCalls != 0 {
		t.Fatalf("DeleteStack called %d times despite concurrent owner", h.store.deleteCalls)
	}
}

func TestExportImport(t *testing.T) {
	h := newHarness(t)
	h.authed(t, "POST", "/api/stacks/acme/api", map[string]any{"stackName": "dev"})

	// Export before any checkpoint → empty deployment (CLI treats 404 as fatal).
	rec := h.authed(t, "GET", "/api/stacks/acme/api/dev/export", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("export empty: status = %d", rec.Code)
	}
	empty := decode[map[string]any](t, rec)
	if empty["version"].(float64) != 3 {
		t.Errorf("empty export = %v", empty)
	}

	deployment := map[string]any{"version": 3, "deployment": map[string]any{"manifest": map[string]any{"time": "2026-09-07T00:00:00Z"}}}
	rec = h.authed(t, "POST", "/api/stacks/acme/api/dev/import", deployment)
	if rec.Code != http.StatusOK {
		t.Fatalf("import: status = %d, body = %s", rec.Code, rec.Body)
	}
	resp := decode[map[string]any](t, rec)
	if resp["updateId"] == "" {
		t.Error("import response missing updateId")
	}

	rec = h.authed(t, "GET", "/api/stacks/acme/api/dev/export", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("export: status = %d", rec.Code)
	}
	exported := decode[map[string]any](t, rec)
	if exported["version"].(float64) != 3 {
		t.Errorf("exported = %v", exported)
	}
}

func TestDeleteStackWithResourcesRequiresForce(t *testing.T) {
	h := newHarness(t)
	h.authed(t, "POST", "/api/stacks/acme/api", map[string]any{"stackName": "dev"})
	h.authed(t, "POST", "/api/stacks/acme/api/dev/import", map[string]any{
		"version": 3,
		"deployment": map[string]any{
			"resources": []any{map[string]any{"urn": "urn:pulumi:dev::api::aws:s3/bucket:Bucket::b"}},
		},
	})

	rec := h.authed(t, "DELETE", "/api/stacks/acme/api/dev", nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("delete without force: status = %d, body = %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "Stack still contains resources") {
		t.Errorf("body = %s", rec.Body)
	}
	if rec := h.authed(t, "DELETE", "/api/stacks/acme/api/dev?force=true", nil); rec.Code != http.StatusNoContent {
		t.Errorf("delete with force: status = %d", rec.Code)
	}
}

func TestDeleteStackFailsClosedOnCheckpointReadError(t *testing.T) {
	h := newHarness(t)
	createStack(t, h, "acme", "api", "dev")
	h.store.checkpointErr = errors.New("s3 unavailable")

	rec := h.authed(t, "DELETE", "/api/stacks/acme/api/dev", nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("delete with checkpoint error: status = %d, body = %s", rec.Code, rec.Body)
	}
	if h.store.deleteCalls != 0 {
		t.Fatal("stack deletion attempted after checkpoint read error")
	}
}

func TestDeleteStackFailsClosedOnMalformedCheckpoint(t *testing.T) {
	h := newHarness(t)
	createStack(t, h, "acme", "api", "dev")
	h.store.checkpoint[key("acme", "api", "dev")] = json.RawMessage(`{`)

	rec := h.authed(t, "DELETE", "/api/stacks/acme/api/dev", nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("delete with malformed checkpoint: status = %d, body = %s", rec.Code, rec.Body)
	}
	if h.store.deleteCalls != 0 {
		t.Fatal("stack deletion attempted after malformed checkpoint")
	}
}

// --- update lifecycle tests ---

func createStack(t *testing.T, h *harness, org, project, stack string) {
	t.Helper()
	if rec := h.authed(t, "POST", "/api/stacks/"+org+"/"+project, map[string]any{"stackName": stack}); rec.Code != http.StatusOK {
		t.Fatalf("create stack: %d %s", rec.Code, rec.Body)
	}
}

func createUpdate(t *testing.T, h *harness, kind string) (updateID string, updateToken string) {
	t.Helper()
	rec := h.authed(t, "POST", "/api/stacks/acme/api/dev/"+kind, map[string]any{
		"name": "api", "runtime": "nodejs", "options": map[string]any{},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("create update: %d %s", rec.Code, rec.Body)
	}
	resp := decode[map[string]any](t, rec)
	updateID, _ = resp["updateID"].(string)
	if updateID == "" {
		t.Fatal("no updateID")
	}

	rec = h.authed(t, "POST", "/api/stacks/acme/api/dev/update/"+updateID, map[string]any{})
	if rec.Code != http.StatusOK {
		t.Fatalf("start update: %d %s", rec.Code, rec.Body)
	}
	start := decode[map[string]any](t, rec)
	updateToken, _ = start["token"].(string)
	if updateToken == "" {
		t.Fatal("no update token")
	}
	if v, _ := start["version"].(float64); (kind == "preview" && v < 0) || (kind != "preview" && v < 1) {
		t.Errorf("version = %v", start["version"])
	}
	if jv, ok := start["journalVersion"]; ok && jv != float64(0) {
		t.Errorf("journalVersion = %v, want 0 (disabled)", jv)
	}
	return updateID, updateToken
}

func TestUpdateLifecycle(t *testing.T) {
	h := newHarness(t)
	createStack(t, h, "acme", "api", "dev")
	updateID, updateToken := createUpdate(t, h, "update")

	// Checkpoint with update token.
	deployment := map[string]any{"version": 3, "deployment": map[string]any{"manifest": map[string]any{}}}
	rec := h.do(t, "PATCH", "/api/stacks/acme/api/dev/update/"+updateID+"/checkpoint",
		map[string]any{"version": 3, "deployment": map[string]any{"manifest": map[string]any{}}},
		"Authorization", "update-token "+updateToken)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("checkpoint: %d %s", rec.Code, rec.Body)
	}

	// Checkpoint rejected with user token lacking update scope? User token is accepted
	// by middleware but must not authorize update operations.
	rec = h.authed(t, "PATCH", "/api/stacks/acme/api/dev/update/"+updateID+"/checkpoint",
		map[string]any{"version": 3, "deployment": map[string]any{}})
	if rec.Code != http.StatusForbidden && rec.Code != http.StatusUnauthorized {
		t.Errorf("checkpoint with user token: %d", rec.Code)
	}

	// Renew lease.
	rec = h.do(t, "POST", "/api/stacks/acme/api/dev/update/"+updateID+"/renew_lease",
		map[string]any{"duration": 120}, "Authorization", "update-token "+updateToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("renew_lease: %d %s", rec.Code, rec.Body)
	}
	renew := decode[map[string]any](t, rec)
	if renew["token"] == "" {
		t.Error("renew response missing token")
	}

	// Events sink.
	rec = h.do(t, "POST", "/api/stacks/acme/api/dev/update/"+updateID+"/events/batch",
		map[string]any{"events": []any{}}, "Authorization", "update-token "+updateToken)
	if rec.Code != http.StatusNoContent {
		t.Errorf("events/batch: %d", rec.Code)
	}

	// Complete.
	rec = h.do(t, "POST", "/api/stacks/acme/api/dev/update/"+updateID+"/complete",
		map[string]any{"status": "succeeded"}, "Authorization", "update-token "+updateToken)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("complete: %d %s", rec.Code, rec.Body)
	}

	// State exported matches checkpoint.
	rec = h.authed(t, "GET", "/api/stacks/acme/api/dev/export", nil)
	exported := decode[map[string]any](t, rec)
	if exported["version"].(float64) != 3 {
		t.Errorf("export = %v", exported)
	}
	_ = deployment

	// History shows the completed update.
	rec = h.authed(t, "GET", "/api/stacks/acme/api/dev/updates", nil)
	history := decode[map[string]any](t, rec)
	updates, _ := history["updates"].([]any)
	if len(updates) != 1 {
		t.Fatalf("history = %v", history)
	}
	u := updates[0].(map[string]any)
	if u["kind"] != "update" || u["result"] != "succeeded" || u["version"].(float64) != 1 {
		t.Errorf("history entry = %v", u)
	}

	// Latest + by-version.
	rec = h.authed(t, "GET", "/api/stacks/acme/api/dev/updates/latest", nil)
	if rec.Code != http.StatusOK {
		t.Errorf("latest: %d", rec.Code)
	}
	latest := decode[map[string]any](t, rec)
	info, ok := latest["info"].(map[string]any)
	if !ok {
		t.Fatalf("latest response has no info object: %v", latest)
	}
	if info["version"] != float64(1) || info["result"] != "succeeded" {
		t.Errorf("latest info = %v", info)
	}
	if rec := h.authed(t, "GET", "/api/stacks/acme/api/dev/updates/1", nil); rec.Code != http.StatusOK {
		t.Errorf("by version: %d", rec.Code)
	}
}

func TestOperationKindsUseCLICanonicalUpdatePath(t *testing.T) {
	for _, kind := range []string{"refresh", "destroy"} {
		t.Run(kind, func(t *testing.T) {
			h := newHarness(t)
			createStack(t, h, "acme", "api", "dev")
			updateID, updateToken := createUpdate(t, h, kind)

			rec := h.do(t, "POST", "/api/stacks/acme/api/dev/update/"+updateID+"/complete",
				map[string]any{"status": "succeeded"},
				"Authorization", "update-token "+updateToken)
			if rec.Code != http.StatusNoContent {
				t.Fatalf("complete %s: status = %d, body = %s", kind, rec.Code, rec.Body)
			}
		})
	}
}

func TestUpdateTokenCannotAccessUserRoutes(t *testing.T) {
	h := newHarness(t)
	createStack(t, h, "acme", "api", "dev")
	_, updateToken := createUpdate(t, h, "update")

	rec := h.do(t, "GET", "/api/user", nil, "Authorization", "update-token "+updateToken)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("update token accessed user route: status = %d, body = %s", rec.Code, rec.Body)
	}
}

func TestUpdateRoutesRequireUpdateTokenScheme(t *testing.T) {
	h := newHarness(t)
	createStack(t, h, "acme", "api", "dev")
	updateID, updateToken := createUpdate(t, h, "update")

	rec := h.do(t, "POST", "/api/stacks/acme/api/dev/update/"+updateID+"/renew_lease",
		map[string]any{"duration": 300}, "Authorization", "token "+updateToken)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("update token scheme accepted as user token: status = %d, body = %s", rec.Code, rec.Body)
	}
}

func TestUntypedUpdateTokenIsRejected(t *testing.T) {
	h := newHarness(t)
	createStack(t, h, "acme", "api", "dev")
	updateID, _ := createUpdate(t, h, "update")
	untyped := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":      testIdentity().Subject,
		"oidc_iss": testIdentity().Issuer,
		"upd":      updateID,
		"org":      "acme",
		"prj":      "api",
		"stk":      "dev",
		"iat":      time.Now().Unix(),
		"exp":      time.Now().Add(time.Minute).Unix(),
	})
	untyped.Header["kid"] = h.issuer.ActiveKeyID
	untypedToken, err := untyped.SignedString(h.issuer.Keys[h.issuer.ActiveKeyID])
	if err != nil {
		t.Fatal(err)
	}

	rec := h.do(t, "POST", "/api/stacks/acme/api/dev/update/"+updateID+"/renew_lease",
		map[string]any{"duration": 300}, "Authorization", "update-token "+untypedToken)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("untyped token: status = %d, body = %s", rec.Code, rec.Body)
	}
}

func TestLockRenewalUsesMigratedGeneration(t *testing.T) {
	h := newHarness(t)
	createStack(t, h, "acme", "api", "dev")
	h.store.mu.Lock()
	h.store.locks[key("acme", "api", "dev")] = &store.Lock{
		UpdateID: "legacy-update",
		Owner:    h.identity.Principal(),
		ExpiresAt: time.Now().
			Add(time.Minute),
	}
	h.store.updates[key("acme", "api", "dev")+"/legacy-update"] = &store.Update{
		ID: "legacy-update", Kind: "update", Status: "in-progress",
	}
	h.store.renewGeneration = 7
	h.store.mu.Unlock()
	token, _, err := h.issuer.IssueUpdate(
		h.identity,
		authn.UpdateClaims{
			UpdateID: "legacy-update",
			Org:      "acme",
			Project:  "api",
			Stack:    "dev",
			Kind:     "update",
		},
		time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}

	rec := h.do(t, "POST", "/api/stacks/acme/api/dev/update/legacy-update/renew_lease",
		map[string]any{"duration": 300}, "Authorization", "update-token "+token)
	if rec.Code != http.StatusOK {
		t.Fatalf("lock migration renewal: status = %d, body = %s", rec.Code, rec.Body)
	}
	renewed := decode[map[string]any](t, rec)["token"].(string)
	_, claims, err := h.issuer.VerifyScoped(renewed)
	if err != nil || claims == nil || claims.Generation != 7 {
		t.Fatalf("renewed claims = %+v, error = %v", claims, err)
	}
}

func TestStartUpdateRefreshesInitialLease(t *testing.T) {
	h := newHarness(t)
	createStack(t, h, "acme", "api", "dev")
	rec := h.authed(t, "POST", "/api/stacks/acme/api/dev/update", map[string]any{
		"name": "api", "runtime": "nodejs",
	})
	updateID := decode[map[string]any](t, rec)["updateID"].(string)
	h.store.mu.Lock()
	h.store.locks[key("acme", "api", "dev")].ExpiresAt = time.Now().Add(time.Second)
	h.store.mu.Unlock()

	rec = h.authed(t, "POST", "/api/stacks/acme/api/dev/update/"+updateID, map[string]any{})
	if rec.Code != http.StatusOK {
		t.Fatalf("start update: %d %s", rec.Code, rec.Body)
	}
	lock, err := h.store.GetLock(t.Context(), "acme", "api", "dev")
	if err != nil {
		t.Fatal(err)
	}
	if time.Until(lock.ExpiresAt) < 4*time.Minute {
		t.Fatalf("initial lease was not refreshed: expires %v", lock.ExpiresAt)
	}
}

func TestCreateUpdateReplayReturnsExistingUpdate(t *testing.T) {
	h := newHarness(t)
	createStack(t, h, "acme", "api", "dev")
	path := "/api/stacks/acme/api/dev/update"
	req := map[string]any{"name": "api", "runtime": "nodejs"}

	first := h.authed(t, "POST", path, req)
	if first.Code != http.StatusOK {
		t.Fatalf("first create: %d %s", first.Code, first.Body)
	}
	firstID := decode[map[string]any](t, first)["updateID"]

	replay := h.authed(t, "POST", path, req)
	if replay.Code != http.StatusOK {
		t.Fatalf("replayed create: %d %s", replay.Code, replay.Body)
	}
	if replayID := decode[map[string]any](t, replay)["updateID"]; replayID != firstID {
		t.Fatalf("replayed update ID = %v, want %v", replayID, firstID)
	}
}

func TestCreateUpdateReplayCommitsPendingRecord(t *testing.T) {
	h := newHarness(t)
	createStack(t, h, "acme", "api", "dev")
	expiresAt := time.Now().Add(time.Minute)
	h.store.mu.Lock()
	h.store.locks[key("acme", "api", "dev")] = &store.Lock{
		UpdateID: "pending-update", Owner: h.identity.Principal(),
		Generation: 1, ExpiresAt: expiresAt,
	}
	h.store.updates[key("acme", "api", "dev")+"/pending-update"] = &store.Update{
		ID: "pending-update", Kind: "update", Status: "not-started", Version: 1,
	}
	h.store.mu.Unlock()

	rec := h.authed(t, "POST", "/api/stacks/acme/api/dev/update", map[string]any{
		"name": "api", "runtime": "nodejs",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("replayed create: status = %d, body = %s", rec.Code, rec.Body)
	}
	if updateID := decode[map[string]any](t, rec)["updateID"]; updateID != "pending-update" {
		t.Fatalf("update ID = %v", updateID)
	}
	h.store.mu.Lock()
	defer h.store.mu.Unlock()
	if got := h.store.stacks[key("acme", "api", "dev")].Version; got != 1 {
		t.Fatalf("stack version = %d, want committed version 1", got)
	}
	if got := h.store.locks[key("acme", "api", "dev")].ExpiresAt; !got.After(expiresAt) {
		t.Fatalf("lease expiry = %v, want after %v", got, expiresAt)
	}
}

func TestStartUpdateReplayReturnsLeaseToken(t *testing.T) {
	h := newHarness(t)
	createStack(t, h, "acme", "api", "dev")
	created := h.authed(t, "POST", "/api/stacks/acme/api/dev/update", map[string]any{
		"name": "api", "runtime": "nodejs",
	})
	updateID := decode[map[string]any](t, created)["updateID"].(string)
	path := "/api/stacks/acme/api/dev/update/" + updateID
	if first := h.authed(t, "POST", path, map[string]any{}); first.Code != http.StatusOK {
		t.Fatalf("first start: %d %s", first.Code, first.Body)
	}

	replay := h.authed(t, "POST", path, map[string]any{})
	if replay.Code != http.StatusOK {
		t.Fatalf("replayed start: %d %s", replay.Code, replay.Body)
	}
	if token, _ := decode[map[string]any](t, replay)["token"].(string); token == "" {
		t.Fatal("replayed start returned no lease token")
	}
}

func TestCancelNotStartedUpdateUsesCLICanonicalKind(t *testing.T) {
	for _, kind := range []string{"update", "refresh", "destroy"} {
		t.Run(kind, func(t *testing.T) {
			h := newHarness(t)
			createStack(t, h, "acme", "api", "dev")
			created := h.authed(t, "POST", "/api/stacks/acme/api/dev/"+kind, map[string]any{
				"name": "api", "runtime": "nodejs",
			})
			updateID := decode[map[string]any](t, created)["updateID"].(string)

			rec := h.authed(t, "POST", "/api/stacks/acme/api/dev/update/"+updateID+"/cancel", nil)
			if rec.Code != http.StatusNoContent {
				t.Fatalf("cancel: status = %d, body = %s", rec.Code, rec.Body)
			}
			update, err := h.store.GetUpdate(t.Context(), "acme", "api", "dev", updateID)
			if err != nil || update.Status != "cancelled" {
				t.Fatalf("update = %+v, error = %v", update, err)
			}
			if _, err := h.store.GetLock(t.Context(), "acme", "api", "dev"); !errors.Is(err, store.ErrNoLock) {
				t.Fatalf("lock remains after cancel: %v", err)
			}
		})
	}
}

func TestCompletedUpdateCannotRestart(t *testing.T) {
	h := newHarness(t)
	createStack(t, h, "acme", "api", "dev")
	updateID, updateToken := createUpdate(t, h, "update")
	rec := h.do(t, "POST", "/api/stacks/acme/api/dev/update/"+updateID+"/complete",
		map[string]any{"status": "succeeded"}, "Authorization", "update-token "+updateToken)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("complete: %d %s", rec.Code, rec.Body)
	}

	rec = h.authed(t, "POST", "/api/stacks/acme/api/dev/update/"+updateID, map[string]any{})
	if rec.Code != http.StatusConflict {
		t.Fatalf("completed update restarted: status = %d, body = %s", rec.Code, rec.Body)
	}
}

func TestCompleteUpdateIsIdempotent(t *testing.T) {
	h := newHarness(t)
	createStack(t, h, "acme", "api", "dev")
	updateID, updateToken := createUpdate(t, h, "update")
	path := "/api/stacks/acme/api/dev/update/" + updateID + "/complete"
	for attempt := 0; attempt < 2; attempt++ {
		rec := h.do(t, "POST", path, map[string]any{"status": "succeeded"},
			"Authorization", "update-token "+updateToken)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("complete attempt %d: %d %s", attempt+1, rec.Code, rec.Body)
		}
	}
}

func TestCompleteRejectsNonterminalStatus(t *testing.T) {
	h := newHarness(t)
	createStack(t, h, "acme", "api", "dev")
	updateID, updateToken := createUpdate(t, h, "update")

	rec := h.do(t, "POST", "/api/stacks/acme/api/dev/update/"+updateID+"/complete",
		map[string]any{"status": "in-progress"}, "Authorization", "update-token "+updateToken)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("nonterminal completion status: %d %s", rec.Code, rec.Body)
	}
	if _, err := h.store.GetLock(t.Context(), "acme", "api", "dev"); err != nil {
		t.Fatalf("completion released lock: %v", err)
	}
}

func TestPreviewUsesCLICanonicalUpdatePath(t *testing.T) {
	h := newHarness(t)
	createStack(t, h, "acme", "api", "dev")

	rec := h.authed(t, "POST", "/api/stacks/acme/api/dev/preview", map[string]any{
		"name": "api", "runtime": "nodejs",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("create preview: %d %s", rec.Code, rec.Body)
	}
	updateID := decode[map[string]any](t, rec)["updateID"].(string)
	rec = h.authed(t, "POST", "/api/stacks/acme/api/dev/update/"+updateID, map[string]any{})
	if rec.Code != http.StatusOK {
		t.Fatalf("start preview: %d %s", rec.Code, rec.Body)
	}
	started := decode[map[string]any](t, rec)
	if started["version"] != float64(0) {
		t.Fatalf("preview version = %v, want current version 0", started["version"])
	}
	updateToken := started["token"].(string)

	rec = h.do(t, "PATCH", "/api/stacks/acme/api/dev/update/"+updateID+"/checkpoint",
		map[string]any{"version": 3, "deployment": map[string]any{}},
		"Authorization", "update-token "+updateToken)
	if rec.Code != http.StatusConflict {
		t.Fatalf("preview wrote checkpoint: status = %d, body = %s", rec.Code, rec.Body)
	}

	rec = h.do(t, "POST", "/api/stacks/acme/api/dev/update/"+updateID+"/complete",
		map[string]any{"status": "succeeded"},
		"Authorization", "update-token "+updateToken)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("complete preview: status = %d, body = %s", rec.Code, rec.Body)
	}
}

func TestPreviewDoesNotEnterUpdateHistory(t *testing.T) {
	h := newHarness(t)
	createStack(t, h, "acme", "api", "dev")
	rec := h.authed(t, "POST", "/api/stacks/acme/api/dev/preview", map[string]any{
		"name": "api", "runtime": "nodejs",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("create preview: %d %s", rec.Code, rec.Body)
	}

	rec = h.authed(t, "GET", "/api/stacks/acme/api/dev/updates", nil)
	updates := decode[map[string]any](t, rec)["updates"].([]any)
	if len(updates) != 0 {
		t.Fatalf("preview entered update history: %v", updates)
	}
}

func TestPreviewLeaseRenewalDoesNotRequireStackLock(t *testing.T) {
	h := newHarness(t)
	createStack(t, h, "acme", "api", "dev")
	updateID, updateToken := createUpdate(t, h, "preview")

	rec := h.do(t, "POST", "/api/stacks/acme/api/dev/update/"+updateID+"/renew_lease",
		map[string]any{"duration": 300}, "Authorization", "update-token "+updateToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("preview renew: %d %s", rec.Code, rec.Body)
	}
}

func TestStaleUpdateCannotCheckpointAfterLockReplacement(t *testing.T) {
	h := newHarness(t)
	createStack(t, h, "acme", "api", "dev")
	updateID, updateToken := createUpdate(t, h, "update")
	h.store.mu.Lock()
	h.store.locks[key("acme", "api", "dev")] = &store.Lock{
		UpdateID:  "replacement",
		Owner:     "other@example.com",
		ExpiresAt: time.Now().Add(time.Minute),
	}
	h.store.mu.Unlock()

	rec := h.do(t, "PATCH", "/api/stacks/acme/api/dev/update/"+updateID+"/checkpoint",
		map[string]any{"version": 3, "deployment": map[string]any{}},
		"Authorization", "update-token "+updateToken)
	if rec.Code != http.StatusConflict {
		t.Fatalf("stale update checkpoint: %d %s", rec.Code, rec.Body)
	}
}

func TestCheckpointIsFencedWhenLockChangesDuringWrite(t *testing.T) {
	h := newHarness(t)
	createStack(t, h, "acme", "api", "dev")
	updateID, updateToken := createUpdate(t, h, "update")
	h.store.beforeSaveCheckpoint = func() {
		h.store.mu.Lock()
		defer h.store.mu.Unlock()
		h.store.locks[key("acme", "api", "dev")] = &store.Lock{
			UpdateID:  "replacement",
			Owner:     "other@example.com",
			ExpiresAt: time.Now().Add(time.Minute),
		}
		h.store.beforeSaveCheckpoint = nil
	}

	rec := h.do(t, "PATCH", "/api/stacks/acme/api/dev/update/"+updateID+"/checkpoint",
		map[string]any{"version": 3, "deployment": map[string]any{"stale": true}},
		"Authorization", "update-token "+updateToken)
	if rec.Code != http.StatusConflict {
		t.Fatalf("checkpoint crossed lock replacement: %d %s", rec.Code, rec.Body)
	}
	if _, err := h.store.GetCheckpoint(t.Context(), "acme", "api", "dev"); !errors.Is(err, store.ErrCheckpointNotFound) {
		t.Fatalf("stale checkpoint became visible: %v", err)
	}
}

func TestConcurrentUpdateConflict(t *testing.T) {
	h := newHarness(t)
	createStack(t, h, "acme", "api", "dev")
	createUpdate(t, h, "update") // holds the lock (never completed)

	rec := h.authed(t, "POST", "/api/stacks/acme/api/dev/update", map[string]any{
		"name": "api", "runtime": "nodejs",
	})
	if rec.Code != http.StatusConflict {
		t.Fatalf("second update: %d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "locked") {
		t.Errorf("body = %s", rec.Body)
	}
}

func TestPreviewDoesNotLock(t *testing.T) {
	h := newHarness(t)
	createStack(t, h, "acme", "api", "dev")
	createUpdate(t, h, "update") // lock held
	// Preview still allowed.
	rec := h.authed(t, "POST", "/api/stacks/acme/api/dev/preview", map[string]any{
		"name": "api", "runtime": "nodejs",
	})
	if rec.Code != http.StatusOK {
		t.Errorf("preview during update: %d %s", rec.Code, rec.Body)
	}
}

func TestDeleteStackRejectsActiveUpdate(t *testing.T) {
	h := newHarness(t)
	createStack(t, h, "acme", "api", "dev")
	createUpdate(t, h, "update")

	rec := h.authed(t, "DELETE", "/api/stacks/acme/api/dev?force=true", nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("delete during update: %d %s", rec.Code, rec.Body)
	}
	if h.store.deleteCalls != 0 {
		t.Fatal("delete attempted while update held lock")
	}
}

func TestDeleteStackResumesOwnedDeletionFence(t *testing.T) {
	h := newHarness(t)
	createStack(t, h, "acme", "api", "dev")
	h.store.mu.Lock()
	h.store.locks[key("acme", "api", "dev")] = &store.Lock{
		UpdateID:   "delete-previous-attempt",
		Owner:      h.identity.Principal(),
		Generation: 1,
		ExpiresAt:  time.Now().Add(time.Minute),
	}
	h.store.mu.Unlock()

	rec := h.authed(t, "DELETE", "/api/stacks/acme/api/dev?force=true", nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete retry: status = %d, body = %s", rec.Code, rec.Body)
	}
}

func TestCancelReleasesLock(t *testing.T) {
	h := newHarness(t)
	createStack(t, h, "acme", "api", "dev")
	updateID, _ := createUpdate(t, h, "update")

	// Cancel uses the user token, not the update token.
	rec := h.authed(t, "POST", "/api/stacks/acme/api/dev/update/"+updateID+"/cancel", nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("cancel: %d %s", rec.Code, rec.Body)
	}
	// Lock free → new update can be created.
	rec = h.authed(t, "POST", "/api/stacks/acme/api/dev/update", map[string]any{
		"name": "api", "runtime": "nodejs",
	})
	if rec.Code != http.StatusOK {
		t.Errorf("update after cancel: %d %s", rec.Code, rec.Body)
	}
}

func TestCancelUpdateIsIdempotent(t *testing.T) {
	h := newHarness(t)
	createStack(t, h, "acme", "api", "dev")
	updateID, _ := createUpdate(t, h, "update")
	path := "/api/stacks/acme/api/dev/update/" + updateID + "/cancel"
	for attempt := 0; attempt < 2; attempt++ {
		rec := h.authed(t, "POST", path, nil)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("cancel attempt %d: %d %s", attempt+1, rec.Code, rec.Body)
		}
	}
}

func TestGzipRequestBody(t *testing.T) {
	h := newHarness(t)
	createStack(t, h, "acme", "api", "dev")
	updateID, updateToken := createUpdate(t, h, "update")

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_ = json.NewEncoder(gz).Encode(map[string]any{"version": 3, "deployment": map[string]any{"x": 1}})
	_ = gz.Close()

	req := httptest.NewRequest("PATCH", "/api/stacks/acme/api/dev/update/"+updateID+"/checkpoint", &buf)
	req.Header.Set("Authorization", "update-token "+updateToken)
	req.Header.Set("Content-Encoding", "gzip")
	rec := httptest.NewRecorder()
	h.server.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("gzipped checkpoint: %d %s", rec.Code, rec.Body)
	}
}

func TestRejectsOversizedGzipRequestBody(t *testing.T) {
	h := newHarness(t)
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, _ = gz.Write([]byte(`{"token":"`))
	chunk := bytes.Repeat([]byte("a"), 1024)
	for range 32*1024 + 1 {
		_, _ = gz.Write(chunk)
	}
	_, _ = gz.Write([]byte(`"}`))
	_ = gz.Close()

	req := httptest.NewRequest("POST", "/api/token/exchange", &buf)
	req.Header.Set("Content-Encoding", "gzip")
	rec := httptest.NewRecorder()
	h.server.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: status = %d, body = %s", rec.Code, rec.Body)
	}
}

// --- crypto tests ---

func TestEncryptDecrypt(t *testing.T) {
	h := newHarness(t)
	createStack(t, h, "acme", "api", "dev")

	rec := h.authed(t, "POST", "/api/stacks/acme/api/dev/encrypt", map[string]any{"plaintext": "aGVsbG8="})
	if rec.Code != http.StatusOK {
		t.Fatalf("encrypt: %d %s", rec.Code, rec.Body)
	}
	resp := decode[map[string]any](t, rec)
	ciphertext, _ := resp["ciphertext"].(string)
	if ciphertext == "" {
		t.Fatal("no ciphertext")
	}

	rec = h.authed(t, "POST", "/api/stacks/acme/api/dev/decrypt", map[string]any{"ciphertext": ciphertext})
	if rec.Code != http.StatusOK {
		t.Fatalf("decrypt: %d %s", rec.Code, rec.Body)
	}
	dec := decode[map[string]any](t, rec)
	if dec["plaintext"] != "aGVsbG8=" { // base64 round-trip of "hello"
		t.Errorf("plaintext = %v", dec["plaintext"])
	}
}

func TestEncryptBindsCiphertextToStack(t *testing.T) {
	crypter, err := secrets.NewCrypter("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=")
	if err != nil {
		t.Fatal(err)
	}
	h := newHarnessWithCrypter(t, crypter)
	createStack(t, h, "acme", "api", "dev")
	createStack(t, h, "acme", "api", "other")

	rec := h.authed(t, "POST", "/api/stacks/acme/api/dev/encrypt", map[string]any{"plaintext": "aGVsbG8="})
	if rec.Code != http.StatusOK {
		t.Fatalf("encrypt: %d %s", rec.Code, rec.Body)
	}
	ciphertext := decode[map[string]any](t, rec)["ciphertext"]

	rec = h.authed(t, "POST", "/api/stacks/acme/api/other/decrypt", map[string]any{"ciphertext": ciphertext})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("decrypt with a different stack: status = %d, body = %s", rec.Code, rec.Body)
	}
}

func TestBatchDecryptKeysPlaintextsByBase64Ciphertext(t *testing.T) {
	h := newHarness(t)
	createStack(t, h, "acme", "api", "dev")

	ciphertext := base64.StdEncoding.EncodeToString([]byte("v2:fake:hello"))
	rec := h.authed(t, "POST", "/api/stacks/acme/api/dev/batch-decrypt", map[string]any{
		"ciphertexts": []string{ciphertext},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("batch decrypt: %d %s", rec.Code, rec.Body)
	}

	resp := decode[struct {
		Plaintexts map[string]string `json:"plaintexts"`
	}](t, rec)
	if got := resp.Plaintexts[ciphertext]; got != "aGVsbG8=" {
		t.Errorf("plaintexts[%q] = %q, want %q", ciphertext, got, "aGVsbG8=")
	}
}

func TestBatchEncryptRejectsTooManyItems(t *testing.T) {
	h := newHarness(t)
	createStack(t, h, "acme", "api", "dev")
	plaintexts := make([]string, 1001)
	for i := range plaintexts {
		plaintexts[i] = "eA=="
	}

	rec := h.authed(t, "POST", "/api/stacks/acme/api/dev/batch-encrypt", map[string]any{
		"plaintexts": plaintexts,
	})
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized batch: status = %d, body = %s", rec.Code, rec.Body)
	}
}

func TestBatchEncryptAcceptsPulumiMaximum(t *testing.T) {
	h := newHarness(t)
	createStack(t, h, "acme", "api", "dev")
	plaintexts := make([]string, 1000)
	for i := range plaintexts {
		plaintexts[i] = "eA=="
	}

	rec := h.authed(t, "POST", "/api/stacks/acme/api/dev/batch-encrypt", map[string]any{
		"plaintexts": plaintexts,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("Pulumi-sized batch: status = %d, body = %s", rec.Code, rec.Body)
	}
}

func TestMaximumPlaintextEncryptDecryptRoundTrip(t *testing.T) {
	h := newHarness(t)
	createStack(t, h, "acme", "api", "dev")
	plaintext := bytes.Repeat([]byte("x"), 1<<20)

	rec := h.authed(t, "POST", "/api/stacks/acme/api/dev/encrypt", map[string]any{
		"plaintext": plaintext,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("encrypt: status = %d, body = %s", rec.Code, rec.Body)
	}
	ciphertext := decode[map[string]any](t, rec)["ciphertext"]

	rec = h.authed(t, "POST", "/api/stacks/acme/api/dev/decrypt", map[string]any{
		"ciphertext": ciphertext,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("decrypt own output: status = %d, body = %s", rec.Code, rec.Body)
	}
}

func TestUpdateHistoryRejectsInvalidPagination(t *testing.T) {
	h := newHarness(t)
	createStack(t, h, "acme", "api", "dev")

	for _, query := range []string{"page=invalid", "pageSize=-1", "pageSize=1001"} {
		rec := h.authed(t, "GET", "/api/stacks/acme/api/dev/updates?"+query, nil)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, body = %s", query, rec.Code, rec.Body)
		}
	}
}

func TestUpdateHistoryReturnsAllEntriesByDefault(t *testing.T) {
	h := newHarness(t)
	createStack(t, h, "acme", "api", "dev")
	h.store.mu.Lock()
	for version := 1; version <= 101; version++ {
		updateID := fmt.Sprintf("update-%d", version)
		h.store.updates[key("acme", "api", "dev")+"/"+updateID] = &store.Update{
			ID: updateID, Kind: "update", Status: "succeeded", Version: version,
		}
	}
	h.store.mu.Unlock()

	for _, query := range []string{"", "?pageSize=0"} {
		rec := h.authed(t, "GET", "/api/stacks/acme/api/dev/updates"+query, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("%q: status = %d, body = %s", query, rec.Code, rec.Body)
		}
		updates := decode[map[string]any](t, rec)["updates"].([]any)
		if len(updates) != 101 {
			t.Fatalf("%q: updates = %d, want 101", query, len(updates))
		}
	}
}

// --- error logging ---

type errStore struct {
	*fakeStore
	err error
}

func (s *errStore) CreateStack(context.Context, string, string, string) (*store.Stack, error) {
	return nil, s.err
}

func TestInternalErrorLogsUnderlyingCause(t *testing.T) {
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	cfg := &config.Config{
		Issuer:           "https://example.com",
		ClientID:         "cid",
		SigningKeys:      []config.SigningKey{{ID: "test", Key: testSigningKey}},
		ActiveSigningKey: "test",
		SecretsKey:       "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
		Authorization:    testAuthorization("admins"),
		TokenTTL:         time.Hour,
		LeaseDuration:    5 * time.Minute,
	}
	issuer := &authn.TokenIssuer{
		Keys: map[string][]byte{"test": []byte(testSigningKey)}, ActiveKeyID: "test", TTL: time.Hour,
	}
	st := &errStore{fakeStore: newFakeStore(), err: errors.New("s3 exploded")}
	id := authn.Identity{Issuer: "https://issuer.example.com", Subject: "u", Username: "u", Groups: []string{"admins"}}
	srv := NewServer(cfg, issuer, fakeOIDC{identity: id}, st, fakeCrypter{})

	tok, err := issuer.Issue(id)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/api/stacks/acme/api", strings.NewReader(`{"stackName":"dev"}`))
	req.Header.Set("Authorization", "token "+tok)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "creating stack failed") {
		t.Errorf("client body = %s, want generic message", rec.Body)
	}
	if strings.Contains(rec.Body.String(), "s3 exploded") {
		t.Errorf("client body leaks internal error: %s", rec.Body)
	}
	if !strings.Contains(logs.String(), "s3 exploded") {
		t.Errorf("logs missing underlying error: %s", logs.String())
	}
}
