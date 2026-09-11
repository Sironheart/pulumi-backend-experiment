package authn

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testClientID = "test-client-id"

// testIdP is a minimal OIDC IdP: discovery document + JWKS.
func testIdP(t *testing.T) (*httptest.Server, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	srv := httptest.NewServer(nil)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": srv.URL, "jwks_uri": srv.URL + "/keys"})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		jwk := map[string]string{
			"kty": "RSA", "use": "sig", "kid": "test-key", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{jwk}})
	})
	srv.Config.Handler = mux
	t.Cleanup(srv.Close)
	return srv, key
}

func oidcToken(t *testing.T, key *rsa.PrivateKey, issuer string, claims jwt.MapClaims) string {
	t.Helper()
	base := jwt.MapClaims{
		"iss": issuer,
		"aud": testClientID,
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
		"sub": "user-sub",
	}
	for k, v := range claims {
		base[k] = v
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, base)
	tok.Header["kid"] = "test-key"
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func newValidator(t *testing.T, issuer string) *OIDCValidator {
	t.Helper()
	v, err := NewOIDCValidator(t.Context(), issuer, testClientID)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestValidateOIDCToken(t *testing.T) {
	srv, key := testIdP(t)
	v := newValidator(t, srv.URL)

	id, err := v.Validate(t.Context(), oidcToken(t, key, srv.URL, jwt.MapClaims{
		"preferred_username": "steffen@example.com",
		"groups":             []any{"g1", "g2"},
	}))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if id.Username != "steffen@example.com" {
		t.Errorf("username = %q", id.Username)
	}
	if len(id.Groups) != 2 || id.Groups[0] != "g1" {
		t.Errorf("groups = %v", id.Groups)
	}
}

func TestValidateFallsBackToSub(t *testing.T) {
	srv, key := testIdP(t)
	v := newValidator(t, srv.URL)
	id, err := v.Validate(t.Context(), oidcToken(t, key, srv.URL, nil))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if id.Username != "user-sub" {
		t.Errorf("username = %q, want sub fallback", id.Username)
	}
}

func TestValidateRejects(t *testing.T) {
	srv, key := testIdP(t)
	v := newValidator(t, srv.URL)

	cases := map[string]jwt.MapClaims{
		"wrong audience": {"aud": "someone-else"},
		"wrong issuer":   {"iss": "https://evil.example.com"},
		"expired":        {"exp": time.Now().Add(-time.Hour).Unix()},
	}
	for name, claims := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := v.Validate(t.Context(), oidcToken(t, key, srv.URL, claims)); err == nil {
				t.Error("expected error")
			}
		})
	}

	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	t.Run("wrong signing key", func(t *testing.T) {
		if _, err := v.Validate(t.Context(), oidcToken(t, otherKey, srv.URL, nil)); err == nil {
			t.Error("expected error")
		}
	})
}

func TestBackendTokenRoundTrip(t *testing.T) {
	issuer := &TokenIssuer{Key: []byte("secret"), TTL: time.Hour}
	want := Identity{Username: "steffen@example.com", Groups: []string{"g1"}}
	tok, err := issuer.Issue(want)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	got, err := issuer.Verify(tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Username != want.Username || len(got.Groups) != 1 || got.Groups[0] != "g1" {
		t.Errorf("got %+v", got)
	}
}

func TestBackendTokenRejects(t *testing.T) {
	issuer := &TokenIssuer{Key: []byte("secret"), TTL: time.Hour}
	tok, _ := issuer.Issue(Identity{Username: "u"})

	if _, err := issuer.Verify(tok + "tampered"); err == nil {
		t.Error("tampered token accepted")
	}
	other := &TokenIssuer{Key: []byte("other-key"), TTL: time.Hour}
	if _, err := other.Verify(tok); err == nil {
		t.Error("wrong key accepted")
	}
	expired := &TokenIssuer{Key: []byte("secret"), TTL: -time.Hour}
	tok, _ = expired.Issue(Identity{Username: "u"})
	if _, err := expired.Verify(tok); err == nil {
		t.Error("expired token accepted")
	}
}

func TestBackendTokenRejectsUpdateToken(t *testing.T) {
	issuer := &TokenIssuer{Key: []byte("secret"), TTL: time.Hour}
	tok, _, err := issuer.IssueUpdate(Identity{Username: "u"}, UpdateClaims{
		UpdateID: "update-1",
		Org:      "acme",
		Project:  "api",
		Stack:    "dev",
	}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.Verify(tok); err == nil {
		t.Fatal("update token accepted as backend user token")
	}
}

func TestTokenIssuerRejectsUnusableTTLs(t *testing.T) {
	issuer := &TokenIssuer{Key: []byte("secret"), TTL: time.Second}
	if _, err := issuer.Issue(Identity{Username: "u"}); err == nil {
		t.Fatal("backend token accepted unusable TTL")
	}
	if _, _, err := issuer.IssueUpdate(
		Identity{Username: "u"},
		UpdateClaims{UpdateID: "update-1", Org: "acme", Project: "api", Stack: "dev", Kind: "update"},
		time.Second,
	); err == nil {
		t.Fatal("update token accepted unusable TTL")
	}
}

func TestBackendTokenRejectsWrongAudience(t *testing.T) {
	issuer := &TokenIssuer{Key: []byte("secret"), TTL: time.Hour}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "u",
		"typ": backendTokenType,
		"aud": "another-service",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	raw, err := token.SignedString(issuer.Key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.Verify(raw); err == nil {
		t.Fatal("token with wrong audience accepted")
	}
}

func TestBackendTokenRejectsTokenWithoutType(t *testing.T) {
	issuer := &TokenIssuer{Key: []byte("secret"), TTL: time.Hour}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":    "u",
		"groups": []string{"g1"},
		"exp":    time.Now().Add(time.Hour).Unix(),
	})
	raw, err := token.SignedString(issuer.Key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.Verify(raw); err == nil {
		t.Fatal("token without type accepted as backend token")
	}
}

func TestBackendTokenRejectsUntypedUpdateToken(t *testing.T) {
	issuer := &TokenIssuer{Key: []byte("secret"), TTL: time.Hour}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "u",
		"upd": "update-1",
		"org": "acme",
		"prj": "api",
		"stk": "dev",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	raw, err := token.SignedString(issuer.Key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.Verify(raw); err == nil {
		t.Fatal("untyped update token accepted as backend user token")
	}
}

func TestVerifyScopedRejectsTokenWithoutType(t *testing.T) {
	issuer := &TokenIssuer{Key: []byte("secret"), TTL: time.Hour}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "u",
		"upd": "update-1",
		"org": "acme",
		"prj": "api",
		"stk": "dev",
		"exp": time.Now().Add(time.Minute).Unix(),
	})
	raw, err := token.SignedString(issuer.Key)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := issuer.VerifyScoped(raw); err == nil {
		t.Fatal("token without type accepted as scoped token")
	}
}

func TestMiddleware(t *testing.T) {
	issuer := &TokenIssuer{Key: []byte("secret"), TTL: time.Hour}
	tok, _ := issuer.Issue(Identity{Username: "u", Groups: []string{"g1"}})

	handler := Middleware(issuer)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := IdentityFrom(r.Context())
		if !ok {
			t.Error("no identity in context")
		}
		if id.Username != "u" {
			t.Errorf("username = %q", id.Username)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "token "+tok)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("valid token: status = %d", rec.Code)
	}

	for _, header := range []string{"", "token invalid", "Bearer " + tok + "x"} {
		req := httptest.NewRequest("GET", "/", nil)
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("header %q: status = %d, want 401", header, rec.Code)
		}
	}
}

func ExampleTokenIssuer_Issue() {
	issuer := &TokenIssuer{Key: []byte("secret"), TTL: time.Hour}
	tok, _ := issuer.Issue(Identity{Username: "u"})
	fmt.Println(len(tok) > 0)
	// Output: true
}

func TestIdentityFromToken(t *testing.T) {
	if got := IdentityFromToken(""); got.Username != "local" {
		t.Errorf("empty: username = %q", got.Username)
	}
	first := IdentityFromToken("alice")
	if first.Username == "alice" || !strings.HasPrefix(first.Username, "local-") {
		t.Errorf("raw token leaked as username %q", first.Username)
	}
	if second := IdentityFromToken("alice"); second.Username != first.Username {
		t.Errorf("opaque identity is not stable: %q vs %q", first.Username, second.Username)
	}
	if other := IdentityFromToken("bob"); other.Username == first.Username {
		t.Errorf("different opaque tokens share identity %q", first.Username)
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"preferred_username": "steffen@example.com",
		"groups":             []any{"devs"},
		"exp":                time.Now().Add(time.Hour).Unix(),
	})
	raw, err := tok.SignedString([]byte("unrelated-key"))
	if err != nil {
		t.Fatal(err)
	}
	got := IdentityFromToken(raw)
	if got.Username != "steffen@example.com" {
		t.Errorf("jwt: username = %q", got.Username)
	}
	if len(got.Groups) != 1 || got.Groups[0] != "devs" {
		t.Errorf("jwt: groups = %v", got.Groups)
	}
}
