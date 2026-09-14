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

func newTokenIssuer(key string, ttl time.Duration) *TokenIssuer {
	return &TokenIssuer{
		Keys:        map[string][]byte{"test": []byte(key)},
		ActiveKeyID: "test",
		TTL:         ttl,
	}
}

func testIdentity(username string, groups ...string) Identity {
	return Identity{
		Issuer:   "https://issuer.example.com",
		Subject:  username + "-subject",
		Username: username,
		Groups:   groups,
	}
}

func signTestClaims(t *testing.T, issuer *TokenIssuer, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = issuer.ActiveKeyID
	raw, err := token.SignedString(issuer.Keys[issuer.ActiveKeyID])
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

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
	if id.Issuer != srv.URL || id.Subject != "user-sub" {
		t.Errorf("stable identity = (%q, %q)", id.Issuer, id.Subject)
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
	issuer := newTokenIssuer("secret", time.Hour)
	want := testIdentity("steffen@example.com", "g1")
	tok, err := issuer.Issue(want)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	got, err := issuer.Verify(tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Issuer != want.Issuer || got.Subject != want.Subject || got.Username != want.Username ||
		len(got.Groups) != 1 || got.Groups[0] != "g1" {
		t.Errorf("got %+v", got)
	}
}

func TestBackendTokenKeyRotation(t *testing.T) {
	old := &TokenIssuer{
		Keys:        map[string][]byte{"old": []byte("old-secret")},
		ActiveKeyID: "old",
		TTL:         time.Hour,
	}
	oldToken, err := old.Issue(testIdentity("u", "g1"))
	if err != nil {
		t.Fatal(err)
	}

	rotated := &TokenIssuer{
		Keys:        map[string][]byte{"old": []byte("old-secret"), "new": []byte("new-secret")},
		ActiveKeyID: "new",
		TTL:         time.Hour,
	}
	if _, err := rotated.Verify(oldToken); err != nil {
		t.Fatalf("Verify old token after rotation: %v", err)
	}

	newToken, err := rotated.Issue(testIdentity("u", "g1"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, _, err := jwt.NewParser().ParseUnverified(newToken, jwt.MapClaims{})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Header["kid"] != "new" {
		t.Errorf("kid = %v, want new", parsed.Header["kid"])
	}
	if _, err := (&TokenIssuer{Keys: map[string][]byte{"new": []byte("new-secret")}}).Verify(oldToken); err == nil {
		t.Fatal("old token remained valid after its key was removed")
	}
}

func TestBackendTokenRejectsMissingKeyID(t *testing.T) {
	issuer := newTokenIssuer("secret", time.Hour)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "u", "oidc_iss": "https://issuer.example.com", "typ": backendTokenType,
		"aud": backendTokenAudience, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
	})
	encoded, err := token.SignedString(issuer.Keys["test"])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.Verify(encoded); err == nil {
		t.Fatal("token without kid accepted")
	}
}

func TestBackendTokenRejects(t *testing.T) {
	issuer := newTokenIssuer("secret", time.Hour)
	tok, err := issuer.Issue(testIdentity("u"))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := issuer.Verify(tok + "tampered"); err == nil {
		t.Error("tampered token accepted")
	}
	other := newTokenIssuer("other-key", time.Hour)
	if _, err := other.Verify(tok); err == nil {
		t.Error("wrong key accepted")
	}
	tok = signTestClaims(t, issuer, jwt.MapClaims{
		"sub": testIdentity("u").Subject, "oidc_iss": testIdentity("u").Issuer,
		"iat": time.Now().Add(-2 * time.Hour).Unix(), "exp": time.Now().Add(-time.Hour).Unix(),
		"typ": backendTokenType, "aud": backendTokenAudience,
	})
	if _, err := issuer.Verify(tok); err == nil {
		t.Error("expired token accepted")
	}
}

func TestBackendTokenRejectsUpdateToken(t *testing.T) {
	issuer := newTokenIssuer("secret", time.Hour)
	tok, _, err := issuer.IssueUpdate(testIdentity("u"), UpdateClaims{
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
	issuer := newTokenIssuer("secret", time.Second)
	if _, err := issuer.Issue(testIdentity("u")); err == nil {
		t.Fatal("backend token accepted unusable TTL")
	}
	if _, _, err := issuer.IssueUpdate(
		testIdentity("u"),
		UpdateClaims{UpdateID: "update-1", Org: "acme", Project: "api", Stack: "dev", Kind: "update"},
		time.Second,
	); err == nil {
		t.Fatal("update token accepted unusable TTL")
	}
}

func TestBackendTokenRejectsWrongAudience(t *testing.T) {
	issuer := newTokenIssuer("secret", time.Hour)
	raw := signTestClaims(t, issuer, jwt.MapClaims{
		"sub":      "u",
		"oidc_iss": "https://issuer.example.com",
		"typ":      backendTokenType,
		"aud":      "another-service",
		"iat":      time.Now().Unix(),
		"exp":      time.Now().Add(time.Hour).Unix(),
	})
	if _, err := issuer.Verify(raw); err == nil {
		t.Fatal("token with wrong audience accepted")
	}
}

func TestBackendTokenRejectsTokenWithoutType(t *testing.T) {
	issuer := newTokenIssuer("secret", time.Hour)
	raw := signTestClaims(t, issuer, jwt.MapClaims{
		"sub":      "u",
		"oidc_iss": "https://issuer.example.com",
		"groups":   []string{"g1"},
		"iat":      time.Now().Unix(),
		"exp":      time.Now().Add(time.Hour).Unix(),
	})
	if _, err := issuer.Verify(raw); err == nil {
		t.Fatal("token without type accepted as backend token")
	}
}

func TestBackendTokenRejectsUntypedUpdateToken(t *testing.T) {
	issuer := newTokenIssuer("secret", time.Hour)
	raw := signTestClaims(t, issuer, jwt.MapClaims{
		"sub":      "u",
		"oidc_iss": "https://issuer.example.com",
		"upd":      "update-1",
		"org":      "acme",
		"prj":      "api",
		"stk":      "dev",
		"iat":      time.Now().Unix(),
		"exp":      time.Now().Add(time.Hour).Unix(),
	})
	if _, err := issuer.Verify(raw); err == nil {
		t.Fatal("untyped update token accepted as backend user token")
	}
}

func TestVerifyScopedRejectsTokenWithoutType(t *testing.T) {
	issuer := newTokenIssuer("secret", time.Hour)
	raw := signTestClaims(t, issuer, jwt.MapClaims{
		"sub":      "u",
		"oidc_iss": "https://issuer.example.com",
		"upd":      "update-1",
		"org":      "acme",
		"prj":      "api",
		"stk":      "dev",
		"iat":      time.Now().Unix(),
		"exp":      time.Now().Add(time.Minute).Unix(),
	})
	if _, _, err := issuer.VerifyScoped(raw); err == nil {
		t.Fatal("token without type accepted as scoped token")
	}
}

func TestMiddleware(t *testing.T) {
	issuer := newTokenIssuer("secret", time.Hour)
	tok, _ := issuer.Issue(testIdentity("u", "g1"))

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
	issuer := newTokenIssuer("secret", time.Hour)
	tok, _ := issuer.Issue(testIdentity("u"))
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
		"iss":                "https://issuer.example.com",
		"sub":                "user-sub",
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
