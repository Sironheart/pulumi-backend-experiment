package authn

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"

	keycloak "github.com/stillya/testcontainers-keycloak"
)

const keycloakImage = "keycloak/keycloak:26.0"

// Integration test: validate tokens issued by a real OIDC provider.
func TestValidateAgainstKeycloak(t *testing.T) {
	ctx := context.Background()
	container, err := keycloak.Run(ctx,
		keycloakImage,
		keycloak.WithRealmImportFile("testdata/realm.json"),
	)
	if err != nil {
		t.Fatalf("start keycloak: %v", err)
	}
	t.Cleanup(func() { _ = container.Terminate(ctx) })

	authServerURL, err := container.GetAuthServerURL(ctx)
	if err != nil {
		t.Fatal(err)
	}
	issuer := authServerURL + "/realms/pulumi-backend"

	v, err := NewOIDCValidator(ctx, issuer, "pulumi-backend")
	if err != nil {
		t.Fatalf("NewOIDCValidator: %v", err)
	}

	id, err := v.Validate(ctx, keycloakIDToken(t, issuer))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if id.Username != "alice" {
		t.Errorf("username = %q, want alice", id.Username)
	}
}

// keycloakIDToken fetches an ID token via the direct access grant (ROPC),
// which only exists for machine-to-machine test setups like this one.
func keycloakIDToken(t *testing.T, issuer string) string {
	t.Helper()
	resp, err := http.PostForm(issuer+"/protocol/openid-connect/token", url.Values{
		"grant_type":    {"password"},
		"client_id":     {"pulumi-backend"},
		"client_secret": {"pulumi-backend-secret"},
		"username":      {"alice"},
		"password":      {"alice-secret"},
		"scope":         {"openid"},
	})
	if err != nil {
		t.Fatalf("token request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("token request: status %d: %s", resp.StatusCode, body)
	}
	var body struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if body.IDToken == "" {
		t.Fatal("token response has no id_token")
	}
	return body.IDToken
}
