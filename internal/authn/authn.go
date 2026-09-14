package authn

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
)

type Identity struct {
	Issuer   string
	Subject  string
	Username string
	Groups   []string
}

// Principal is the stable identity used for ownership and audit fields. OIDC
// only guarantees uniqueness for the issuer-and-subject pair.
func (id Identity) Principal() string {
	if id.Issuer == "" {
		return id.Subject
	}
	return id.Issuer + "|" + id.Subject
}

const (
	backendTokenType     = "backend"
	updateTokenType      = "update"
	backendTokenAudience = "pulumi-backend"        // #nosec G101 -- public JWT audience, not a credential.
	updateTokenAudience  = "pulumi-backend-update" // #nosec G101 -- public JWT audience, not a credential.
	minimumTokenTTL      = 2 * time.Second
)

// OIDCValidator validates ID tokens from any OIDC provider via discovery + JWKS.
type OIDCValidator struct {
	verifier *oidc.IDTokenVerifier
}

func NewOIDCValidator(ctx context.Context, issuer, clientID string) (*OIDCValidator, error) {
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc provider: %w", err)
	}
	return &OIDCValidator{verifier: provider.Verifier(&oidc.Config{ClientID: clientID})}, nil
}

func (v *OIDCValidator) Validate(ctx context.Context, raw string) (Identity, error) {
	tok, err := v.verifier.Verify(ctx, raw)
	if err != nil {
		return Identity{}, err
	}
	var claims map[string]any
	if err := tok.Claims(&claims); err != nil {
		return Identity{}, fmt.Errorf("claims: %w", err)
	}
	return identityFromClaims(claims, tok.Issuer)
}

// IdentityFromToken extracts an identity without verifying signatures.
// Opaque noAuth credentials use a digest so their secret text never persists.
func IdentityFromToken(raw string) Identity {
	if raw == "" {
		return localIdentity("local")
	}
	tok, _, err := jwt.NewParser().ParseUnverified(raw, jwt.MapClaims{})
	if err == nil {
		if claims, ok := tok.Claims.(jwt.MapClaims); ok {
			if id, err := identityFromClaims(claims, ""); err == nil {
				return id
			}
		}
	}
	if strings.Count(raw, ".") == 2 {
		return localIdentity("local")
	}
	sum := sha256.Sum256([]byte(raw))
	return localIdentity(fmt.Sprintf("local-%x", sum[:8]))
}

func localIdentity(name string) Identity {
	return Identity{Issuer: "local", Subject: name, Username: name}
}

func identityFromClaims(claims map[string]any, issuer string) (Identity, error) {
	subject, _ := claims["sub"].(string)
	if subject == "" {
		return Identity{}, errors.New("no subject claim")
	}
	if issuer == "" {
		issuer, _ = claims["oidc_iss"].(string)
	}
	if issuer == "" {
		issuer, _ = claims["iss"].(string)
	}
	if issuer == "" {
		return Identity{}, errors.New("no issuer claim")
	}
	id := Identity{Issuer: issuer, Subject: subject, Username: subject}
	for _, key := range []string{"preferred_username", "name", "email"} {
		if s, ok := claims[key].(string); ok && s != "" {
			id.Username = s
			break
		}
	}
	switch groups := claims["groups"].(type) {
	case []any:
		for _, g := range groups {
			if s, ok := g.(string); ok {
				id.Groups = append(id.Groups, s)
			}
		}
	case []string:
		id.Groups = append(id.Groups, groups...)
	}
	return id, nil
}

// TokenIssuer issues and verifies backend tokens using an HS256 keyring.
type TokenIssuer struct {
	Keys        map[string][]byte
	ActiveKeyID string
	TTL         time.Duration
}

func validateIdentity(id Identity) error {
	if id.Issuer == "" {
		return errors.New("identity issuer is required")
	}
	if id.Subject == "" {
		return errors.New("identity subject is required")
	}
	return nil
}

func (i *TokenIssuer) sign(claims jwt.MapClaims) (string, error) {
	key, ok := i.Keys[i.ActiveKeyID]
	if !ok || len(key) == 0 {
		return "", fmt.Errorf("active signing key %q is not configured", i.ActiveKeyID)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = i.ActiveKeyID
	return token.SignedString(key)
}

func (i *TokenIssuer) parse(raw string) (*jwt.Token, error) {
	return jwt.Parse(raw, func(token *jwt.Token) (any, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, errors.New("token has no key ID")
		}
		key, ok := i.Keys[kid]
		if !ok || len(key) == 0 {
			return nil, fmt.Errorf("unknown token key ID %q", kid)
		}
		return key, nil
	},
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	)
}

func (i *TokenIssuer) Issue(id Identity) (string, error) {
	if i.TTL < minimumTokenTTL {
		return "", fmt.Errorf("token TTL must be at least %s", minimumTokenTTL)
	}
	if err := validateIdentity(id); err != nil {
		return "", err
	}
	now := time.Now()
	return i.sign(jwt.MapClaims{
		"sub":      id.Subject,
		"oidc_iss": id.Issuer,
		"name":     id.Username,
		"groups":   id.Groups,
		"iat":      now.Unix(),
		"exp":      now.Add(i.TTL).Unix(),
		"typ":      backendTokenType,
		"aud":      backendTokenAudience,
	})
}

func (i *TokenIssuer) Verify(raw string) (Identity, error) {
	tok, err := i.parse(raw)
	if err != nil {
		return Identity{}, err
	}
	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return Identity{}, errors.New("unexpected claims type")
	}
	tokenType, ok := claims["typ"].(string)
	if !ok || tokenType != backendTokenType {
		return Identity{}, errors.New("not a backend user token")
	}
	if err := requireAudience(claims, backendTokenAudience); err != nil {
		return Identity{}, err
	}
	return identityFromClaims(claims, "")
}

// UpdateClaims scopes a backend token to a single in-flight update.
type UpdateClaims struct {
	UpdateID   string
	Org        string
	Project    string
	Stack      string
	Kind       string
	Generation uint64
}

// IssueUpdate mints a short-lived token authorizing operations on one update.
func (i *TokenIssuer) IssueUpdate(id Identity, uc UpdateClaims, ttl time.Duration) (string, int64, error) {
	if ttl < minimumTokenTTL {
		return "", 0, fmt.Errorf("token TTL must be at least %s", minimumTokenTTL)
	}
	if err := validateIdentity(id); err != nil {
		return "", 0, err
	}
	now := time.Now()
	exp := now.Add(ttl)
	tok, err := i.sign(jwt.MapClaims{
		"sub":      id.Subject,
		"oidc_iss": id.Issuer,
		"name":     id.Username,
		"groups":   id.Groups,
		"iat":      now.Unix(),
		"exp":      exp.Unix(),
		"upd":      uc.UpdateID,
		"org":      uc.Org,
		"prj":      uc.Project,
		"stk":      uc.Stack,
		"kind":     uc.Kind,
		"fence":    strconv.FormatUint(uc.Generation, 10),
		"typ":      updateTokenType,
		"aud":      updateTokenAudience,
	})
	return tok, exp.Unix(), err
}

// VerifyScoped verifies a token and extracts update claims when present.
func (i *TokenIssuer) VerifyScoped(raw string) (Identity, *UpdateClaims, error) {
	tok, err := i.parse(raw)
	if err != nil {
		return Identity{}, nil, err
	}
	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return Identity{}, nil, errors.New("unexpected claims type")
	}
	id, err := identityFromClaims(claims, "")
	if err != nil {
		return Identity{}, nil, err
	}
	tokenType, _ := claims["typ"].(string)
	switch tokenType {
	case backendTokenType:
		if err := requireAudience(claims, backendTokenAudience); err != nil {
			return Identity{}, nil, err
		}
		return id, nil, nil
	case updateTokenType:
		return updateTokenScope(id, claims)
	default:
		return Identity{}, nil, errors.New("unknown token type")
	}
}

func updateTokenScope(id Identity, claims jwt.MapClaims) (Identity, *UpdateClaims, error) {
	if err := requireAudience(claims, updateTokenAudience); err != nil {
		return Identity{}, nil, err
	}
	upd, _ := claims["upd"].(string)
	if upd == "" {
		return Identity{}, nil, errors.New("update token has no update ID")
	}
	org, orgOK := claims["org"].(string)
	project, projectOK := claims["prj"].(string)
	stack, stackOK := claims["stk"].(string)
	kind, kindOK := claims["kind"].(string)
	fenceValue, fenceOK := claims["fence"].(string)
	generation, fenceErr := strconv.ParseUint(fenceValue, 10, 64)
	if !orgOK || !projectOK || !stackOK || !kindOK || !fenceOK || fenceErr != nil {
		return Identity{}, nil, errors.New("invalid update token scope")
	}
	return id, &UpdateClaims{
		UpdateID:   upd,
		Org:        org,
		Project:    project,
		Stack:      stack,
		Kind:       kind,
		Generation: generation,
	}, nil
}

func requireAudience(claims jwt.MapClaims, want string) error {
	audiences, err := claims.GetAudience()
	if err != nil {
		return fmt.Errorf("read token audience: %w", err)
	}
	if len(audiences) != 1 || audiences[0] != want {
		return errors.New("invalid token audience")
	}
	return nil
}

type updateContextKey struct{}

func WithUpdateClaims(ctx context.Context, uc *UpdateClaims) context.Context {
	return context.WithValue(ctx, updateContextKey{}, uc)
}

func UpdateClaimsFrom(ctx context.Context) (*UpdateClaims, bool) {
	uc, ok := ctx.Value(updateContextKey{}).(*UpdateClaims)
	return uc, ok && uc != nil
}

type contextKey struct{}

func ContextWithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, contextKey{}, id)
}

func IdentityFrom(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(contextKey{}).(Identity)
	return id, ok
}

// Middleware requires a valid backend user token in the Authorization header.
func Middleware(issuer *TokenIssuer) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := r.Header.Get("Authorization")
			for _, scheme := range []string{"update-token ", "token ", "Bearer "} {
				raw = strings.TrimSpace(strings.TrimPrefix(raw, scheme))
			}
			if raw == "" {
				http.Error(w, `{"code":401,"message":"missing token"}`, http.StatusUnauthorized)
				return
			}
			id, err := issuer.Verify(raw)
			if err != nil {
				http.Error(w, `{"code":401,"message":"invalid token"}`, http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), contextKey{}, id)))
		})
	}
}
