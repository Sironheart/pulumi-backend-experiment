package api

import (
	"net/http"
	"time"

	"forgejo.siron.casa/sironheart/pulumi-backend-experiment/internal/authn"
)

type tokenExchangeRequest struct {
	Token string `json:"token"`
}

type tokenExchangeResponse struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expiresAt"`
}

// tokenExchange trades a valid OIDC ID token for a long-lived backend token.
func (s *Server) tokenExchange(w http.ResponseWriter, r *http.Request) {
	var req tokenExchangeRequest
	if err := decodeBody(r, &req); err != nil {
		writeDecodeError(w, err, "invalid request")
		return
	}
	if req.Token == "" {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	var id authn.Identity
	if s.cfg.NoAuth {
		id = authn.IdentityFromToken(req.Token)
	} else {
		var err error
		id, err = s.oidc.Validate(r.Context(), req.Token)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid identity token")
			return
		}
	}
	tok, err := s.issuer.Issue(id)
	if err != nil {
		internalError(w, r, err, "token issuance failed")
		return
	}
	writeJSON(w, http.StatusOK, tokenExchangeResponse{
		Token:     tok,
		ExpiresAt: time.Now().Add(s.cfg.TokenTTL).Unix(),
	})
}

// whoami implements GET /api/user. The CLI requires githubLogin to be set.
func (s *Server) whoami(w http.ResponseWriter, r *http.Request) {
	id := s.identity(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"id":            id.Username,
		"githubLogin":   id.Username,
		"name":          id.Username,
		"email":         "",
		"avatarUrl":     "",
		"organizations": []any{},
		"identities":    []string{},
	})
}

// defaultOrg returns 404: the CLI then falls back to its legacy behavior
// (default org = username).
func (s *Server) defaultOrg(w http.ResponseWriter, _ *http.Request) {
	writeError(w, http.StatusNotFound, "default organization not supported")
}

func (s *Server) capabilities(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"capabilities": []any{}})
}

// listUserStacks implements GET /api/user/stacks over the single bucket.
func (s *Server) listUserStacks(w http.ResponseWriter, r *http.Request) {
	s.listStacks(w, r, r.URL.Query().Get("organization"))
}

func (s *Server) listOrgStacks(w http.ResponseWriter, r *http.Request) {
	s.listStacks(w, r, r.PathValue("org"))
}

func (s *Server) listStacks(w http.ResponseWriter, r *http.Request, org string) {
	project := r.URL.Query().Get("project")
	stacks, err := s.store.ListStacks(r.Context(), org)
	if err != nil {
		internalError(w, r, err, "listing stacks failed")
		return
	}
	type summary struct {
		OrgName     string `json:"orgName"`
		ProjectName string `json:"projectName"`
		StackName   string `json:"stackName"`
	}
	out := []summary{}
	for _, stack := range stacks {
		if project != "" && stack.Project != project {
			continue
		}
		out = append(out, summary{OrgName: stack.Org, ProjectName: stack.Project, StackName: stack.Name})
	}
	writeJSON(w, http.StatusOK, map[string]any{"stacks": out})
}
