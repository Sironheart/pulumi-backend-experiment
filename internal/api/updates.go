package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"forgejo.siron.casa/sironheart/pulumi-backend-experiment/internal/authn"
	"forgejo.siron.casa/sironheart/pulumi-backend-experiment/internal/store"
)

func stackRef(r *http.Request) (org, project, stack, kind, updateID string) {
	return r.PathValue("org"), r.PathValue("project"), r.PathValue("stack"), r.PathValue("kind"), r.PathValue("updateID")
}

// createUpdate implements POST /api/stacks/{org}/{project}/{stack}/{kind}.
// Non-preview kinds take the stack lock; previews run lock-free.
func (s *Server) createUpdate(w http.ResponseWriter, r *http.Request) {
	org, project, stackName, kind, _ := stackRef(r)
	if !validUpdateKind(kind) {
		writeError(w, http.StatusNotFound, "unknown update kind")
		return
	}
	st, err := s.store.GetStack(r.Context(), org, project, stackName)
	if err != nil {
		if s.storeError(w, err) {
			return
		}
		internalError(w, r, err, "reading stack failed")
		return
	}

	updateID := store.NewUpdateID()
	var lock *store.Lock
	if kind != "preview" {
		lock, err = s.store.AcquireLock(
			r.Context(),
			org,
			project,
			stackName,
			st.Incarnation,
			updateID,
			s.identity(r).Username,
			s.cfg.LeaseDuration,
		)
		if err != nil {
			var held *store.LockHeldError
			if errors.As(err, &held) {
				if held.Lock.Owner == s.identity(r).Username {
					existing, getErr := s.store.GetUpdate(
						r.Context(),
						org,
						project,
						stackName,
						held.Lock.UpdateID,
					)
					if getErr == nil && existing.Kind == kind && existing.Status == "not-started" {
						if _, renewErr := s.store.RenewLock(
							r.Context(),
							org,
							project,
							stackName,
							existing.ID,
							held.Lock.Generation,
							s.cfg.LeaseDuration,
						); renewErr != nil {
							s.writeStoreError(w, r, renewErr, "renewing pending update lock failed")
							return
						}
						committed, commitErr := s.store.CreateUpdate(
							r.Context(),
							org,
							project,
							stackName,
							kind,
							existing.ID,
						)
						if commitErr != nil {
							s.writeStoreError(w, r, commitErr, "committing pending update failed")
							return
						}
						writeJSON(w, http.StatusOK, map[string]any{"updateID": committed.ID})
						return
					}
				}
				slog.Warn("stack locked", "org", org, "project", project, "stack", stackName, "holder", held.Lock.UpdateID, "owner", held.Lock.Owner)
			}
			if s.storeError(w, err) {
				return
			}
			internalError(w, r, err, "acquiring lock failed")
			return
		}
	}
	if _, err := s.store.CreateUpdate(r.Context(), org, project, stackName, kind, updateID); err != nil {
		if lock != nil {
			_ = s.store.ReleaseLock(r.Context(), org, project, stackName, updateID, lock.Generation)
		}
		if s.storeError(w, err) {
			return
		}
		internalError(w, r, err, "creating update failed")
		return
	}
	slog.Info("update created", "org", org, "project", project, "stack", stackName, "kind", kind, "update", updateID)
	writeJSON(w, http.StatusOK, map[string]any{"updateID": updateID})
}

// startUpdate implements POST .../{kind}/{updateID}; returns the stack version
// and the update-scoped lease token. JournalVersion 0 disables journaling.
func (s *Server) startUpdate(w http.ResponseWriter, r *http.Request) {
	org, project, stackName, kind, updateID := stackRef(r)
	if !validUpdateKind(kind) {
		writeError(w, http.StatusNotFound, "unknown update kind")
		return
	}
	u, err := s.store.GetUpdate(r.Context(), org, project, stackName, updateID)
	if err != nil {
		if s.storeError(w, err) {
			return
		}
		internalError(w, r, err, "reading update failed")
		return
	}
	if u.Status != "not-started" && u.Status != "in-progress" {
		writeError(w, http.StatusConflict, store.ErrInvalidUpdateState.Error())
		return
	}
	var generation uint64
	if u.Kind != "preview" {
		lock, ok := s.requireLiveLock(w, r, updateID, 0)
		if !ok {
			return
		}
		lock, err = s.store.RenewLock(
			r.Context(),
			org,
			project,
			stackName,
			updateID,
			lock.Generation,
			s.cfg.LeaseDuration,
		)
		if err != nil {
			s.writeStoreError(w, r, err, "renewing update lock failed")
			return
		}
		generation = lock.Generation
	}
	if u.Status == "not-started" {
		if err := s.store.StartUpdate(r.Context(), org, project, stackName, updateID); err != nil {
			if s.storeError(w, err) {
				return
			}
			internalError(w, r, err, "starting update failed")
			return
		}
	}
	token, exp, err := s.issuer.IssueUpdate(s.identity(r), authn.UpdateClaims{
		UpdateID: updateID, Org: org, Project: project, Stack: stackName, Kind: kind, Generation: generation,
	}, s.cfg.LeaseDuration)
	if err != nil {
		internalError(w, r, err, "token issuance failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":         u.Version,
		"token":           token,
		"tokenExpiration": exp,
		"journalVersion":  0,
	})
}

func (s *Server) getUpdateStatus(w http.ResponseWriter, r *http.Request) {
	org, project, stackName, kind, updateID := stackRef(r)
	if !validUpdateKind(kind) {
		writeError(w, http.StatusNotFound, "unknown update kind")
		return
	}
	u, err := s.store.GetUpdate(r.Context(), org, project, stackName, updateID)
	if err != nil {
		if s.storeError(w, err) {
			return
		}
		internalError(w, r, err, "reading update failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": u.Status,
		"events": []any{},
	})
}

func (s *Server) requireLiveLock(
	w http.ResponseWriter,
	r *http.Request,
	updateID string,
	generation uint64,
) (*store.Lock, bool) {
	org, project, stackName, _, _ := stackRef(r)
	lock, err := s.store.GetLock(r.Context(), org, project, stackName)
	if err != nil {
		if errors.Is(err, store.ErrNoLock) {
			writeError(w, http.StatusConflict, "update no longer owns stack lock")
			return nil, false
		}
		internalError(w, r, err, "reading update lock failed")
		return nil, false
	}
	if lock.UpdateID != updateID ||
		(generation != 0 && lock.Generation != generation) ||
		lock.Expired(time.Now()) {
		writeError(w, http.StatusConflict, "update no longer owns stack lock")
		return nil, false
	}
	return lock, true
}

func (s *Server) releaseUpdateLock(
	ctx context.Context,
	org, project, stackName, updateID string,
	generation uint64,
) error {
	err := s.store.ReleaseLock(ctx, org, project, stackName, updateID, generation)
	var held *store.LockHeldError
	if errors.As(err, &held) {
		return nil
	}
	return err
}

func (s *Server) patchCheckpoint(w http.ResponseWriter, r *http.Request) {
	if !s.requireUpdateScope(w, r) {
		return
	}
	org, project, stackName, _, updateID := stackRef(r)
	var req struct {
		Version    int             `json:"version"`
		Features   []string        `json:"features,omitempty"`
		Deployment json.RawMessage `json:"deployment,omitempty"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeDecodeError(w, err, "invalid checkpoint")
		return
	}
	deployment, _ := json.Marshal(map[string]any{
		"version":    req.Version,
		"features":   req.Features,
		"deployment": req.Deployment,
	})
	s.saveCheckpointForUpdate(w, r, org, project, stackName, updateID, deployment)
}

func (s *Server) patchCheckpointVerbatim(w http.ResponseWriter, r *http.Request) {
	if !s.requireUpdateScope(w, r) {
		return
	}
	org, project, stackName, _, updateID := stackRef(r)
	var req struct {
		Version           int             `json:"version"`
		UntypedDeployment json.RawMessage `json:"untypedDeployment"`
		SequenceNumber    int             `json:"sequenceNumber"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeDecodeError(w, err, "invalid checkpoint")
		return
	}
	if len(req.UntypedDeployment) == 0 {
		writeError(w, http.StatusBadRequest, "invalid checkpoint")
		return
	}
	s.saveCheckpointForUpdate(w, r, org, project, stackName, updateID, req.UntypedDeployment)
}

func (s *Server) saveCheckpointForUpdate(w http.ResponseWriter, r *http.Request, org, project, stackName, updateID string, deployment json.RawMessage) {
	u, err := s.store.GetUpdate(r.Context(), org, project, stackName, updateID)
	if err != nil {
		if s.storeError(w, err) {
			return
		}
		internalError(w, r, err, "reading update failed")
		return
	}
	if u.Kind == "preview" || u.Status != "in-progress" {
		writeError(w, http.StatusConflict, store.ErrInvalidUpdateState.Error())
		return
	}
	var generation uint64
	if uc, ok := authn.UpdateClaimsFrom(r.Context()); ok {
		generation = uc.Generation
	}
	lock, ok := s.requireLiveLock(w, r, updateID, generation)
	if !ok {
		return
	}
	generation = lock.Generation
	renewed, err := s.store.RenewLock(
		r.Context(),
		org,
		project,
		stackName,
		updateID,
		generation,
		s.cfg.LeaseDuration,
	)
	if err != nil {
		s.writeStoreError(w, r, err, "renewing update lock failed")
		return
	}
	generation = renewed.Generation
	if err := s.store.SaveCheckpoint(
		r.Context(),
		org,
		project,
		stackName,
		u.Incarnation,
		updateID,
		generation,
		u.Version,
		deployment,
	); err != nil {
		s.writeStoreError(w, r, err, "saving checkpoint failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) completeUpdate(w http.ResponseWriter, r *http.Request) {
	if !s.requireUpdateScope(w, r) {
		return
	}
	org, project, stackName, _, updateID := stackRef(r)
	var req struct {
		Status string `json:"status"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeDecodeError(w, err, "invalid request")
		return
	}
	if req.Status != "succeeded" && req.Status != "failed" {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	u, err := s.store.GetUpdate(r.Context(), org, project, stackName, updateID)
	if err != nil {
		s.writeStoreError(w, r, err, "reading update failed")
		return
	}
	var generation uint64
	if uc, ok := authn.UpdateClaimsFrom(r.Context()); ok {
		generation = uc.Generation
	}
	if u.Status == req.Status {
		if u.Kind != "preview" {
			if generation == 0 {
				lock, lockErr := s.store.GetLock(r.Context(), org, project, stackName)
				if lockErr == nil && lock.UpdateID == updateID {
					generation = lock.Generation
				} else if lockErr != nil && !errors.Is(lockErr, store.ErrNoLock) {
					s.writeStoreError(w, r, lockErr, "reading update lock failed")
					return
				}
			}
			if generation != 0 {
				if err := s.releaseUpdateLock(r.Context(), org, project, stackName, updateID, generation); err != nil {
					s.writeStoreError(w, r, err, "releasing update lock failed")
					return
				}
			}
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if u.Status != "in-progress" {
		writeError(w, http.StatusConflict, store.ErrInvalidUpdateState.Error())
		return
	}
	var liveLock *store.Lock
	if u.Kind != "preview" {
		var ok bool
		liveLock, ok = s.requireLiveLock(w, r, updateID, generation)
		if !ok {
			return
		}
		generation = liveLock.Generation
	}
	if err := s.store.CompleteUpdate(r.Context(), org, project, stackName, updateID, req.Status, "", nil); err != nil {
		if s.storeError(w, err) {
			return
		}
		internalError(w, r, err, "completing update failed")
		return
	}
	if u.Kind != "preview" {
		if err := s.releaseUpdateLock(r.Context(), org, project, stackName, updateID, generation); err != nil {
			s.writeStoreError(w, r, err, "releasing update lock failed")
			return
		}
	}
	slog.Info("update completed", "org", org, "project", project, "stack", stackName, "update", updateID, "status", req.Status)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) renewLease(w http.ResponseWriter, r *http.Request) {
	if !s.requireUpdateScope(w, r) {
		return
	}
	org, project, stackName, _, updateID := stackRef(r)
	var req struct {
		Duration int `json:"duration"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeDecodeError(w, err, "invalid request")
		return
	}
	var generation uint64
	if uc, ok := authn.UpdateClaimsFrom(r.Context()); ok {
		generation = uc.Generation
	}
	d := time.Duration(req.Duration) * time.Second
	if d <= 0 || d > 300*time.Second {
		d = 300 * time.Second
	}
	u, err := s.store.GetUpdate(r.Context(), org, project, stackName, updateID)
	if err != nil {
		s.writeStoreError(w, r, err, "reading update failed")
		return
	}
	if u.Kind != "preview" {
		lock, ok := s.requireLiveLock(w, r, updateID, generation)
		if !ok {
			return
		}
		generation = lock.Generation
		renewed, err := s.store.RenewLock(
			r.Context(),
			org,
			project,
			stackName,
			updateID,
			generation,
			d,
		)
		if err != nil {
			if s.storeError(w, err) {
				return
			}
			internalError(w, r, err, "renewing lease failed")
			return
		}
		generation = renewed.Generation
	}
	token, exp, err := s.issuer.IssueUpdate(s.identity(r), authn.UpdateClaims{
		UpdateID: updateID,
		Org:      org, Project: project, Stack: stackName,
		Kind: r.PathValue("kind"), Generation: generation,
	}, d)
	if err != nil {
		internalError(w, r, err, "token issuance failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": token, "tokenExpiration": exp})
}

// cancelUpdate marks the update cancelled and releases the stack lock.
// Called with the user token (pulumi cancel), not the update token.
func (s *Server) cancelUpdate(w http.ResponseWriter, r *http.Request) {
	org, project, stackName, kind, updateID := stackRef(r)
	if !validUpdateKind(kind) {
		writeError(w, http.StatusNotFound, "unknown update kind")
		return
	}
	u, err := s.store.GetUpdate(r.Context(), org, project, stackName, updateID)
	if err != nil {
		s.writeStoreError(w, r, err, "reading update failed")
		return
	}
	updateKind := u.Kind
	if u.Status == "cancelled" {
		if updateKind != "preview" {
			lock, lockErr := s.store.GetLock(r.Context(), org, project, stackName)
			if lockErr != nil && !errors.Is(lockErr, store.ErrNoLock) {
				s.writeStoreError(w, r, lockErr, "reading update lock failed")
				return
			}
			if lock != nil && lock.UpdateID == updateID {
				if err := s.releaseUpdateLock(r.Context(), org, project, stackName, updateID, lock.Generation); err != nil {
					s.writeStoreError(w, r, err, "releasing update lock failed")
					return
				}
			}
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if u.Status != "not-started" && u.Status != "in-progress" {
		writeError(w, http.StatusConflict, store.ErrInvalidUpdateState.Error())
		return
	}
	var lock *store.Lock
	if updateKind != "preview" {
		lock, err = s.store.GetLock(r.Context(), org, project, stackName)
		if err != nil && !errors.Is(err, store.ErrNoLock) {
			s.writeStoreError(w, r, err, "reading update lock failed")
			return
		}
		if lock != nil && lock.UpdateID != updateID {
			lock = nil
		}
	}
	if err := s.store.CompleteUpdate(r.Context(), org, project, stackName, updateID, "cancelled", "cancelled by user", nil); err != nil {
		if s.storeError(w, err) {
			return
		}
		internalError(w, r, err, "cancelling update failed")
		return
	}
	if lock != nil {
		if err := s.releaseUpdateLock(r.Context(), org, project, stackName, updateID, lock.Generation); err != nil {
			s.writeStoreError(w, r, err, "releasing update lock failed")
			return
		}
	}
	slog.Info("update cancelled", "org", org, "project", project, "stack", stackName, "update", updateID)
	w.WriteHeader(http.StatusNoContent)
}

// discardEvents accepts engine events and drops them; log retrieval is out of
// scope for the MVP, but the CLI expects the endpoint to exist.
func (s *Server) discardEvents(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) getStackUpdates(w http.ResponseWriter, r *http.Request) {
	org, project, stackName := r.PathValue("org"), r.PathValue("project"), r.PathValue("stack")
	updates, err := s.store.ListUpdates(r.Context(), org, project, stackName)
	if err != nil {
		internalError(w, r, err, "listing updates failed")
		return
	}
	updates = historicalUpdates(updates)
	start, end, ok := pageWindow(w, r, len(updates))
	if !ok {
		return
	}
	infos := []map[string]any{}
	for _, u := range updates[start:end] {
		infos = append(infos, updateInfo(u))
	}
	writeJSON(w, http.StatusOK, map[string]any{"updates": infos})
}

// pageWindow parses ?page/?pageSize and clamps them to a slice window over
// total items. ok is false after a 400 was written for invalid parameters.
func pageWindow(w http.ResponseWriter, r *http.Request, total int) (start, end int, ok bool) {
	page, pageSize := 1, total
	if v := r.URL.Query().Get("page"); v != "" {
		p, err := strconv.Atoi(v)
		if err != nil || p < 1 {
			writeError(w, http.StatusBadRequest, "invalid page")
			return 0, 0, false
		}
		page = p
	}
	if v := r.URL.Query().Get("pageSize"); v != "" {
		ps, err := strconv.Atoi(v)
		if err != nil || ps < 0 || ps > 1000 {
			writeError(w, http.StatusBadRequest, "invalid pageSize")
			return 0, 0, false
		}
		pageSize = ps
		if pageSize == 0 {
			pageSize = total
		}
	}
	if total == 0 {
		return 0, 0, true
	}
	start = total
	if page-1 <= total/pageSize {
		start = (page - 1) * pageSize
	}
	if start > total {
		start = total
	}
	end = start + pageSize
	if end > total {
		end = total
	}
	return start, end, true
}

func (s *Server) getLatestUpdate(w http.ResponseWriter, r *http.Request) {
	updates, err := s.store.ListUpdates(r.Context(), r.PathValue("org"), r.PathValue("project"), r.PathValue("stack"))
	if err != nil {
		internalError(w, r, err, "listing updates failed")
		return
	}
	updates = historicalUpdates(updates)
	if len(updates) == 0 {
		writeError(w, http.StatusNotFound, "no updates")
		return
	}
	writeJSON(w, http.StatusOK, updateInfo(updates[0]))
}

func (s *Server) getUpdateByVersion(w http.ResponseWriter, r *http.Request) {
	version, err := strconv.Atoi(r.PathValue("version"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid version")
		return
	}
	updates, err := s.store.ListUpdates(r.Context(), r.PathValue("org"), r.PathValue("project"), r.PathValue("stack"))
	if err != nil {
		internalError(w, r, err, "listing updates failed")
		return
	}
	updates = historicalUpdates(updates)
	for _, u := range updates {
		if u.Version == version {
			writeJSON(w, http.StatusOK, updateInfo(u))
			return
		}
	}
	writeError(w, http.StatusNotFound, "update not found")
}

func historicalUpdates(updates []store.Update) []store.Update {
	out := updates[:0]
	for _, update := range updates {
		if update.Kind != "preview" {
			out = append(out, update)
		}
	}
	return out
}

func updateInfo(u store.Update) map[string]any {
	changes := map[string]int{}
	for k, v := range u.ResourceChanges {
		changes[k] = v
	}
	return map[string]any{
		"kind":            u.Kind,
		"startTime":       u.StartTime,
		"endTime":         u.EndTime,
		"message":         u.Message,
		"environment":     map[string]string{},
		"config":          map[string]any{},
		"result":          u.Status,
		"version":         u.Version,
		"resourceChanges": changes,
	}
}
