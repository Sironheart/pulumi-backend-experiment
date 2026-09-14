package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"forgejo.siron.casa/sironheart/pulumi-backend-experiment/internal/authz"
	"forgejo.siron.casa/sironheart/pulumi-backend-experiment/internal/store"
)

type createStackRequest struct {
	StackName string          `json:"stackName"`
	State     json.RawMessage `json:"state,omitempty"`
}

func (s *Server) createStack(w http.ResponseWriter, r *http.Request) {
	var req createStackRequest
	if err := decodeBody(r, &req); err != nil {
		writeDecodeError(w, err, "invalid request")
		return
	}
	if !validStorageSegment(req.StackName) {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	org, project := r.PathValue("org"), r.PathValue("project")
	if !s.authorize(w, r, authz.Write, org, project, req.StackName) {
		return
	}
	created, err := s.store.CreateStack(r.Context(), org, project, req.StackName)
	if err != nil {
		if s.storeError(w, err) {
			return
		}
		internalError(w, r, err, "creating stack failed")
		return
	}
	if len(req.State) > 0 {
		if err := s.store.SaveCheckpoint(
			r.Context(),
			org,
			project,
			req.StackName,
			created.Incarnation,
			"",
			0,
			0,
			req.State,
		); err != nil {
			rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 30*time.Second)
			defer cancel()
			if rollbackErr := s.rollbackFailedStackCreation(
				rollbackCtx,
				org,
				project,
				req.StackName,
				created.Incarnation,
				s.identity(r).Principal(),
			); rollbackErr != nil {
				err = errors.Join(err, fmt.Errorf("rolling back stack creation: %w", rollbackErr))
			}
			internalError(w, r, err, "saving initial state failed")
			return
		}
	}
	slog.Info("stack created", "org", org, "project", project, "stack", req.StackName)
	// The CLI (>=3.x) decodes a CreateStackResponse body; an empty 204 fails
	// with "unexpected end of JSON input".
	writeJSON(w, http.StatusOK, map[string]any{"messages": []any{}})
}

func (s *Server) rollbackFailedStackCreation(
	ctx context.Context,
	org, project, stackName, incarnation, owner string,
) error {
	updateID := "delete-" + store.NewUpdateID()
	lock, err := s.store.AcquireLock(
		ctx,
		org,
		project,
		stackName,
		incarnation,
		updateID,
		owner,
		s.cfg.LeaseDuration,
	)
	if err != nil {
		return err
	}
	releaseLock := true
	defer func() {
		if releaseLock {
			_ = s.store.ReleaseLock(ctx, org, project, stackName, updateID, lock.Generation)
		}
	}()
	st, err := s.store.GetStack(ctx, org, project, stackName)
	if err != nil {
		return err
	}
	if st.Incarnation != incarnation {
		return store.ErrConcurrentMutation
	}
	releaseLock = false
	return s.store.DeleteStack(
		ctx,
		org,
		project,
		stackName,
		incarnation,
		updateID,
		lock.Generation,
	)
}

func (s *Server) headProject(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeProject(w, r, authz.Read, r.PathValue("org"), r.PathValue("project")) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) getStack(w http.ResponseWriter, r *http.Request) {
	org, project, stackName := r.PathValue("org"), r.PathValue("project"), r.PathValue("stack")
	st, err := s.store.GetStack(r.Context(), org, project, stackName)
	if err != nil {
		if s.storeError(w, err) {
			return
		}
		internalError(w, r, err, "reading stack failed")
		return
	}
	resp := map[string]any{
		"orgName":     st.Org,
		"projectName": st.Project,
		"stackName":   st.Name,
		"version":     st.Version,
	}
	if lock, err := s.store.GetLock(r.Context(), org, project, stackName); err == nil {
		resp["activeUpdate"] = lock.UpdateID
		resp["currentOperation"] = map[string]any{"kind": "update", "author": lock.Owner, "started": lock.ExpiresAt.Unix()}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) deleteStack(w http.ResponseWriter, r *http.Request) {
	org, project, stackName := r.PathValue("org"), r.PathValue("project"), r.PathValue("stack")
	st, err := s.store.GetStack(r.Context(), org, project, stackName)
	if err != nil {
		s.writeStoreError(w, r, err, "reading stack for deletion failed")
		return
	}
	updateID := "delete-" + store.NewUpdateID()
	owner := s.identity(r).Principal()
	lock, err := s.store.AcquireLock(
		r.Context(),
		org,
		project,
		stackName,
		st.Incarnation,
		updateID,
		owner,
		s.cfg.LeaseDuration,
	)
	if err != nil {
		var held *store.LockHeldError
		if errors.As(err, &held) &&
			held.Lock.Owner == owner &&
			strings.HasPrefix(held.Lock.UpdateID, "delete-") &&
			!held.Lock.Expired(time.Now()) {
			updateID = held.Lock.UpdateID
			lock, err = s.store.RenewLock(
				r.Context(),
				org,
				project,
				stackName,
				updateID,
				held.Lock.Generation,
				s.cfg.LeaseDuration,
			)
			if err != nil {
				s.writeStoreError(w, r, err, "renewing deletion lock failed")
				return
			}
		} else {
			s.writeStoreError(w, r, err, "locking stack for deletion failed")
			return
		}
	}
	releaseLock := true
	defer func() {
		if releaseLock {
			_ = s.store.ReleaseLock(r.Context(), org, project, stackName, updateID, lock.Generation)
		}
	}()
	if r.URL.Query().Get("force") != "true" {
		checkpoint, err := s.store.GetCheckpoint(r.Context(), org, project, stackName)
		switch {
		case err == nil:
			hasResources, parseErr := checkpointHasResources(checkpoint)
			if parseErr != nil {
				internalError(w, r, parseErr, "reading stack checkpoint failed")
				return
			}
			if hasResources {
				writeError(w, http.StatusBadRequest, "Bad Request: Stack still contains resources.")
				return
			}
		case errors.Is(err, store.ErrCheckpointNotFound):
		default:
			internalError(w, r, err, "reading stack checkpoint failed")
			return
		}
	}
	releaseLock = false
	if err := s.store.DeleteStack(
		r.Context(),
		org,
		project,
		stackName,
		st.Incarnation,
		updateID,
		lock.Generation,
	); err != nil {
		if s.storeError(w, err) {
			return
		}
		internalError(w, r, err, "deleting stack failed")
		return
	}
	slog.Info("stack deleted", "org", org, "project", project, "stack", stackName)
	w.WriteHeader(http.StatusNoContent)
}

func checkpointHasResources(raw json.RawMessage) (bool, error) {
	var doc struct {
		Deployment struct {
			Resources []json.RawMessage `json:"resources"`
		} `json:"deployment"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return false, err
	}
	return len(doc.Deployment.Resources) > 0, nil
}

func (s *Server) exportStack(w http.ResponseWriter, r *http.Request) {
	org, project, stackName := r.PathValue("org"), r.PathValue("project"), r.PathValue("stack")
	var (
		raw json.RawMessage
		err error
	)
	if v := r.PathValue("version"); v != "" {
		version, convErr := strconv.Atoi(v)
		if convErr != nil {
			writeError(w, http.StatusBadRequest, "invalid version")
			return
		}
		raw, err = s.store.GetCheckpointVersion(r.Context(), org, project, stackName, version)
	} else {
		raw, err = s.store.GetCheckpoint(r.Context(), org, project, stackName)
	}
	if err != nil {
		// The CLI fetches the current deployment on every operation and treats
		// a 404 as fatal; a fresh stack must export as an empty deployment.
		if errors.Is(err, store.ErrCheckpointNotFound) && r.PathValue("version") == "" {
			raw = json.RawMessage(`{"version":3,"deployment":{}}`)
		} else {
			if s.storeError(w, err) {
				return
			}
			internalError(w, r, err, "reading checkpoint failed")
			return
		}
	}
	if !json.Valid(raw) {
		internalError(w, r, errors.New("stored checkpoint is not valid JSON"), "reading checkpoint failed")
		return
	}
	writeJSON(w, http.StatusOK, json.RawMessage(raw))
}

func (s *Server) importStack(w http.ResponseWriter, r *http.Request) {
	org, project, stackName := r.PathValue("org"), r.PathValue("project"), r.PathValue("stack")
	var deployment json.RawMessage
	if err := decodeBody(r, &deployment); err != nil {
		writeDecodeError(w, err, "invalid deployment")
		return
	}
	if len(deployment) == 0 {
		writeError(w, http.StatusBadRequest, "invalid deployment")
		return
	}
	owner := s.identity(r).Principal()
	st, err := s.store.GetStack(r.Context(), org, project, stackName)
	if err != nil {
		s.writeStoreError(w, r, err, "reading stack failed")
		return
	}
	updateID := store.NewUpdateID()
	lock, err := s.store.AcquireLock(
		r.Context(),
		org,
		project,
		stackName,
		st.Incarnation,
		updateID,
		owner,
		s.cfg.LeaseDuration,
	)
	if err != nil {
		if s.storeError(w, err) {
			return
		}
		internalError(w, r, err, "acquiring lock failed")
		return
	}
	defer func() {
		_ = s.store.ReleaseLock(r.Context(), org, project, stackName, updateID, lock.Generation)
	}()

	u, err := s.store.CreateUpdate(r.Context(), org, project, stackName, "import", updateID)
	if err != nil {
		if s.storeError(w, err) {
			return
		}
		internalError(w, r, err, "creating import update failed")
		return
	}
	if err := s.store.StartUpdate(r.Context(), org, project, stackName, updateID); err != nil {
		s.writeStoreError(w, r, err, "starting import update failed")
		return
	}
	if err := s.store.SaveCheckpoint(
		r.Context(),
		org,
		project,
		stackName,
		u.Incarnation,
		updateID,
		lock.Generation,
		u.Version,
		deployment,
	); err != nil {
		internalError(w, r, err, "saving checkpoint failed")
		return
	}
	if err := s.store.CompleteUpdate(r.Context(), org, project, stackName, updateID, "succeeded", "import", nil); err != nil {
		internalError(w, r, err, "completing import failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"updateId": updateID})
}
