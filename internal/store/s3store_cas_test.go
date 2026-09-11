package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func newHTTPTestStore(t *testing.T, handler http.Handler) *S3Store {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	cfg, err := awsconfig.LoadDefaultConfig(t.Context(),
		awsconfig.WithRegion("us-east-1"),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "")),
	)
	if err != nil {
		t.Fatal(err)
	}
	client := s3.NewFromConfig(cfg, func(options *s3.Options) {
		options.BaseEndpoint = aws.String(server.URL)
		options.UsePathStyle = true
	})
	return NewS3Store(client, "state")
}

func writeStack(t *testing.T, w http.ResponseWriter, stack Stack, etag string) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("ETag", etag)
	if err := json.NewEncoder(w).Encode(stack); err != nil {
		t.Fatal(err)
	}
}

func writeLock(t *testing.T, w http.ResponseWriter, lock Lock, etag string) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("ETag", etag)
	if err := json.NewEncoder(w).Encode(lock); err != nil {
		t.Fatal(err)
	}
}

func TestCreateStackRetriesConditionalConflict(t *testing.T) {
	putCalls := 0
	store := newHTTPTestStore(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), `"org":"acme"`) {
			http.Error(w, "empty retry body", http.StatusBadRequest)
			return
		}
		putCalls++
		if putCalls == 1 {
			http.Error(w, "retry", http.StatusConflict)
			return
		}
		w.Header().Set("ETag", `"stack-v1"`)
	}))

	if _, err := store.CreateStack(t.Context(), "acme", "api", "dev"); err != nil {
		t.Fatalf("CreateStack: %v", err)
	}
	if putCalls != 2 {
		t.Fatalf("PutObject calls = %d, want 2", putCalls)
	}
}

func TestCreateStackDoesNotRetryPreconditionFailure(t *testing.T) {
	putCalls := 0
	store := newHTTPTestStore(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		putCalls++
		http.Error(w, "exists", http.StatusPreconditionFailed)
	}))

	_, err := store.CreateStack(t.Context(), "acme", "api", "dev")
	if !errors.Is(err, ErrStackExists) {
		t.Fatalf("CreateStack error = %v", err)
	}
	if putCalls != 1 {
		t.Fatalf("PutObject calls = %d, want 1", putCalls)
	}
}

func TestCreateStackAssignsIncarnation(t *testing.T) {
	store := newHTTPTestStore(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || !strings.HasSuffix(r.URL.Path, "/stack.json") {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		var stack map[string]any
		if err := json.NewDecoder(r.Body).Decode(&stack); err != nil {
			t.Fatal(err)
		}
		if incarnation, _ := stack["incarnation"].(string); incarnation == "" {
			http.Error(w, "missing stack incarnation", http.StatusBadRequest)
			return
		}
		w.Header().Set("ETag", `"stack-v1"`)
	}))

	if _, err := store.CreateStack(t.Context(), "acme", "api", "dev"); err != nil {
		t.Fatalf("CreateStack: %v", err)
	}
}

func TestAcquireLockUsesCanonicalStackCAS(t *testing.T) {
	store := newHTTPTestStore(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/stack.json"):
			writeStack(t, w, Stack{
				Org: "acme", Project: "api", Name: "dev", Fence: 3,
			}, `"stack-v3"`)
		case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/stack.json"):
			if r.Header.Get("If-Match") != `"stack-v3"` {
				http.Error(w, "missing stack precondition", http.StatusPreconditionFailed)
				return
			}
			var got Stack
			if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
				t.Fatal(err)
			}
			if got.Fence != 4 || got.Lock == nil || got.Lock.Generation != 4 {
				http.Error(w, "lock fence missing", http.StatusBadRequest)
				return
			}
			w.Header().Set("ETag", `"stack-v4"`)
		default:
			http.Error(w, "lock operation bypassed stack CAS", http.StatusBadRequest)
		}
	}))

	lock, err := store.AcquireLock(t.Context(), "acme", "api", "dev", "", "upd-1", "user", time.Minute)
	if err != nil {
		t.Fatalf("AcquireLock: %v", err)
	}
	if lock.Generation != 4 {
		t.Fatalf("lock = %+v", lock)
	}
}

func TestAcquireLockRejectsReplacementIncarnation(t *testing.T) {
	requests := 0
	store := newHTTPTestStore(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/stack.json") {
			http.Error(w, "replacement stack was locked", http.StatusConflict)
			return
		}
		writeStack(t, w, Stack{
			Org: "acme", Project: "api", Name: "dev",
			Incarnation: "replacement", LockProtocol: canonicalLockProtocol,
		}, `"stack-replacement"`)
	}))

	_, err := store.AcquireLock(
		t.Context(),
		"acme",
		"api",
		"dev",
		"created",
		"delete-rollback",
		"user",
		time.Minute,
	)
	if !errors.Is(err, ErrConcurrentMutation) {
		t.Fatalf("AcquireLock error = %v", err)
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want only stack read", requests)
	}
}

func TestRenewLockUsesCanonicalStackCAS(t *testing.T) {
	lock := Lock{
		UpdateID: "upd-1", Owner: "user",
		ExpiresAt: time.Now().Add(time.Minute), Generation: 4,
	}
	store := newHTTPTestStore(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/stack.json"):
			writeStack(t, w, Stack{
				Org: "acme", Project: "api", Name: "dev", Fence: 4, Lock: &lock,
			}, `"stack-v4"`)
		case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/stack.json"):
			if r.Header.Get("If-Match") != `"stack-v4"` {
				http.Error(w, "missing stack precondition", http.StatusPreconditionFailed)
				return
			}
			var got Stack
			if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
				t.Fatal(err)
			}
			if got.Lock == nil || !got.Lock.ExpiresAt.After(lock.ExpiresAt) {
				http.Error(w, "lease not renewed", http.StatusBadRequest)
				return
			}
			w.Header().Set("ETag", `"stack-v5"`)
		default:
			http.Error(w, "lease operation bypassed stack CAS", http.StatusBadRequest)
		}
	}))

	if _, err := store.RenewLock(t.Context(), "acme", "api", "dev", "upd-1", 4, 2*time.Minute); err != nil {
		t.Fatalf("RenewLock: %v", err)
	}
}

func TestRenewLegacyLockMigratesToCanonicalStack(t *testing.T) {
	legacy := Lock{
		UpdateID: "upd-1", Owner: "user",
		ExpiresAt: time.Now().Add(time.Minute),
	}
	migrated := false
	legacyDeleted := false
	store := newHTTPTestStore(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/stack.json"):
			writeStack(t, w, Stack{
				Org: "acme", Project: "api", Name: "dev",
			}, `"stack-v0"`)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/lock.json"):
			writeLock(t, w, legacy, `"lock-v0"`)
		case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/stack.json"):
			if r.Header.Get("If-Match") != `"stack-v0"` {
				http.Error(w, "missing stack precondition", http.StatusPreconditionFailed)
				return
			}
			var got Stack
			if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
				t.Fatal(err)
			}
			if got.LockProtocol != canonicalLockProtocol ||
				got.Fence != 1 ||
				got.Lock == nil ||
				got.Lock.Generation != 1 {
				http.Error(w, "legacy lock was not fenced", http.StatusBadRequest)
				return
			}
			migrated = true
			w.Header().Set("ETag", `"stack-v1"`)
		case r.Method == http.MethodDelete && strings.HasSuffix(r.URL.Path, "/lock.json"):
			if !migrated || r.Header.Get("If-Match") != `"lock-v0"` {
				http.Error(w, "legacy lock deleted before migration", http.StatusConflict)
				return
			}
			legacyDeleted = true
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unexpected request", http.StatusBadRequest)
		}
	}))

	lock, err := store.RenewLock(t.Context(), "acme", "api", "dev", "upd-1", 0, 2*time.Minute)
	if err != nil {
		t.Fatalf("RenewLock: %v", err)
	}
	if lock.Generation != 1 || !legacyDeleted {
		t.Fatalf("lock = %+v, legacy deleted = %v", lock, legacyDeleted)
	}
}

func TestCheckpointCommitUsesOnlyCanonicalStackFence(t *testing.T) {
	lock := Lock{
		UpdateID: "upd-1", Owner: "user",
		ExpiresAt: time.Now().Add(time.Minute), Generation: 4,
	}
	store := newHTTPTestStore(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/checkpoints/objects/"):
			w.Header().Set("ETag", `"checkpoint-v1"`)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/stack.json"):
			writeStack(t, w, Stack{
				Org: "acme", Project: "api", Name: "dev", Version: 1,
				Fence: 4, Lock: &lock,
			}, `"stack-v4"`)
		case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/stack.json"):
			if r.Header.Get("If-Match") != `"stack-v4"` {
				http.Error(w, "missing stack precondition", http.StatusPreconditionFailed)
				return
			}
			w.Header().Set("ETag", `"stack-v5"`)
		case r.Method == http.MethodPut:
			w.Header().Set("ETag", `"legacy-copy"`)
		default:
			http.Error(w, "checkpoint read noncanonical lock", http.StatusBadRequest)
		}
	}))

	err := store.SaveCheckpoint(
		t.Context(),
		"acme",
		"api",
		"dev",
		"",
		"upd-1",
		4,
		1,
		json.RawMessage(`{"version":3,"deployment":{"resources":[]}}`),
	)
	if err != nil {
		t.Fatalf("SaveCheckpoint: %v", err)
	}
}

func TestInitialCheckpointRejectsReplacementIncarnation(t *testing.T) {
	requests := 0
	store := newHTTPTestStore(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/stack.json") {
			http.Error(w, "checkpoint touched replacement stack", http.StatusConflict)
			return
		}
		writeStack(t, w, Stack{
			Org: "acme", Project: "api", Name: "dev",
			Incarnation: "replacement", LockProtocol: canonicalLockProtocol,
		}, `"stack-replacement"`)
	}))

	err := store.SaveCheckpoint(
		t.Context(),
		"acme",
		"api",
		"dev",
		"created",
		"",
		0,
		0,
		json.RawMessage(`{"version":3,"deployment":{}}`),
	)
	if !errors.Is(err, ErrConcurrentMutation) {
		t.Fatalf("SaveCheckpoint error = %v", err)
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want only stack read", requests)
	}
}

func TestCheckpointFallbackUsesStackIncarnation(t *testing.T) {
	store := newHTTPTestStore(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/stack.json"):
			w.Header().Set("ETag", `"stack-v1"`)
			_, _ = io.WriteString(w, `{"org":"acme","project":"api","name":"dev","incarnation":"new"}`)
		case r.Method == http.MethodGet &&
			strings.Contains(r.URL.Path, "/incarnations/new/checkpoints/latest.json"):
			w.Header().Set("ETag", `"checkpoint-v1"`)
			_, _ = io.WriteString(w, `{"version":3,"deployment":{}}`)
		default:
			http.Error(w, "checkpoint used stale stack namespace", http.StatusBadRequest)
		}
	}))

	if _, err := store.GetCheckpoint(t.Context(), "acme", "api", "dev"); err != nil {
		t.Fatalf("GetCheckpoint: %v", err)
	}
}

func TestListUpdatesUsesStackIncarnation(t *testing.T) {
	store := newHTTPTestStore(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/stack.json"):
			w.Header().Set("ETag", `"stack-v1"`)
			_, _ = io.WriteString(w, `{"org":"acme","project":"api","name":"dev","incarnation":"new"}`)
		case r.Method == http.MethodGet && r.URL.Query().Get("list-type") == "2":
			if r.URL.Query().Get("prefix") != "acme/api/dev/incarnations/new/updates/" {
				http.Error(w, "updates used stale stack namespace", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/xml")
			_, _ = io.WriteString(w, `<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>state</Name><KeyCount>0</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated></ListBucketResult>`)
		default:
			http.Error(w, "unexpected request", http.StatusBadRequest)
		}
	}))

	if _, err := store.ListUpdates(t.Context(), "acme", "api", "dev"); err != nil {
		t.Fatalf("ListUpdates: %v", err)
	}
}

func TestUpdateMutationUsesStackIncarnation(t *testing.T) {
	updateKey := "/acme/api/dev/incarnations/new/updates/upd-1.json"
	store := newHTTPTestStore(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/stack.json"):
			w.Header().Set("ETag", `"stack-v1"`)
			_, _ = io.WriteString(w, `{"org":"acme","project":"api","name":"dev","incarnation":"new"}`)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, updateKey):
			w.Header().Set("ETag", `"update-v1"`)
			_, _ = io.WriteString(w, `{"id":"upd-1","kind":"update","status":"not-started","version":1}`)
		case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, updateKey):
			if r.Header.Get("If-Match") != `"update-v1"` {
				http.Error(w, "missing update precondition", http.StatusPreconditionFailed)
				return
			}
			var got Update
			if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
				t.Fatal(err)
			}
			if got.Status != "in-progress" {
				http.Error(w, "update did not start", http.StatusBadRequest)
				return
			}
			w.Header().Set("ETag", `"update-v2"`)
		default:
			http.Error(w, "update used stale stack namespace", http.StatusBadRequest)
		}
	}))

	if err := store.StartUpdate(t.Context(), "acme", "api", "dev", "upd-1"); err != nil {
		t.Fatalf("StartUpdate: %v", err)
	}
}

func TestRenewLockDoesNotReactivateReleasedFence(t *testing.T) {
	lock := Lock{
		UpdateID: "upd-1", Owner: "user",
		ExpiresAt: time.Now().Add(time.Minute), Generation: 4,
	}
	putCalled := false
	store := newHTTPTestStore(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/lock.json"):
			writeLock(t, w, lock, `"lock-v1"`)
		case r.Method == http.MethodGet:
			writeStack(t, w, Stack{
				Org: "acme", Project: "api", Name: "dev", Fence: 4,
			}, `"stack-v2"`)
		case r.Method == http.MethodPut:
			putCalled = true
			http.Error(w, "released fence reactivated", http.StatusConflict)
		default:
			http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
		}
	}))

	if _, err := store.RenewLock(t.Context(), "acme", "api", "dev", "upd-1", 4, time.Minute); !errors.Is(err, ErrNoLock) {
		t.Fatalf("RenewLock error = %v", err)
	}
	if putCalled {
		t.Fatal("renew wrote lock after fence release")
	}
}

func TestReleaseLockClearsCanonicalFence(t *testing.T) {
	lock := Lock{
		UpdateID: "upd-1", Owner: "user",
		ExpiresAt: time.Now().Add(time.Minute), Generation: 4,
	}
	store := newHTTPTestStore(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeStack(t, w, Stack{Org: "acme", Project: "api", Name: "dev", Fence: 4, Lock: &lock}, `"stack-v1"`)
		case http.MethodPut:
			if r.Header.Get("If-Match") != `"stack-v1"` {
				http.Error(w, "missing stack precondition", http.StatusPreconditionFailed)
				return
			}
			var got Stack
			if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
				t.Fatal(err)
			}
			if got.Lock != nil {
				http.Error(w, "lock was not cleared", http.StatusBadRequest)
				return
			}
			w.Header().Set("ETag", `"stack-v2"`)
		default:
			http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
		}
	}))

	if err := store.ReleaseLock(t.Context(), "acme", "api", "dev", "upd-1", 4); err != nil {
		t.Fatalf("ReleaseLock: %v", err)
	}
}

func TestExpiredLockTakeoverAdvancesFence(t *testing.T) {
	lock := Lock{
		UpdateID: "upd-old", Owner: "old",
		ExpiresAt: time.Now().Add(-time.Minute), Generation: 7,
	}
	store := newHTTPTestStore(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeStack(t, w, Stack{Org: "acme", Project: "api", Name: "dev", Fence: 7, Lock: &lock}, `"stack-v1"`)
		case http.MethodPut:
			if r.Header.Get("If-Match") != `"stack-v1"` {
				http.Error(w, "missing stack precondition", http.StatusPreconditionFailed)
				return
			}
			var got Stack
			if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
				t.Fatal(err)
			}
			if got.Lock == nil || got.Lock.Generation != 8 || got.Fence != 8 {
				http.Error(w, "fence did not advance", http.StatusBadRequest)
				return
			}
			w.Header().Set("ETag", `"stack-v2"`)
		default:
			http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
		}
	}))

	got, err := store.AcquireLock(t.Context(), "acme", "api", "dev", "", "upd-new", "new", time.Minute)
	if err != nil {
		t.Fatalf("AcquireLock: %v", err)
	}
	if got.UpdateID != "upd-new" || got.Generation != 8 {
		t.Fatalf("lock = %+v", got)
	}
}

func TestExpiredDeletionFenceBlocksUpdateTakeover(t *testing.T) {
	lock := Lock{
		UpdateID: "delete-old", Owner: "old",
		ExpiresAt: time.Now().Add(-time.Minute), Generation: 7,
	}
	requests := 0
	store := newHTTPTestStore(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/stack.json") {
			http.Error(w, "deletion tombstone was replaced", http.StatusConflict)
			return
		}
		writeStack(t, w, Stack{
			Org: "acme", Project: "api", Name: "dev", Fence: 7, Lock: &lock,
		}, `"stack-v1"`)
	}))

	_, err := store.AcquireLock(t.Context(), "acme", "api", "dev", "", "upd-new", "new", time.Minute)
	var held *LockHeldError
	if !errors.As(err, &held) || held.Lock.UpdateID != "delete-old" {
		t.Fatalf("AcquireLock error = %v", err)
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want only stack read", requests)
	}
}

func TestDeleteStackReportsPerObjectErrors(t *testing.T) {
	const checkpointKey = "acme/api/dev/checkpoints/latest.json"
	lock := &Lock{
		UpdateID: "delete-1", Generation: 1,
		ExpiresAt: time.Now().Add(time.Minute),
	}
	store := newHTTPTestStore(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Query().Get("list-type") == "2":
			w.Header().Set("Content-Type", "application/xml")
			_, _ = io.WriteString(w, `<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>state</Name><Prefix>acme/api/dev/</Prefix><KeyCount>2</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated><Contents><Key>acme/api/dev/stack.json</Key><ETag>"stack"</ETag><Size>1</Size><StorageClass>STANDARD</StorageClass></Contents><Contents><Key>`+checkpointKey+`</Key><ETag>"checkpoint"</ETag><Size>1</Size><StorageClass>STANDARD</StorageClass></Contents></ListBucketResult>`)
		case r.Method == http.MethodGet:
			writeStack(t, w, Stack{
				Org: "acme", Project: "api", Name: "dev", Fence: 1, Lock: lock,
			}, `"stack"`)
		case r.Method == http.MethodPost && r.URL.Query().Has("delete"):
			w.Header().Set("Content-Type", "application/xml")
			_, _ = io.WriteString(w, `<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Error><Key>`+checkpointKey+`</Key><Code>AccessDenied</Code><Message>denied</Message></Error></DeleteResult>`)
		default:
			http.Error(w, "unexpected request", http.StatusBadRequest)
		}
	}))

	err := store.DeleteStack(t.Context(), "acme", "api", "dev", "", "delete-1", 1)
	if err == nil || !strings.Contains(err.Error(), "AccessDenied") {
		t.Fatalf("DeleteStack error = %v", err)
	}
}

func TestDeleteStackRejectsNonDeletionFence(t *testing.T) {
	lock := Lock{
		UpdateID: "update-1", Owner: "user",
		ExpiresAt: time.Now().Add(time.Minute), Generation: 2,
	}
	requests := 0
	store := newHTTPTestStore(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/stack.json") {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		writeStack(t, w, Stack{
			Org: "acme", Project: "api", Name: "dev", Fence: 2, Lock: &lock,
		}, `"stack"`)
	}))

	err := store.DeleteStack(t.Context(), "acme", "api", "dev", "", "update-1", 2)
	var held *LockHeldError
	if !errors.As(err, &held) {
		t.Fatalf("DeleteStack error = %v", err)
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want only stack read", requests)
	}
}

func TestDeleteStackRequiresDeletionFence(t *testing.T) {
	requests := 0
	store := newHTTPTestStore(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/stack.json") {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		writeStack(t, w, Stack{
			Org: "acme", Project: "api", Name: "dev", LockProtocol: canonicalLockProtocol,
		}, `"stack"`)
	}))

	err := store.DeleteStack(t.Context(), "acme", "api", "dev", "", "delete-1", 1)
	if !errors.Is(err, ErrNoLock) {
		t.Fatalf("DeleteStack error = %v", err)
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want only stack read", requests)
	}
}

func TestDeleteStackRejectsExpiredDeletionFence(t *testing.T) {
	requests := 0
	lock := &Lock{
		UpdateID: "delete-expired", Generation: 1,
		ExpiresAt: time.Now().Add(-time.Minute),
	}
	store := newHTTPTestStore(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/stack.json") {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		writeStack(t, w, Stack{
			Org: "acme", Project: "api", Name: "dev", Fence: 1, Lock: lock,
		}, `"stack"`)
	}))

	err := store.DeleteStack(t.Context(), "acme", "api", "dev", "", "delete-expired", 1)
	if !errors.Is(err, ErrNoLock) {
		t.Fatalf("DeleteStack error = %v", err)
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want only stack read", requests)
	}
}

func TestDeleteStackUsesStackFence(t *testing.T) {
	deletedObjects := false
	lock := Lock{
		UpdateID: "delete-1", Generation: 2,
		ExpiresAt: time.Now().Add(time.Minute),
	}
	store := newHTTPTestStore(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Query().Get("list-type") == "2":
			w.Header().Set("Content-Type", "application/xml")
			if deletedObjects {
				_, _ = io.WriteString(w, `<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>state</Name><Prefix>acme/api/dev/</Prefix><KeyCount>1</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated><Contents><Key>acme/api/dev/stack.json</Key><ETag>"stack"</ETag><Size>1</Size><StorageClass>STANDARD</StorageClass></Contents></ListBucketResult>`)
				return
			}
			_, _ = io.WriteString(w, `<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>state</Name><Prefix>acme/api/dev/</Prefix><KeyCount>3</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated><Contents><Key>acme/api/dev/stack.json</Key><ETag>"stack"</ETag><Size>1</Size><StorageClass>STANDARD</StorageClass></Contents><Contents><Key>acme/api/dev/lock.json</Key><ETag>"lock"</ETag><Size>1</Size><StorageClass>STANDARD</StorageClass></Contents><Contents><Key>acme/api/dev/checkpoints/latest.json</Key><ETag>"checkpoint"</ETag><Size>1</Size><StorageClass>STANDARD</StorageClass></Contents></ListBucketResult>`)
		case r.Method == http.MethodGet:
			writeStack(t, w, Stack{Org: "acme", Project: "api", Name: "dev", Fence: 2, Lock: &lock}, `"stack"`)
		case r.Method == http.MethodPost && r.URL.Query().Has("delete"):
			body, _ := io.ReadAll(r.Body)
			if strings.Contains(string(body), "stack.json") {
				http.Error(w, "stack fence deleted in batch", http.StatusConflict)
				return
			}
			if !strings.Contains(string(body), "lock.json") {
				http.Error(w, "legacy lock was not cleaned up", http.StatusConflict)
				return
			}
			deletedObjects = true
			w.Header().Set("Content-Type", "application/xml")
			_, _ = io.WriteString(w, `<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"/>`)
		case r.Method == http.MethodDelete && strings.HasSuffix(r.URL.Path, "/stack.json"):
			if r.Header.Get("If-Match") != `"stack"` {
				http.Error(w, "missing stack precondition", http.StatusPreconditionFailed)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unexpected request", http.StatusBadRequest)
		}
	}))

	if err := store.DeleteStack(t.Context(), "acme", "api", "dev", "", "delete-1", 2); err != nil {
		t.Fatalf("DeleteStack: %v", err)
	}
	if !deletedObjects {
		t.Fatal("stack children were not deleted before stack fence")
	}
}

func TestDeleteStackScopesChildrenToCapturedIncarnation(t *testing.T) {
	lock := Lock{
		UpdateID: "delete-1", Generation: 2,
		ExpiresAt: time.Now().Add(time.Minute),
	}
	deleted := false
	store := newHTTPTestStore(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Query().Get("list-type") == "2":
			if r.URL.Query().Get("prefix") != "acme/api/dev/incarnations/created/" {
				http.Error(w, "deletion escaped captured incarnation", http.StatusConflict)
				return
			}
			w.Header().Set("Content-Type", "application/xml")
			if deleted {
				_, _ = io.WriteString(w, `<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>state</Name><KeyCount>0</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated></ListBucketResult>`)
				return
			}
			_, _ = io.WriteString(w, `<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>state</Name><KeyCount>1</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated><Contents><Key>acme/api/dev/incarnations/created/checkpoints/latest.json</Key><ETag>"checkpoint"</ETag><Size>1</Size><StorageClass>STANDARD</StorageClass></Contents></ListBucketResult>`)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/stack.json"):
			writeStack(t, w, Stack{
				Org: "acme", Project: "api", Name: "dev",
				Incarnation: "created", Fence: 2, Lock: &lock,
			}, `"stack-created"`)
		case r.Method == http.MethodPost && r.URL.Query().Has("delete"):
			deleted = true
			w.Header().Set("Content-Type", "application/xml")
			_, _ = io.WriteString(w, `<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"/>`)
		case r.Method == http.MethodDelete && strings.HasSuffix(r.URL.Path, "/stack.json"):
			if r.Header.Get("If-Match") != `"stack-created"` {
				http.Error(w, "wrong stack incarnation", http.StatusPreconditionFailed)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unexpected request", http.StatusBadRequest)
		}
	}))

	if err := store.DeleteStack(
		t.Context(),
		"acme",
		"api",
		"dev",
		"created",
		"delete-1",
		2,
	); err != nil {
		t.Fatalf("DeleteStack: %v", err)
	}
}

func TestDeleteStackRevalidatesFenceBeforeEveryBatch(t *testing.T) {
	lock := Lock{
		UpdateID: "delete-1", Generation: 2,
		ExpiresAt: time.Now().Add(time.Minute),
	}
	var contents strings.Builder
	for i := range 1001 {
		fmt.Fprintf(
			&contents,
			`<Contents><Key>acme/api/dev/incarnations/created/updates/%04d.json</Key><ETag>"%04d"</ETag><Size>1</Size><StorageClass>STANDARD</StorageClass></Contents>`,
			i,
			i,
		)
	}
	deleteBatches := 0
	store := newHTTPTestStore(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Query().Get("list-type") == "2":
			w.Header().Set("Content-Type", "application/xml")
			_, _ = fmt.Fprintf(
				w,
				`<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>state</Name><KeyCount>1001</KeyCount><MaxKeys>1001</MaxKeys><IsTruncated>false</IsTruncated>%s</ListBucketResult>`,
				contents.String(),
			)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/stack.json"):
			if deleteBatches == 0 {
				writeStack(t, w, Stack{
					Org: "acme", Project: "api", Name: "dev",
					Incarnation: "created", Fence: 2, Lock: &lock,
				}, `"stack-created"`)
				return
			}
			writeStack(t, w, Stack{
				Org: "acme", Project: "api", Name: "dev",
				Incarnation: "replacement", LockProtocol: canonicalLockProtocol,
			}, `"stack-replacement"`)
		case r.Method == http.MethodPost && r.URL.Query().Has("delete"):
			deleteBatches++
			if deleteBatches > 1 {
				http.Error(w, "deleted replacement children", http.StatusConflict)
				return
			}
			w.Header().Set("Content-Type", "application/xml")
			_, _ = io.WriteString(w, `<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"/>`)
		default:
			http.Error(w, "unexpected request", http.StatusBadRequest)
		}
	}))

	err := store.DeleteStack(
		t.Context(),
		"acme",
		"api",
		"dev",
		"created",
		"delete-1",
		2,
	)
	if !errors.Is(err, ErrConcurrentMutation) {
		t.Fatalf("DeleteStack error = %v", err)
	}
	if deleteBatches != 1 {
		t.Fatalf("delete batches = %d, want 1", deleteBatches)
	}
}

func TestSaveCheckpointCommitsPointerWithStackFence(t *testing.T) {
	lock := &Lock{
		UpdateID: "upd-1", Owner: "user",
		ExpiresAt: time.Now().Add(time.Minute), Generation: 4,
	}
	store := newHTTPTestStore(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/lock.json"):
			writeLock(t, w, *lock, `"lock-v1"`)
		case r.Method == http.MethodGet:
			writeStack(t, w, Stack{Org: "acme", Project: "api", Name: "dev", Version: 1, Fence: 4, Lock: lock}, `"stack-v1"`)
		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/checkpoints/objects/"):
			if r.Header.Get("If-None-Match") != "*" {
				http.Error(w, "missing immutable object precondition", http.StatusPreconditionFailed)
				return
			}
			w.Header().Set("ETag", `"checkpoint-v1"`)
		case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/stack.json"):
			if r.Header.Get("If-Match") != `"stack-v1"` {
				http.Error(w, "missing stack precondition", http.StatusPreconditionFailed)
				return
			}
			var got Stack
			if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
				t.Fatal(err)
			}
			if got.LatestCheckpointKey == "" || got.CheckpointVersions["1"] != got.LatestCheckpointKey {
				http.Error(w, "checkpoint pointer missing", http.StatusBadRequest)
				return
			}
			w.Header().Set("ETag", `"stack-v2"`)
		case r.Method == http.MethodPut:
			w.Header().Set("ETag", `"legacy-copy"`)
		default:
			http.Error(w, "unexpected request", http.StatusBadRequest)
		}
	}))

	err := store.SaveCheckpoint(
		t.Context(),
		"acme",
		"api",
		"dev",
		"",
		"upd-1",
		4,
		1,
		json.RawMessage(`{"version":3,"deployment":{"resources":[]}}`),
	)
	if err != nil {
		t.Fatalf("SaveCheckpoint: %v", err)
	}
}

func TestSaveCheckpointRejectsReplacedLockDuringCommit(t *testing.T) {
	oldLock := Lock{
		UpdateID: "upd-old", Owner: "old",
		ExpiresAt: time.Now().Add(time.Minute), Generation: 4,
	}
	newLock := Lock{
		UpdateID: "upd-new", Owner: "new",
		ExpiresAt: time.Now().Add(time.Minute), Generation: 5,
	}
	replaced := false
	store := newHTTPTestStore(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/lock.json"):
			if replaced {
				writeLock(t, w, newLock, `"lock-v2"`)
			} else {
				writeLock(t, w, oldLock, `"lock-v1"`)
			}
		case r.Method == http.MethodGet:
			writeStack(t, w, Stack{
				Org: "acme", Project: "api", Name: "dev", Version: 1,
				Fence: 4, Lock: &oldLock,
			}, `"stack-v1"`)
		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/checkpoints/objects/"):
			w.Header().Set("ETag", `"checkpoint-v1"`)
		case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/stack.json"):
			replaced = true
			http.Error(w, "lock replaced", http.StatusPreconditionFailed)
		default:
			http.Error(w, "unexpected request", http.StatusBadRequest)
		}
	}))

	err := store.SaveCheckpoint(
		t.Context(),
		"acme",
		"api",
		"dev",
		"",
		"upd-old",
		4,
		1,
		json.RawMessage(`{"version":3,"deployment":{"resources":[]}}`),
	)
	if !errors.Is(err, ErrConcurrentMutation) {
		t.Fatalf("SaveCheckpoint error = %v", err)
	}
}

func TestPreviewCreationRejectsDeletionFence(t *testing.T) {
	deleteLock := &Lock{
		UpdateID: "delete-123", Owner: "user",
		ExpiresAt: time.Now().Add(time.Minute), Generation: 3,
	}
	putCalled := false
	store := newHTTPTestStore(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeStack(t, w, Stack{
				Org: "acme", Project: "api", Name: "dev",
				Fence: 3, Lock: deleteLock,
			}, `"stack-v3"`)
		case http.MethodPut:
			putCalled = true
			w.Header().Set("ETag", `"preview"`)
		default:
			http.Error(w, "unexpected request", http.StatusMethodNotAllowed)
		}
	}))

	_, err := store.CreateUpdate(t.Context(), "acme", "api", "dev", "preview", "preview-1")
	var held *LockHeldError
	if !errors.As(err, &held) {
		t.Fatalf("CreateUpdate error = %v", err)
	}
	if putCalled {
		t.Fatal("preview record written during deletion")
	}
}

func TestCreateUpdateRetriesStackCASConflict(t *testing.T) {
	lock := Lock{
		UpdateID: "upd-1", Owner: "user",
		ExpiresAt: time.Now().Add(time.Minute), Generation: 4,
	}
	stackGets := 0
	stackPuts := 0
	store := newHTTPTestStore(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/lock.json"):
			writeLock(t, w, lock, `"lock-v1"`)
		case r.Method == http.MethodGet:
			stackGets++
			etag := `"stack-v1"`
			if stackGets > 2 {
				etag = `"stack-v2"`
			}
			writeStack(t, w, Stack{
				Org: "acme", Project: "api", Name: "dev",
				Fence: 4, Lock: &lock,
			}, etag)
		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/updates/"):
			w.Header().Set("ETag", `"update-v1"`)
		case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/stack.json"):
			stackPuts++
			if stackPuts == 1 {
				http.Error(w, "concurrent preview barrier", http.StatusPreconditionFailed)
				return
			}
			w.Header().Set("ETag", `"stack-v3"`)
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unexpected request", http.StatusMethodNotAllowed)
		}
	}))

	update, err := store.CreateUpdate(t.Context(), "acme", "api", "dev", "update", "upd-1")
	if err != nil {
		t.Fatalf("CreateUpdate: %v", err)
	}
	if update.Version != 1 || stackPuts != 2 {
		t.Fatalf("update = %+v, stack PUTs = %d", update, stackPuts)
	}
}
