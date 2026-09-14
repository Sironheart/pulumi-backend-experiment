//go:build integration

package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
)

const flociImage = "floci/floci:2.0.1@sha256:4e451c39c7bb88e3cd4f87e8fc0c25d5b47695a51185d521e2241fa00486e8eb"

// startFloci runs a floci container and returns an S3 client pointed at it,
// plus a created bucket name.
func startFloci(t *testing.T) (*s3.Client, string) {
	t.Helper()
	ctx := context.Background()
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        flociImage,
			ExposedPorts: []string{"4566/tcp"},
			WaitingFor:   wait.ForListeningPort("4566/tcp"),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("start floci: %v", err)
	}
	t.Cleanup(func() { _ = container.Terminate(ctx) })

	endpoint, err := container.Endpoint(ctx, "http")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion("us-east-1"),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "")),
	)
	if err != nil {
		t.Fatal(err)
	}
	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(endpoint)
		o.UsePathStyle = true
	})
	bucket := "test-bucket"
	if _, err := client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &bucket}); err != nil {
		t.Fatalf("create bucket: %v", err)
	}
	return client, bucket
}

func newTestStore(t *testing.T) *S3Store {
	t.Helper()
	client, bucket := startFloci(t)
	return NewS3Store(client, bucket)
}

func TestStackLifecycle(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if _, err := s.GetStack(ctx, "acme", "api", "dev"); !errors.Is(err, ErrStackNotFound) {
		t.Fatalf("GetStack before create: %v", err)
	}
	if _, err := s.CreateStack(ctx, "acme", "api", "dev"); err != nil {
		t.Fatalf("CreateStack: %v", err)
	}
	if _, err := s.CreateStack(ctx, "acme", "api", "dev"); !errors.Is(err, ErrStackExists) {
		t.Fatalf("duplicate CreateStack: %v", err)
	}

	st, err := s.GetStack(ctx, "acme", "api", "dev")
	if err != nil {
		t.Fatalf("GetStack: %v", err)
	}
	if st.Org != "acme" || st.Project != "api" || st.Name != "dev" || st.Version != 0 {
		t.Errorf("stack = %+v", st)
	}

	if _, err := s.CreateStack(ctx, "acme", "web", "prod"); err != nil {
		t.Fatal(err)
	}
	stacks, err := s.ListStacks(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if len(stacks) != 2 {
		t.Fatalf("ListStacks = %d, want 2", len(stacks))
	}
	if stacks[0].Project != "api" || stacks[1].Project != "web" {
		t.Errorf("ListStacks order = %v", stacks)
	}

	deleteID := "delete-" + NewUpdateID()
	deleteLock, err := s.AcquireLock(
		ctx,
		"acme",
		"api",
		"dev",
		st.Incarnation,
		deleteID,
		"user@example.com",
		time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteStack(
		ctx,
		"acme",
		"api",
		"dev",
		st.Incarnation,
		deleteID,
		deleteLock.Generation,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetStack(ctx, "acme", "api", "dev"); !errors.Is(err, ErrStackNotFound) {
		t.Fatalf("GetStack after delete: %v", err)
	}
	if err := s.DeleteStack(
		ctx,
		"acme",
		"api",
		"dev",
		st.Incarnation,
		deleteID,
		deleteLock.Generation,
	); !errors.Is(err, ErrStackNotFound) {
		t.Fatalf("DeleteStack again: %v", err)
	}
}

func TestCheckpointRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	created, err := s.CreateStack(ctx, "acme", "api", "dev")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := s.GetCheckpoint(ctx, "acme", "api", "dev"); !errors.Is(err, ErrCheckpointNotFound) {
		t.Fatalf("GetCheckpoint before save: %v", err)
	}

	deployment := []byte(`{"version":3,"deployment":{"manifest":{"time":"2026-09-07T00:00:00Z"}}}`)
	if err := s.SaveCheckpoint(
		ctx,
		"acme",
		"api",
		"dev",
		created.Incarnation,
		"",
		0,
		0,
		deployment,
	); err != nil {
		t.Fatalf("SaveCheckpoint: %v", err)
	}
	got, err := s.GetCheckpoint(ctx, "acme", "api", "dev")
	if err != nil {
		t.Fatalf("GetCheckpoint: %v", err)
	}
	if string(got) != string(deployment) {
		t.Errorf("checkpoint = %s", got)
	}

	v1, err := s.GetCheckpointVersion(ctx, "acme", "api", "dev", 0)
	if err != nil {
		t.Fatalf("GetCheckpointVersion: %v", err)
	}
	if string(v1) != string(deployment) {
		t.Errorf("history checkpoint = %s", v1)
	}
	if _, err := s.GetCheckpointVersion(ctx, "acme", "api", "dev", 99); !errors.Is(err, ErrCheckpointNotFound) {
		t.Errorf("GetCheckpointVersion 99: %v", err)
	}
}

func TestUpdateLifecycle(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	created, err := s.CreateStack(ctx, "acme", "api", "dev")
	if err != nil {
		t.Fatal(err)
	}

	updateID := NewUpdateID()
	if _, err := s.AcquireLock(
		ctx,
		"acme",
		"api",
		"dev",
		created.Incarnation,
		updateID,
		"user@example.com",
		time.Minute,
	); err != nil {
		t.Fatal(err)
	}
	u, err := s.CreateUpdate(ctx, "acme", "api", "dev", "update", updateID)
	if err != nil {
		t.Fatalf("CreateUpdate: %v", err)
	}
	if u.Version != 1 || u.Status != "not-started" || u.Kind != "update" || u.ID == "" {
		t.Errorf("update = %+v", u)
	}

	u2, err := s.CreateUpdate(ctx, "acme", "api", "dev", "preview", NewUpdateID())
	if err != nil {
		t.Fatal(err)
	}
	if u2.Version != 1 {
		t.Errorf("preview version = %d, want current version 1", u2.Version)
	}

	if err := s.StartUpdate(ctx, "acme", "api", "dev", u.ID); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetUpdate(ctx, "acme", "api", "dev", u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "in-progress" {
		t.Errorf("status = %q", got.Status)
	}

	changes := map[string]int{"create": 3}
	if err := s.CompleteUpdate(ctx, "acme", "api", "dev", u.ID, "succeeded", "done", changes); err != nil {
		t.Fatal(err)
	}
	got, err = s.GetUpdate(ctx, "acme", "api", "dev", u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "succeeded" || got.ResourceChanges["create"] != 3 || got.EndTime == 0 {
		t.Errorf("completed update = %+v", got)
	}

	st, err := s.GetStack(ctx, "acme", "api", "dev")
	if err != nil {
		t.Fatal(err)
	}
	if st.Version != 1 || st.LastUpdate.IsZero() {
		t.Errorf("stack after complete = %+v", st)
	}

	updates, err := s.ListUpdates(ctx, "acme", "api", "dev")
	if err != nil {
		t.Fatal(err)
	}
	if len(updates) != 2 || updates[0].Version != 1 || updates[1].Version != 1 {
		t.Errorf("ListUpdates = %+v", updates)
	}

	if _, err := s.GetUpdate(ctx, "acme", "api", "dev", "nonexistent"); !errors.Is(err, ErrUpdateNotFound) {
		t.Errorf("GetUpdate nonexistent: %v", err)
	}
}

func TestLockLifecycle(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	created, err := s.CreateStack(ctx, "acme", "api", "dev")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := s.GetLock(ctx, "acme", "api", "dev"); !errors.Is(err, ErrNoLock) {
		t.Fatalf("GetLock before acquire: %v", err)
	}

	lock, err := s.AcquireLock(
		ctx,
		"acme",
		"api",
		"dev",
		created.Incarnation,
		"upd-1",
		"user@example.com",
		time.Minute,
	)
	if err != nil {
		t.Fatalf("AcquireLock: %v", err)
	}
	if lock.UpdateID != "upd-1" || lock.Owner != "user@example.com" {
		t.Errorf("lock = %+v", lock)
	}

	// Second acquire while held fails with LockHeldError.
	_, err = s.AcquireLock(
		ctx,
		"acme",
		"api",
		"dev",
		created.Incarnation,
		"upd-2",
		"other@example.com",
		time.Minute,
	)
	var held *LockHeldError
	if !errors.As(err, &held) {
		t.Fatalf("second acquire: %v", err)
	}
	if held.Lock.UpdateID != "upd-1" {
		t.Errorf("held by %q", held.Lock.UpdateID)
	}

	// Renew with wrong update ID fails.
	if _, err := s.RenewLock(ctx, "acme", "api", "dev", "upd-2", lock.Generation, time.Minute); err == nil {
		t.Error("renew with wrong id succeeded")
	}
	renewed, err := s.RenewLock(ctx, "acme", "api", "dev", "upd-1", lock.Generation, 2*time.Minute)
	if err != nil {
		t.Fatalf("RenewLock: %v", err)
	}
	if !renewed.ExpiresAt.After(lock.ExpiresAt) {
		t.Errorf("renew did not extend: %v vs %v", renewed.ExpiresAt, lock.ExpiresAt)
	}

	// Release with wrong ID fails, right ID succeeds.
	if err := s.ReleaseLock(ctx, "acme", "api", "dev", "upd-2", lock.Generation); err == nil {
		t.Error("release with wrong id succeeded")
	}
	if err := s.ReleaseLock(ctx, "acme", "api", "dev", "upd-1", lock.Generation); err != nil {
		t.Fatalf("ReleaseLock: %v", err)
	}
	if _, err := s.GetLock(ctx, "acme", "api", "dev"); !errors.Is(err, ErrNoLock) {
		t.Fatalf("GetLock after release: %v", err)
	}
}

func TestExpiredLockIsBreakable(t *testing.T) {
	s := newTestStore(t)
	s.now = func() time.Time { return time.Now().Add(-time.Hour) } // lock written "in the past"
	ctx := context.Background()
	created, err := s.CreateStack(ctx, "acme", "api", "dev")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcquireLock(
		ctx,
		"acme",
		"api",
		"dev",
		created.Incarnation,
		"upd-stale",
		"u",
		time.Millisecond,
	); err != nil {
		t.Fatal(err)
	}
	s.now = time.Now

	lock, err := s.AcquireLock(
		ctx,
		"acme",
		"api",
		"dev",
		created.Incarnation,
		"upd-new",
		"u2",
		time.Minute,
	)
	if err != nil {
		t.Fatalf("acquire over expired lock: %v", err)
	}
	if lock.UpdateID != "upd-new" {
		t.Errorf("lock = %+v", lock)
	}
}
