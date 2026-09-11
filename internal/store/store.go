package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

var (
	ErrStackNotFound      = errors.New("stack not found")
	ErrStackExists        = errors.New("stack already exists")
	ErrUpdateNotFound     = errors.New("update not found")
	ErrCheckpointNotFound = errors.New("checkpoint not found")
	ErrNoLock             = errors.New("no lock held")
	ErrInvalidUpdateState = errors.New("invalid update state")
	ErrConcurrentMutation = errors.New("concurrent state mutation")
)

var _ error = (*LockHeldError)(nil)

// LockHeldError reports that another update holds the stack lock.
type LockHeldError struct {
	Lock *Lock
}

func (e *LockHeldError) Error() string { return "stack is locked by another update" }

type Stack struct {
	Org                 string            `json:"org"`
	Project             string            `json:"project"`
	Name                string            `json:"name"`
	Version             int               `json:"version"`
	Created             time.Time         `json:"created"`
	LastUpdate          time.Time         `json:"lastUpdate,omitempty"`
	Incarnation         string            `json:"incarnation,omitempty"`
	LockProtocol        int               `json:"lockProtocol,omitempty"`
	Fence               uint64            `json:"fence,omitempty"`
	Lock                *Lock             `json:"lock,omitempty"`
	LatestCheckpointKey string            `json:"latestCheckpointKey,omitempty"`
	CheckpointVersions  map[string]string `json:"checkpointVersions,omitempty"`
	etag                string
}

type Update struct {
	ID              string         `json:"id"`
	Kind            string         `json:"kind"` // preview|update|refresh|destroy|import
	Status          string         `json:"status"`
	Version         int            `json:"version"`
	Incarnation     string         `json:"-"`
	Message         string         `json:"message,omitempty"`
	ResourceChanges map[string]int `json:"resourceChanges,omitempty"`
	StartTime       int64          `json:"startTime"`
	EndTime         int64          `json:"endTime,omitempty"`
	etag            string
}

type Lock struct {
	UpdateID   string    `json:"updateID"`
	Owner      string    `json:"owner"`
	ExpiresAt  time.Time `json:"expiresAt"`
	Generation uint64    `json:"generation"`
	etag       string
}

func (l *Lock) Expired(now time.Time) bool { return !now.Before(l.ExpiresAt) }

// Store persists all backend state for one S3 bucket.
type Store interface {
	CreateStack(ctx context.Context, org, project, stack string) (*Stack, error)
	GetStack(ctx context.Context, org, project, stack string) (*Stack, error)
	ListStacks(ctx context.Context, org string) ([]Stack, error)
	DeleteStack(ctx context.Context, org, project, stack, incarnation, updateID string, generation uint64) error

	GetCheckpoint(ctx context.Context, org, project, stack string) (json.RawMessage, error)
	GetCheckpointVersion(ctx context.Context, org, project, stack string, version int) (json.RawMessage, error)
	SaveCheckpoint(ctx context.Context, org, project, stack, incarnation, updateID string, generation uint64, version int, deployment json.RawMessage) error

	CreateUpdate(ctx context.Context, org, project, stack, kind, updateID string) (*Update, error)
	GetUpdate(ctx context.Context, org, project, stack, updateID string) (*Update, error)
	StartUpdate(ctx context.Context, org, project, stack, updateID string) error
	CompleteUpdate(ctx context.Context, org, project, stack, updateID, status, message string, resourceChanges map[string]int) error
	ListUpdates(ctx context.Context, org, project, stack string) ([]Update, error)

	AcquireLock(ctx context.Context, org, project, stack, incarnation, updateID, owner string, ttl time.Duration) (*Lock, error)
	RenewLock(ctx context.Context, org, project, stack, updateID string, generation uint64, ttl time.Duration) (*Lock, error)
	ReleaseLock(ctx context.Context, org, project, stack, updateID string, generation uint64) error
	GetLock(ctx context.Context, org, project, stack string) (*Lock, error)
}
