package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

var _ Store = (*S3Store)(nil)

const canonicalLockProtocol = 1

type S3Store struct {
	client *s3.Client
	bucket string
	now    func() time.Time
}

func NewS3Store(client *s3.Client, bucket string) *S3Store {
	return &S3Store{client: client, bucket: bucket, now: time.Now}
}

func (s *S3Store) stackPrefix(org, project, stack string) string {
	return fmt.Sprintf("%s/%s/%s/", org, project, stack)
}

func (s *S3Store) stackKey(org, project, stack string) string {
	return s.stackPrefix(org, project, stack) + "stack.json"
}

func (s *S3Store) lockKey(org, project, stack string) string {
	return s.stackPrefix(org, project, stack) + "lock.json"
}

func (s *S3Store) stackDataPrefix(org, project, stack, incarnation string) string {
	prefix := s.stackPrefix(org, project, stack)
	if incarnation != "" {
		prefix += "incarnations/" + incarnation + "/"
	}
	return prefix
}

func (s *S3Store) latestCheckpointKey(org, project, stack, incarnation string) string {
	return s.stackDataPrefix(org, project, stack, incarnation) + "checkpoints/latest.json"
}

func (s *S3Store) historyCheckpointKey(org, project, stack, incarnation string, version int) string {
	return fmt.Sprintf("%scheckpoints/history/%d.json", s.stackDataPrefix(org, project, stack, incarnation), version)
}

func (s *S3Store) checkpointObjectKey(
	org, project, stack, incarnation string,
	deployment json.RawMessage,
) string {
	sum := sha256.Sum256(deployment)
	return fmt.Sprintf("%scheckpoints/objects/%x.json", s.stackDataPrefix(org, project, stack, incarnation), sum)
}

func (s *S3Store) updateKey(org, project, stack, incarnation, updateID string) string {
	return s.stackDataPrefix(org, project, stack, incarnation) + "updates/" + updateID + ".json"
}

func (s *S3Store) get(ctx context.Context, key string, out any) error {
	_, err := s.getWithETag(ctx, key, out)
	return err
}

func (s *S3Store) getWithETag(ctx context.Context, key string, out any) (string, error) {
	resp, err := s.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &s.bucket, Key: &key})
	if err != nil {
		var nsk *types.NoSuchKey
		if errors.As(err, &nsk) {
			return "", errNotFound
		}
		return "", fmt.Errorf("get %s: %w", key, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return "", err
	}
	return aws.ToString(resp.ETag), nil
}

var errNotFound = errors.New("object not found")

func isNotFound(err error) bool {
	var nsk *types.NoSuchKey
	return errors.Is(err, errNotFound) || errors.As(err, &nsk)
}

func isPreconditionFailed(err error) bool {
	var re *awshttp.ResponseError
	return errors.As(err, &re) && re.HTTPStatusCode() == 412
}

func isConditionalConflict(err error) bool {
	var re *awshttp.ResponseError
	return errors.As(err, &re) && re.HTTPStatusCode() == 409
}

func (s *S3Store) put(ctx context.Context, key string, body []byte, ifNoneMatch bool) error {
	_, err := s.putConditional(ctx, key, body, ifNoneMatch, "")
	return err
}

func (s *S3Store) putIfMatch(ctx context.Context, key string, body []byte, etag string) error {
	if etag == "" {
		return errors.New("conditional write requires ETag")
	}
	_, err := s.putConditional(ctx, key, body, false, etag)
	return err
}

func (s *S3Store) putConditional(
	ctx context.Context,
	key string,
	body []byte,
	ifNoneMatch bool,
	ifMatch string,
) (*s3.PutObjectOutput, error) {
	input := &s3.PutObjectInput{
		Bucket:      &s.bucket,
		Key:         &key,
		Body:        bytes.NewReader(body),
		ContentType: aws.String("application/json"),
	}
	if ifNoneMatch {
		input.IfNoneMatch = aws.String("*")
	}
	if ifMatch != "" {
		input.IfMatch = aws.String(ifMatch)
	}
	var (
		out *s3.PutObjectOutput
		err error
	)
	for attempt := 0; attempt < 3; attempt++ {
		input.Body = bytes.NewReader(body)
		out, err = s.client.PutObject(ctx, input)
		if !isConditionalConflict(err) {
			return out, err
		}
	}
	return out, err
}

func (s *S3Store) putJSON(ctx context.Context, key string, v any, ifNoneMatch bool) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.put(ctx, key, body, ifNoneMatch)
}

func (s *S3Store) putJSONIfMatch(ctx context.Context, key string, v any, etag string) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.putIfMatch(ctx, key, body, etag)
}

func (s *S3Store) deleteIfMatch(ctx context.Context, key, etag string) error {
	if etag == "" {
		return errors.New("conditional delete requires ETag")
	}
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		_, err = s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket:  &s.bucket,
			Key:     &key,
			IfMatch: aws.String(etag),
		})
		if !isConditionalConflict(err) {
			break
		}
	}
	return err
}

func (s *S3Store) CreateStack(ctx context.Context, org, project, stack string) (*Stack, error) {
	st := Stack{
		Org:          org,
		Project:      project,
		Name:         stack,
		Created:      s.now().UTC(),
		Incarnation:  NewUpdateID(),
		LockProtocol: canonicalLockProtocol,
	}
	err := s.putJSON(ctx, s.stackKey(org, project, stack), st, true)
	if isPreconditionFailed(err) {
		return nil, ErrStackExists
	}
	if err != nil {
		return nil, err
	}
	return &st, nil
}

func (s *S3Store) GetStack(ctx context.Context, org, project, stack string) (*Stack, error) {
	var st Stack
	etag, err := s.getWithETag(ctx, s.stackKey(org, project, stack), &st)
	if err != nil {
		if isNotFound(err) {
			return nil, ErrStackNotFound
		}
		return nil, err
	}
	st.etag = etag
	return &st, nil
}

// ListStacks lists stacks of one org, or all stacks when org is empty.
func (s *S3Store) ListStacks(ctx context.Context, org string) ([]Stack, error) {
	prefix := org
	if prefix != "" {
		prefix += "/"
	}
	var stacks []Stack
	paginator := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{
		Bucket: &s.bucket, Prefix: &prefix,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, obj := range page.Contents {
			if !strings.HasSuffix(*obj.Key, "/stack.json") {
				continue
			}
			var st Stack
			if err := s.get(ctx, *obj.Key, &st); err != nil {
				return nil, err
			}
			stacks = append(stacks, st)
		}
	}
	sort.Slice(stacks, func(i, j int) bool {
		return stacks[i].Project+"/"+stacks[i].Name < stacks[j].Project+"/"+stacks[j].Name
	})
	return stacks, nil
}

func (s *S3Store) DeleteStack(
	ctx context.Context,
	org, project, stack, incarnation, updateID string,
	generation uint64,
) error {
	st, err := s.GetStack(ctx, org, project, stack)
	if err != nil {
		return err
	}
	if st.Incarnation != incarnation {
		return ErrConcurrentMutation
	}
	if st.Lock == nil || st.Lock.Expired(s.now()) {
		return ErrNoLock
	}
	if !deletionFence(st.Lock) {
		lock := *st.Lock
		return &LockHeldError{Lock: &lock}
	}
	if st.Lock.UpdateID != updateID || st.Lock.Generation != generation {
		return ErrConcurrentMutation
	}
	stackKey := s.stackKey(org, project, stack)
	objects, err := s.listStackIncarnationObjects(ctx, org, project, stack, incarnation)
	if err != nil {
		return err
	}
	for start := 0; start < len(objects); start += 1000 {
		if err := s.validateDeletionFence(ctx, st, updateID, generation); err != nil {
			return err
		}
		end := min(start+1000, len(objects))
		out, deleteErr := s.client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
			Bucket: &s.bucket, Delete: &types.Delete{Objects: objects[start:end]},
		})
		if deleteErr != nil {
			return deleteErr
		}
		if len(out.Errors) > 0 {
			first := out.Errors[0]
			return fmt.Errorf(
				"delete %s: %s: %s",
				aws.ToString(first.Key),
				aws.ToString(first.Code),
				aws.ToString(first.Message),
			)
		}
	}
	remaining, err := s.listStackIncarnationObjects(ctx, org, project, stack, incarnation)
	if err != nil {
		return err
	}
	if len(remaining) > 0 {
		return ErrConcurrentMutation
	}
	if err := s.validateDeletionFence(ctx, st, updateID, generation); err != nil {
		return err
	}
	if err := s.deleteIfMatch(ctx, stackKey, st.etag); err != nil {
		if isPreconditionFailed(err) {
			return ErrConcurrentMutation
		}
		return err
	}
	return nil
}

func (s *S3Store) validateDeletionFence(
	ctx context.Context,
	expected *Stack,
	updateID string,
	generation uint64,
) error {
	current, err := s.GetStack(ctx, expected.Org, expected.Project, expected.Name)
	if err != nil {
		return ErrConcurrentMutation
	}
	if current.etag != expected.etag ||
		current.Incarnation != expected.Incarnation ||
		current.Lock == nil ||
		current.Lock.UpdateID != updateID ||
		current.Lock.Generation != generation ||
		current.Lock.Expired(s.now()) {
		return ErrConcurrentMutation
	}
	return nil
}

func (s *S3Store) listStackIncarnationObjects(
	ctx context.Context,
	org, project, stack, incarnation string,
) ([]types.ObjectIdentifier, error) {
	if incarnation != "" {
		return s.listObjectsExcept(ctx, s.stackDataPrefix(org, project, stack, incarnation))
	}
	prefix := s.stackPrefix(org, project, stack)
	objects, err := s.listObjectsExcept(ctx, prefix, s.stackKey(org, project, stack))
	if err != nil {
		return nil, err
	}
	incarnationsPrefix := prefix + "incarnations/"
	return slices.DeleteFunc(objects, func(object types.ObjectIdentifier) bool {
		return strings.HasPrefix(aws.ToString(object.Key), incarnationsPrefix)
	}), nil
}

func (s *S3Store) listObjectsExcept(ctx context.Context, prefix string, excludedKeys ...string) ([]types.ObjectIdentifier, error) {
	excluded := make(map[string]struct{}, len(excludedKeys))
	for _, key := range excludedKeys {
		excluded[key] = struct{}{}
	}
	paginator := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{
		Bucket: &s.bucket, Prefix: &prefix,
	})
	var objects []types.ObjectIdentifier
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, obj := range page.Contents {
			if _, skip := excluded[aws.ToString(obj.Key)]; !skip {
				objects = append(objects, types.ObjectIdentifier{Key: obj.Key})
			}
		}
	}
	return objects, nil
}

func (s *S3Store) GetCheckpoint(ctx context.Context, org, project, stack string) (json.RawMessage, error) {
	st, err := s.GetStack(ctx, org, project, stack)
	if err != nil {
		return nil, err
	}
	key := st.LatestCheckpointKey
	if key == "" {
		key = s.latestCheckpointKey(org, project, stack, st.Incarnation)
	}
	raw, _, err := s.getCheckpointWithETag(ctx, key)
	return raw, err
}

func (s *S3Store) getCheckpointWithETag(ctx context.Context, key string) (json.RawMessage, string, error) {
	resp, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &s.bucket, Key: aws.String(key),
	})
	if err != nil {
		if isNotFound(err) {
			return nil, "", ErrCheckpointNotFound
		}
		return nil, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	var raw json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, "", err
	}
	return raw, aws.ToString(resp.ETag), nil
}

func (s *S3Store) GetCheckpointVersion(ctx context.Context, org, project, stack string, version int) (json.RawMessage, error) {
	st, err := s.GetStack(ctx, org, project, stack)
	if err != nil {
		return nil, err
	}
	key := ""
	if st.CheckpointVersions != nil {
		key = st.CheckpointVersions[strconv.Itoa(version)]
	}
	if key == "" {
		key = s.historyCheckpointKey(org, project, stack, st.Incarnation, version)
	}
	raw, _, err := s.getCheckpointWithETag(ctx, key)
	return raw, err
}

func (s *S3Store) SaveCheckpoint(
	ctx context.Context,
	org, project, stack, incarnation, updateID string,
	generation uint64,
	version int,
	deployment json.RawMessage,
) error {
	initialStack, err := s.GetStack(ctx, org, project, stack)
	if err != nil {
		return err
	}
	if initialStack.Incarnation != incarnation {
		return ErrConcurrentMutation
	}
	objectKey := s.checkpointObjectKey(org, project, stack, incarnation, deployment)
	if err := s.put(ctx, objectKey, deployment, true); err != nil && !isPreconditionFailed(err) {
		return err
	}

	for attempt := 0; attempt < 5; attempt++ {
		st, err := s.GetStack(ctx, org, project, stack)
		if err != nil {
			return err
		}
		if st.Incarnation != incarnation {
			return ErrConcurrentMutation
		}
		if updateID == "" {
			if generation != 0 || version != 0 || st.Version != 0 || st.Lock != nil {
				return ErrInvalidUpdateState
			}
		} else if st.Lock == nil ||
			st.Lock.UpdateID != updateID ||
			st.Lock.Generation != generation ||
			st.Lock.Expired(s.now()) ||
			st.Version != version {
			return ErrConcurrentMutation
		}

		if st.CheckpointVersions == nil {
			st.CheckpointVersions = map[string]string{}
		}
		st.LatestCheckpointKey = objectKey
		st.CheckpointVersions[strconv.Itoa(version)] = objectKey
		err = s.putJSONIfMatch(ctx, s.stackKey(org, project, stack), st, st.etag)
		if err == nil {
			if legacyErr := s.put(
				ctx,
				s.historyCheckpointKey(org, project, stack, incarnation, version),
				deployment,
				false,
			); legacyErr != nil {
				slog.Warn("checkpoint committed without legacy history copy", "error", legacyErr)
			}
			if legacyErr := s.put(
				ctx,
				s.latestCheckpointKey(org, project, stack, incarnation),
				deployment,
				false,
			); legacyErr != nil {
				slog.Warn("checkpoint committed without legacy latest copy", "error", legacyErr)
			}
			return nil
		}
		if !isPreconditionFailed(err) {
			return err
		}
	}
	return ErrConcurrentMutation
}

// NewUpdateID generates an opaque update identifier.
func NewUpdateID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *S3Store) CreateUpdate(ctx context.Context, org, project, stack, kind, updateID string) (*Update, error) {
	st, err := s.GetStack(ctx, org, project, stack)
	if err != nil {
		return nil, err
	}
	version := st.Version
	var generation uint64
	if kind == "preview" && deletionFence(st.Lock) {
		lock := *st.Lock
		return nil, &LockHeldError{Lock: &lock}
	}
	if kind != "preview" {
		if st.Lock == nil ||
			st.Lock.UpdateID != updateID ||
			st.Lock.Expired(s.now()) {
			return nil, ErrNoLock
		}
		generation = st.Lock.Generation
		version++
	}
	u := Update{
		ID:          updateID,
		Kind:        kind,
		Status:      "not-started",
		Version:     version,
		StartTime:   s.now().Unix(),
		Incarnation: st.Incarnation,
	}
	updateKey := s.updateKey(org, project, stack, st.Incarnation, u.ID)
	updateBody, err := json.Marshal(u)
	if err != nil {
		return nil, err
	}
	updateOut, err := s.putConditional(ctx, updateKey, updateBody, true, "")
	if err != nil {
		if isPreconditionFailed(err) {
			existing, getErr := s.GetUpdate(ctx, org, project, stack, updateID)
			if getErr == nil {
				if existing.Kind != kind {
					return nil, ErrConcurrentMutation
				}
				if kind != "preview" {
					if commitErr := s.commitUpdateVersion(
						ctx,
						org,
						project,
						stack,
						updateID,
						st.Incarnation,
						generation,
						existing.Version,
					); commitErr != nil {
						return nil, commitErr
					}
				}
				return existing, nil
			}
		}
		return nil, err
	}
	rollbackUpdate := func(cause error) error {
		rollbackErr := s.deleteIfMatch(ctx, updateKey, aws.ToString(updateOut.ETag))
		if rollbackErr != nil {
			return errors.Join(cause, fmt.Errorf("rollback update record: %w", rollbackErr))
		}
		return cause
	}
	if kind == "preview" {
		for attempt := 0; attempt < 5; attempt++ {
			current, getErr := s.GetStack(ctx, org, project, stack)
			if getErr != nil {
				return nil, rollbackUpdate(getErr)
			}
			if current.Incarnation != st.Incarnation {
				return nil, rollbackUpdate(ErrConcurrentMutation)
			}
			if deletionFence(current.Lock) {
				lock := *current.Lock
				return nil, rollbackUpdate(&LockHeldError{Lock: &lock})
			}
			barrierErr := s.putJSONIfMatch(
				ctx,
				s.stackKey(org, project, stack),
				current,
				current.etag,
			)
			if barrierErr == nil {
				return &u, nil
			}
			if !isPreconditionFailed(barrierErr) {
				return nil, rollbackUpdate(barrierErr)
			}
		}
		return nil, rollbackUpdate(ErrConcurrentMutation)
	}
	if err := s.commitUpdateVersion(
		ctx,
		org,
		project,
		stack,
		updateID,
		st.Incarnation,
		generation,
		u.Version,
	); err != nil {
		return nil, rollbackUpdate(err)
	}
	return &u, nil
}

func (s *S3Store) commitUpdateVersion(
	ctx context.Context,
	org, project, stack, updateID string,
	incarnation string,
	generation uint64,
	version int,
) error {
	for attempt := 0; attempt < 5; attempt++ {
		st, err := s.GetStack(ctx, org, project, stack)
		if err != nil {
			return err
		}
		if st.Incarnation != incarnation ||
			st.Lock == nil ||
			st.Lock.UpdateID != updateID ||
			st.Lock.Generation != generation ||
			st.Lock.Expired(s.now()) {
			return ErrConcurrentMutation
		}
		switch st.Version {
		case version:
			return nil
		case version - 1:
			st.Version = version
			st.LastUpdate = s.now().UTC()
		default:
			return ErrConcurrentMutation
		}
		err = s.putJSONIfMatch(ctx, s.stackKey(org, project, stack), st, st.etag)
		if err == nil {
			return nil
		}
		if !isPreconditionFailed(err) {
			return err
		}
	}
	return ErrConcurrentMutation
}

func deletionFence(lock *Lock) bool {
	return lock != nil && strings.HasPrefix(lock.UpdateID, "delete-")
}

func (s *S3Store) GetUpdate(ctx context.Context, org, project, stack, updateID string) (*Update, error) {
	st, err := s.GetStack(ctx, org, project, stack)
	if err != nil {
		return nil, err
	}
	var u Update
	etag, err := s.getWithETag(
		ctx,
		s.updateKey(org, project, stack, st.Incarnation, updateID),
		&u,
	)
	if err != nil {
		if isNotFound(err) {
			return nil, ErrUpdateNotFound
		}
		return nil, err
	}
	u.etag = etag
	u.Incarnation = st.Incarnation
	return &u, nil
}

func (s *S3Store) StartUpdate(ctx context.Context, org, project, stack, updateID string) error {
	u, err := s.GetUpdate(ctx, org, project, stack, updateID)
	if err != nil {
		return err
	}
	if u.Status == "in-progress" {
		return nil
	}
	if u.Status != "not-started" {
		return ErrInvalidUpdateState
	}
	u.Status = "in-progress"
	u.StartTime = s.now().Unix()
	err = s.putJSONIfMatch(
		ctx,
		s.updateKey(org, project, stack, u.Incarnation, updateID),
		u,
		u.etag,
	)
	if isPreconditionFailed(err) {
		return ErrConcurrentMutation
	}
	return err
}

func (s *S3Store) CompleteUpdate(ctx context.Context, org, project, stack, updateID, status, message string, resourceChanges map[string]int) error {
	u, err := s.GetUpdate(ctx, org, project, stack, updateID)
	if err != nil {
		return err
	}
	if u.Status == status {
		return nil
	}
	if u.Status != "in-progress" && (u.Status != "not-started" || status != "cancelled") {
		return ErrInvalidUpdateState
	}
	u.Status = status
	u.Message = message
	u.ResourceChanges = resourceChanges
	u.EndTime = s.now().Unix()
	err = s.putJSONIfMatch(
		ctx,
		s.updateKey(org, project, stack, u.Incarnation, updateID),
		u,
		u.etag,
	)
	if isPreconditionFailed(err) {
		return ErrConcurrentMutation
	}
	if err != nil {
		return err
	}
	return nil
}

func (s *S3Store) ListUpdates(ctx context.Context, org, project, stack string) ([]Update, error) {
	st, err := s.GetStack(ctx, org, project, stack)
	if err != nil {
		return nil, err
	}
	prefix := s.stackDataPrefix(org, project, stack, st.Incarnation) + "updates/"
	var updates []Update
	paginator := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{
		Bucket: &s.bucket, Prefix: &prefix,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, obj := range page.Contents {
			var u Update
			if err := s.get(ctx, *obj.Key, &u); err != nil {
				return nil, err
			}
			u.Incarnation = st.Incarnation
			updates = append(updates, u)
		}
	}
	sort.Slice(updates, func(i, j int) bool { return updates[i].Version > updates[j].Version })
	return updates, nil
}

func (s *S3Store) AcquireLock(
	ctx context.Context,
	org, project, stack, incarnation, updateID, owner string,
	ttl time.Duration,
) (*Lock, error) {
	for attempt := 0; attempt < 5; attempt++ {
		st, err := s.GetStack(ctx, org, project, stack)
		if err != nil {
			return nil, err
		}
		if st.Incarnation != incarnation {
			return nil, ErrConcurrentMutation
		}
		var legacy *Lock
		if !usesCanonicalLock(st) {
			legacy, err = s.getLegacyLock(ctx, org, project, stack)
			if err != nil && !errors.Is(err, ErrNoLock) {
				return nil, err
			}
		}

		var lock Lock
		switch {
		case st.Lock != nil &&
			deletionFence(st.Lock) &&
			!strings.HasPrefix(updateID, "delete-"):
			current := *st.Lock
			return nil, &LockHeldError{Lock: &current}
		case legacy != nil &&
			deletionFence(legacy) &&
			!strings.HasPrefix(updateID, "delete-"):
			return nil, &LockHeldError{Lock: legacy}
		case st.Lock != nil && !st.Lock.Expired(s.now()):
			if st.Lock.UpdateID != updateID || st.Lock.Owner != owner {
				current := *st.Lock
				return nil, &LockHeldError{Lock: &current}
			}
			lock = *st.Lock
			lock.ExpiresAt = s.now().Add(ttl).UTC()
		case legacy != nil && !legacy.Expired(s.now()):
			if legacy.UpdateID != updateID || legacy.Owner != owner {
				return nil, &LockHeldError{Lock: legacy}
			}
			lock = *legacy
			if lock.Generation == 0 {
				lock.Generation = st.Fence + 1
			}
			lock.ExpiresAt = s.now().Add(ttl).UTC()
		default:
			generation := st.Fence + 1
			if st.Lock != nil && st.Lock.Generation >= generation {
				generation = st.Lock.Generation + 1
			}
			if legacy != nil && legacy.Generation >= generation {
				generation = legacy.Generation + 1
			}
			lock = Lock{
				UpdateID:   updateID,
				Owner:      owner,
				ExpiresAt:  s.now().Add(ttl).UTC(),
				Generation: generation,
			}
		}

		if lock.Generation == 0 {
			lock.Generation = st.Fence + 1
		}
		st.Fence = max(st.Fence, lock.Generation)
		st.LockProtocol = canonicalLockProtocol
		st.Lock = &lock
		err = s.putJSONIfMatch(ctx, s.stackKey(org, project, stack), st, st.etag)
		if err == nil {
			s.deleteLegacyLock(ctx, org, project, stack, legacy)
			return &lock, nil
		}
		if !isPreconditionFailed(err) {
			return nil, err
		}
	}
	return nil, ErrConcurrentMutation
}

func (s *S3Store) RenewLock(
	ctx context.Context,
	org, project, stack, updateID string,
	generation uint64,
	ttl time.Duration,
) (*Lock, error) {
	for attempt := 0; attempt < 5; attempt++ {
		st, err := s.GetStack(ctx, org, project, stack)
		if err != nil {
			return nil, err
		}
		var legacy *Lock
		lock := st.Lock
		if lock == nil && !usesCanonicalLock(st) {
			legacy, err = s.getLegacyLock(ctx, org, project, stack)
			if err != nil {
				return nil, err
			}
			lock = legacy
		}
		if lock == nil {
			return nil, ErrNoLock
		}
		if lock.UpdateID != updateID ||
			(generation != 0 && lock.Generation != generation) {
			current := *lock
			return nil, &LockHeldError{Lock: &current}
		}
		if lock.Expired(s.now()) {
			return nil, ErrNoLock
		}
		renewed := *lock
		if renewed.Generation == 0 {
			renewed.Generation = st.Fence + 1
		}
		renewed.ExpiresAt = s.now().Add(ttl).UTC()
		st.Fence = max(st.Fence, renewed.Generation)
		st.LockProtocol = canonicalLockProtocol
		st.Lock = &renewed
		err = s.putJSONIfMatch(ctx, s.stackKey(org, project, stack), st, st.etag)
		if err == nil {
			s.deleteLegacyLock(ctx, org, project, stack, legacy)
			return &renewed, nil
		}
		if !isPreconditionFailed(err) {
			return nil, err
		}
	}
	return nil, ErrConcurrentMutation
}

func (s *S3Store) ReleaseLock(
	ctx context.Context,
	org, project, stack, updateID string,
	generation uint64,
) error {
	for attempt := 0; attempt < 5; attempt++ {
		st, err := s.GetStack(ctx, org, project, stack)
		if errors.Is(err, ErrStackNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		var legacy *Lock
		lock := st.Lock
		if lock == nil && !usesCanonicalLock(st) {
			legacy, err = s.getLegacyLock(ctx, org, project, stack)
			if errors.Is(err, ErrNoLock) {
				return nil
			}
			if err != nil {
				return err
			}
			lock = legacy
		}
		if lock == nil {
			return nil
		}
		if lock.UpdateID != updateID ||
			(generation != 0 && lock.Generation != generation) {
			current := *lock
			return &LockHeldError{Lock: &current}
		}
		st.Fence = max(st.Fence, lock.Generation)
		st.LockProtocol = canonicalLockProtocol
		st.Lock = nil
		err = s.putJSONIfMatch(ctx, s.stackKey(org, project, stack), st, st.etag)
		if err == nil {
			s.deleteLegacyLock(ctx, org, project, stack, legacy)
			return nil
		}
		if !isPreconditionFailed(err) {
			return err
		}
	}
	return ErrConcurrentMutation
}

func (s *S3Store) GetLock(ctx context.Context, org, project, stack string) (*Lock, error) {
	st, err := s.GetStack(ctx, org, project, stack)
	if err != nil {
		return nil, err
	}
	if st.Lock != nil {
		lock := *st.Lock
		return &lock, nil
	}
	if usesCanonicalLock(st) {
		return nil, ErrNoLock
	}
	return s.getLegacyLock(ctx, org, project, stack)
}

func usesCanonicalLock(st *Stack) bool {
	// Fence and incarnation also identify pre-marker builds that already moved
	// lock authority into stack.json; consulting an orphaned lock.json would regress.
	return st.LockProtocol >= canonicalLockProtocol ||
		st.Incarnation != "" ||
		st.Fence != 0 ||
		st.Lock != nil
}

func (s *S3Store) getLegacyLock(ctx context.Context, org, project, stack string) (*Lock, error) {
	var lock Lock
	etag, err := s.getWithETag(ctx, s.lockKey(org, project, stack), &lock)
	if err != nil {
		if isNotFound(err) {
			return nil, ErrNoLock
		}
		return nil, err
	}
	lock.etag = etag
	return &lock, nil
}

func (s *S3Store) deleteLegacyLock(
	ctx context.Context,
	org, project, stack string,
	lock *Lock,
) {
	if lock == nil || lock.etag == "" {
		return
	}
	err := s.deleteIfMatch(ctx, s.lockKey(org, project, stack), lock.etag)
	if err != nil && !isPreconditionFailed(err) && !isNotFound(err) {
		slog.Warn("canonical lock committed without deleting legacy lock", "error", err)
	}
}
