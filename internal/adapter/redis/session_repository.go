package redis

import (
	"context"
	"encoding/json"
	"time"

	"github.com/authplex/internal/domain/user"
	apperrors "github.com/authplex/pkg/sdk/errors"
	goredis "github.com/redis/go-redis/v9"
)

const sessionPrefix = "session:"

// SessionRepository implements user.SessionRepository using Redis.
type SessionRepository struct {
	rdb *goredis.Client
}

// NewSessionRepository creates a new Redis-backed session repository.
func NewSessionRepository(rdb *goredis.Client) *SessionRepository {
	return &SessionRepository{rdb: rdb}
}

var _ user.SessionRepository = (*SessionRepository)(nil)

func (r *SessionRepository) Create(ctx context.Context, s user.Session) error {
	data, err := json.Marshal(s)
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to marshal session", err)
	}
	ttl := time.Until(s.ExpiresAt)
	if ttl <= 0 {
		return nil
	}
	return r.rdb.Set(ctx, sessionPrefix+s.ID, data, ttl).Err()
}

func (r *SessionRepository) GetByID(ctx context.Context, id string) (user.Session, error) {
	data, err := r.rdb.Get(ctx, sessionPrefix+id).Bytes()
	if err != nil {
		return user.Session{}, apperrors.New(apperrors.ErrNotFound, "session not found")
	}
	var s user.Session
	if err := json.Unmarshal(data, &s); err != nil {
		return user.Session{}, apperrors.Wrap(apperrors.ErrInternal, "failed to unmarshal session", err)
	}
	return s, nil
}

func (r *SessionRepository) Delete(ctx context.Context, id string) error {
	return r.rdb.Del(ctx, sessionPrefix+id).Err()
}

func (r *SessionRepository) DeleteByUserID(ctx context.Context, userID string) error {
	// Scan for all sessions by user — uses pattern matching
	// In production, consider a secondary index (user:sessions:userID set)
	iter := r.rdb.Scan(ctx, 0, sessionPrefix+"*", 100).Iterator()
	for iter.Next(ctx) {
		data, err := r.rdb.Get(ctx, iter.Val()).Bytes()
		if err != nil {
			continue
		}
		var s user.Session
		if json.Unmarshal(data, &s) == nil && s.UserID == userID {
			r.rdb.Del(ctx, iter.Val()) //nolint:errcheck
		}
	}
	return nil
}
