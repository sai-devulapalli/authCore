package redis

import (
	"context"
	"encoding/json"
	"time"

	"github.com/authplex/internal/domain/identity"
	apperrors "github.com/authplex/pkg/sdk/errors"
	goredis "github.com/redis/go-redis/v9"
)

const statePrefix = "oauthstate:"

// StateRepository implements identity.StateRepository using Redis.
type StateRepository struct {
	rdb *goredis.Client
}

// NewStateRepository creates a new Redis-backed OAuth state repository.
func NewStateRepository(rdb *goredis.Client) *StateRepository {
	return &StateRepository{rdb: rdb}
}

var _ identity.StateRepository = (*StateRepository)(nil)

func (r *StateRepository) Store(ctx context.Context, s identity.OAuthState) error {
	data, err := json.Marshal(s)
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to marshal state", err)
	}
	ttl := time.Until(s.ExpiresAt)
	if ttl <= 0 {
		return nil
	}
	return r.rdb.Set(ctx, statePrefix+s.State, data, ttl).Err()
}

func (r *StateRepository) Consume(ctx context.Context, state string) (identity.OAuthState, error) {
	key := statePrefix + state

	pipe := r.rdb.Pipeline()
	getCmd := pipe.Get(ctx, key)
	pipe.Del(ctx, key)
	_, _ = pipe.Exec(ctx)

	data, err := getCmd.Bytes()
	if err != nil {
		return identity.OAuthState{}, apperrors.New(apperrors.ErrNotFound, "state not found")
	}

	var s identity.OAuthState
	if err := json.Unmarshal(data, &s); err != nil {
		return identity.OAuthState{}, apperrors.Wrap(apperrors.ErrInternal, "failed to unmarshal state", err)
	}

	if s.IsExpired() {
		return identity.OAuthState{}, apperrors.New(apperrors.ErrBadRequest, "state has expired")
	}
	return s, nil
}
