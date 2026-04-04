package redis

import (
	"context"
	"encoding/json"
	"time"

	"github.com/authplex/internal/domain/token"
	apperrors "github.com/authplex/pkg/sdk/errors"
	goredis "github.com/redis/go-redis/v9"
)

const codePrefix = "authcode:"

// CodeRepository implements token.CodeRepository using Redis.
type CodeRepository struct {
	rdb *goredis.Client
}

// NewCodeRepository creates a new Redis-backed auth code repository.
func NewCodeRepository(rdb *goredis.Client) *CodeRepository {
	return &CodeRepository{rdb: rdb}
}

var _ token.CodeRepository = (*CodeRepository)(nil)

func (r *CodeRepository) Store(ctx context.Context, code token.AuthorizationCode) error {
	data, err := json.Marshal(code)
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to marshal auth code", err)
	}
	ttl := time.Until(code.ExpiresAt)
	if ttl <= 0 {
		return nil
	}
	return r.rdb.Set(ctx, codePrefix+code.Code, data, ttl).Err()
}

func (r *CodeRepository) Consume(ctx context.Context, code string) (token.AuthorizationCode, error) {
	key := codePrefix + code

	// Atomic get + delete via pipeline
	pipe := r.rdb.Pipeline()
	getCmd := pipe.Get(ctx, key)
	pipe.Del(ctx, key)
	_, _ = pipe.Exec(ctx)

	data, err := getCmd.Bytes()
	if err != nil {
		return token.AuthorizationCode{}, apperrors.New(apperrors.ErrNotFound, "authorization code not found")
	}

	var ac token.AuthorizationCode
	if err := json.Unmarshal(data, &ac); err != nil {
		return token.AuthorizationCode{}, apperrors.Wrap(apperrors.ErrInternal, "failed to unmarshal auth code", err)
	}
	return ac, nil
}
