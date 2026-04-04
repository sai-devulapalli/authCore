package redis

import (
	"context"
	"time"

	"github.com/authplex/internal/domain/token"
	goredis "github.com/redis/go-redis/v9"
)

const blacklistPrefix = "blacklist:"

// TokenBlacklist implements token.TokenBlacklist using Redis.
type TokenBlacklist struct {
	rdb *goredis.Client
}

// NewTokenBlacklist creates a new Redis-backed token blacklist.
func NewTokenBlacklist(rdb *goredis.Client) *TokenBlacklist {
	return &TokenBlacklist{rdb: rdb}
}

var _ token.TokenBlacklist = (*TokenBlacklist)(nil)

func (b *TokenBlacklist) Revoke(ctx context.Context, jti string, expiresAt time.Time) error {
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		return nil
	}
	return b.rdb.Set(ctx, blacklistPrefix+jti, "1", ttl).Err()
}

func (b *TokenBlacklist) IsRevoked(ctx context.Context, jti string) (bool, error) {
	exists, err := b.rdb.Exists(ctx, blacklistPrefix+jti).Result()
	if err != nil {
		return false, err
	}
	return exists > 0, nil
}
