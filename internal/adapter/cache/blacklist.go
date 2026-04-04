package cache

import (
	"context"
	"sync"
	"time"

	"github.com/authplex/internal/domain/token"
)

// InMemoryBlacklist implements token.TokenBlacklist.
type InMemoryBlacklist struct {
	mu      sync.RWMutex
	revoked map[string]time.Time // jti -> expiresAt
}

// NewInMemoryBlacklist creates a new in-memory token blacklist.
func NewInMemoryBlacklist() *InMemoryBlacklist {
	return &InMemoryBlacklist{revoked: make(map[string]time.Time)}
}

var _ token.TokenBlacklist = (*InMemoryBlacklist)(nil)

func (b *InMemoryBlacklist) Revoke(_ context.Context, jti string, expiresAt time.Time) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.revoked[jti] = expiresAt
	return nil
}

func (b *InMemoryBlacklist) IsRevoked(_ context.Context, jti string) (bool, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	_, ok := b.revoked[jti]
	return ok, nil
}
