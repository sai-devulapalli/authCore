package cache

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"sync"
	"time"

	"github.com/authcore/internal/domain/token"
	apperrors "github.com/authcore/pkg/sdk/errors"
)

// hashRefreshToken returns a SHA-256 hash of the token for storage.
// Refresh tokens are stored as hashes so that a database compromise
// does not expose usable tokens.
func hashRefreshToken(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// InMemoryRefreshRepository implements token.RefreshTokenRepository.
type InMemoryRefreshRepository struct {
	mu     sync.Mutex
	tokens map[string]token.RefreshToken
}

// NewInMemoryRefreshRepository creates a new in-memory refresh token repository.
func NewInMemoryRefreshRepository() *InMemoryRefreshRepository {
	return &InMemoryRefreshRepository{tokens: make(map[string]token.RefreshToken)}
}

var _ token.RefreshTokenRepository = (*InMemoryRefreshRepository)(nil)

func (r *InMemoryRefreshRepository) Store(_ context.Context, rt token.RefreshToken) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	// If token already exists as key (re-store after rotation), update in place
	if _, exists := r.tokens[rt.Token]; exists {
		r.tokens[rt.Token] = rt
		return nil
	}
	// New token — hash before storage
	hashed := hashRefreshToken(rt.Token)
	rt.Token = hashed
	r.tokens[hashed] = rt
	return nil
}

func (r *InMemoryRefreshRepository) GetByToken(_ context.Context, tok string) (token.RefreshToken, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	hashed := hashRefreshToken(tok)
	rt, ok := r.tokens[hashed]
	if !ok {
		return token.RefreshToken{}, apperrors.New(apperrors.ErrNotFound, "refresh token not found")
	}
	return rt, nil
}

func (r *InMemoryRefreshRepository) RevokeByToken(_ context.Context, tok string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	hashed := hashRefreshToken(tok)
	rt, ok := r.tokens[hashed]
	if !ok {
		return apperrors.New(apperrors.ErrNotFound, "refresh token not found")
	}
	now := time.Now().UTC()
	rt.RevokedAt = &now
	r.tokens[hashed] = rt
	return nil
}

func (r *InMemoryRefreshRepository) RevokeFamily(_ context.Context, familyID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now().UTC()
	for k, rt := range r.tokens {
		if rt.FamilyID == familyID {
			rt.RevokedAt = &now
			r.tokens[k] = rt
		}
	}
	return nil
}

func (r *InMemoryRefreshRepository) DeleteExpiredAndRevoked(_ context.Context, olderThan time.Time) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var count int64
	for k, rt := range r.tokens {
		if (rt.RevokedAt != nil && rt.RevokedAt.Before(olderThan)) || (!rt.ExpiresAt.IsZero() && rt.ExpiresAt.Before(olderThan)) {
			delete(r.tokens, k)
			count++
		}
	}
	return count, nil
}
