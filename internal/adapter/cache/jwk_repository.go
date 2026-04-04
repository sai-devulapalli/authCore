package cache

import (
	"context"
	"sync"
	"time"

	"github.com/authplex/internal/domain/jwk"
	apperrors "github.com/authplex/pkg/sdk/errors"
)

// InMemoryJWKRepository implements jwk.Repository using an in-memory map.
type InMemoryJWKRepository struct {
	mu   sync.RWMutex
	keys map[string]jwk.KeyPair
}

// NewInMemoryJWKRepository creates a new in-memory JWK repository.
func NewInMemoryJWKRepository() *InMemoryJWKRepository {
	return &InMemoryJWKRepository{keys: make(map[string]jwk.KeyPair)}
}

var _ jwk.Repository = (*InMemoryJWKRepository)(nil)

func (r *InMemoryJWKRepository) Store(_ context.Context, kp jwk.KeyPair) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.keys[kp.ID] = kp
	return nil
}

func (r *InMemoryJWKRepository) GetActive(_ context.Context, tenantID string) (jwk.KeyPair, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, kp := range r.keys {
		if kp.TenantID == tenantID && kp.Active {
			return kp, nil
		}
	}
	return jwk.KeyPair{}, apperrors.New(apperrors.ErrNotFound, "no active key pair")
}

func (r *InMemoryJWKRepository) GetAllPublic(_ context.Context, tenantID string) ([]jwk.KeyPair, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var result []jwk.KeyPair
	for _, kp := range r.keys {
		if kp.TenantID == tenantID {
			result = append(result, kp)
		}
	}
	return result, nil
}

func (r *InMemoryJWKRepository) Deactivate(_ context.Context, keyID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	kp, ok := r.keys[keyID]
	if !ok {
		return apperrors.New(apperrors.ErrNotFound, "key pair not found")
	}
	kp.Active = false
	now := time.Now().UTC()
	kp.ExpiresAt = &now
	r.keys[keyID] = kp
	return nil
}

func (r *InMemoryJWKRepository) GetAllActiveTenantIDs(_ context.Context) ([]string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	seen := make(map[string]bool)
	for _, kp := range r.keys {
		if kp.Active {
			seen[kp.TenantID] = true
		}
	}
	result := make([]string, 0, len(seen))
	for id := range seen {
		result = append(result, id)
	}
	return result, nil
}

func (r *InMemoryJWKRepository) DeleteInactive(_ context.Context, olderThan time.Time) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var count int64
	for id, kp := range r.keys {
		if !kp.Active && kp.ExpiresAt != nil && kp.ExpiresAt.Before(olderThan) {
			delete(r.keys, id)
			count++
		}
	}
	return count, nil
}
