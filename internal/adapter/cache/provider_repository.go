package cache

import (
	"context"
	"sync"

	"github.com/authplex/internal/domain/identity"
	apperrors "github.com/authplex/pkg/sdk/errors"
)

// InMemoryProviderRepository implements identity.ProviderRepository.
type InMemoryProviderRepository struct {
	mu        sync.RWMutex
	providers map[string]identity.IdentityProvider
}

// NewInMemoryProviderRepository creates a new in-memory provider repository.
func NewInMemoryProviderRepository() *InMemoryProviderRepository {
	return &InMemoryProviderRepository{providers: make(map[string]identity.IdentityProvider)}
}

var _ identity.ProviderRepository = (*InMemoryProviderRepository)(nil)

func (r *InMemoryProviderRepository) Create(_ context.Context, p identity.IdentityProvider) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.providers[p.ID] = p
	return nil
}

func (r *InMemoryProviderRepository) GetByID(_ context.Context, id, tenantID string) (identity.IdentityProvider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.providers[id]
	if !ok || p.TenantID != tenantID {
		return identity.IdentityProvider{}, apperrors.New(apperrors.ErrNotFound, "provider not found")
	}
	return p, nil
}

func (r *InMemoryProviderRepository) GetByType(_ context.Context, tenantID string, pt identity.ProviderType) (identity.IdentityProvider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, p := range r.providers {
		if p.TenantID == tenantID && p.ProviderType == pt {
			return p, nil
		}
	}
	return identity.IdentityProvider{}, apperrors.New(apperrors.ErrNotFound, "provider not found")
}

func (r *InMemoryProviderRepository) List(_ context.Context, tenantID string) ([]identity.IdentityProvider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var result []identity.IdentityProvider
	for _, p := range r.providers {
		if p.TenantID == tenantID {
			result = append(result, p)
		}
	}
	return result, nil
}

func (r *InMemoryProviderRepository) Update(_ context.Context, p identity.IdentityProvider) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.providers[p.ID] = p
	return nil
}

func (r *InMemoryProviderRepository) Delete(_ context.Context, id, tenantID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.providers[id]
	if !ok || p.TenantID != tenantID {
		return apperrors.New(apperrors.ErrNotFound, "provider not found")
	}
	delete(r.providers, id)
	return nil
}
