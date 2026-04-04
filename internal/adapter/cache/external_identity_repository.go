package cache

import (
	"context"
	"sync"

	"github.com/authplex/internal/domain/identity"
	apperrors "github.com/authplex/pkg/sdk/errors"
)

// InMemoryExternalIdentityRepository implements identity.ExternalIdentityRepository.
type InMemoryExternalIdentityRepository struct {
	mu         sync.RWMutex
	identities map[string]identity.ExternalIdentity
}

// NewInMemoryExternalIdentityRepository creates a new in-memory external identity repository.
func NewInMemoryExternalIdentityRepository() *InMemoryExternalIdentityRepository {
	return &InMemoryExternalIdentityRepository{identities: make(map[string]identity.ExternalIdentity)}
}

var _ identity.ExternalIdentityRepository = (*InMemoryExternalIdentityRepository)(nil)

func (r *InMemoryExternalIdentityRepository) Create(_ context.Context, ei identity.ExternalIdentity) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.identities[ei.ID] = ei
	return nil
}

func (r *InMemoryExternalIdentityRepository) GetByExternalSubject(_ context.Context, providerID, externalSubject string) (identity.ExternalIdentity, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, ei := range r.identities {
		if ei.ProviderID == providerID && ei.ExternalSubject == externalSubject {
			return ei, nil
		}
	}
	return identity.ExternalIdentity{}, apperrors.New(apperrors.ErrNotFound, "external identity not found")
}

func (r *InMemoryExternalIdentityRepository) GetByInternalSubject(_ context.Context, tenantID, internalSubject string) ([]identity.ExternalIdentity, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var result []identity.ExternalIdentity
	for _, ei := range r.identities {
		if ei.TenantID == tenantID && ei.InternalSubject == internalSubject {
			result = append(result, ei)
		}
	}
	return result, nil
}

func (r *InMemoryExternalIdentityRepository) Update(_ context.Context, ei identity.ExternalIdentity) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.identities[ei.ID] = ei
	return nil
}
