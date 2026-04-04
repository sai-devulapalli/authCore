package cache

import (
	"context"
	"sync"
	"time"

	"github.com/authplex/internal/domain/tenant"
	apperrors "github.com/authplex/pkg/sdk/errors"
)

// InMemoryTenantRepository implements tenant.Repository using an in-memory map.
type InMemoryTenantRepository struct {
	mu      sync.RWMutex
	tenants map[string]tenant.Tenant
}

// NewInMemoryTenantRepository creates a new in-memory tenant repository.
func NewInMemoryTenantRepository() *InMemoryTenantRepository {
	return &InMemoryTenantRepository{tenants: make(map[string]tenant.Tenant)}
}

var _ tenant.Repository = (*InMemoryTenantRepository)(nil)

func (r *InMemoryTenantRepository) GetByID(_ context.Context, id string) (tenant.Tenant, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.tenants[id]
	if !ok {
		return tenant.Tenant{}, apperrors.New(apperrors.ErrNotFound, "tenant not found")
	}
	return t, nil
}

func (r *InMemoryTenantRepository) GetByDomain(_ context.Context, domain string) (tenant.Tenant, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, t := range r.tenants {
		if t.Domain == domain && t.DeletedAt == nil {
			return t, nil
		}
	}
	return tenant.Tenant{}, apperrors.New(apperrors.ErrNotFound, "tenant not found")
}

func (r *InMemoryTenantRepository) Create(_ context.Context, t tenant.Tenant) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tenants[t.ID] = t
	return nil
}

func (r *InMemoryTenantRepository) Update(_ context.Context, t tenant.Tenant) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.tenants[t.ID]; !ok {
		return apperrors.New(apperrors.ErrNotFound, "tenant not found")
	}
	r.tenants[t.ID] = t
	return nil
}

func (r *InMemoryTenantRepository) Delete(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.tenants[id]
	if !ok {
		return apperrors.New(apperrors.ErrNotFound, "tenant not found")
	}
	now := time.Now().UTC()
	t.DeletedAt = &now
	r.tenants[id] = t
	return nil
}

func (r *InMemoryTenantRepository) IncrementTokenVersion(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.tenants[id]
	if !ok {
		return apperrors.New(apperrors.ErrNotFound, "tenant not found")
	}
	t.TokenVersion++
	r.tenants[id] = t
	return nil
}

func (r *InMemoryTenantRepository) List(_ context.Context, offset, limit int) ([]tenant.Tenant, int, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var active []tenant.Tenant
	for _, t := range r.tenants {
		if t.DeletedAt == nil {
			active = append(active, t)
		}
	}
	total := len(active)
	if offset >= total {
		return nil, total, nil
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return active[offset:end], total, nil
}
