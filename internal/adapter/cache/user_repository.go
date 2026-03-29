package cache

import (
	"context"
	"strings"
	"sync"

	"github.com/authcore/internal/domain/user"
	apperrors "github.com/authcore/pkg/sdk/errors"
)

// InMemoryUserRepository implements user.Repository.
type InMemoryUserRepository struct {
	mu    sync.Mutex
	users map[string]user.User
}

// NewInMemoryUserRepository creates a new in-memory user repository.
func NewInMemoryUserRepository() *InMemoryUserRepository {
	return &InMemoryUserRepository{users: make(map[string]user.User)}
}

var _ user.Repository = (*InMemoryUserRepository)(nil)

func (r *InMemoryUserRepository) Create(_ context.Context, u user.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check email uniqueness per tenant
	for _, existing := range r.users {
		if existing.TenantID == u.TenantID &&
			strings.EqualFold(existing.Email, u.Email) &&
			existing.DeletedAt == nil {
			return apperrors.New(apperrors.ErrConflict, "email already registered")
		}
	}

	r.users[u.ID] = u
	return nil
}

func (r *InMemoryUserRepository) GetByID(_ context.Context, id, tenantID string) (user.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[id]
	if !ok || u.TenantID != tenantID {
		return user.User{}, apperrors.New(apperrors.ErrNotFound, "user not found")
	}
	return u, nil
}

func (r *InMemoryUserRepository) GetByEmail(_ context.Context, email, tenantID string) (user.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, u := range r.users {
		if u.TenantID == tenantID && strings.EqualFold(u.Email, email) && u.DeletedAt == nil {
			return u, nil
		}
	}
	return user.User{}, apperrors.New(apperrors.ErrNotFound, "user not found")
}

func (r *InMemoryUserRepository) GetByPhone(_ context.Context, phone, tenantID string) (user.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, u := range r.users {
		if u.TenantID == tenantID && u.Phone == phone && u.Phone != "" && u.DeletedAt == nil {
			return u, nil
		}
	}
	return user.User{}, apperrors.New(apperrors.ErrNotFound, "user not found")
}

func (r *InMemoryUserRepository) Update(_ context.Context, u user.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.users[u.ID]; !ok {
		return apperrors.New(apperrors.ErrNotFound, "user not found")
	}
	r.users[u.ID] = u
	return nil
}

func (r *InMemoryUserRepository) Delete(_ context.Context, id, tenantID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[id]
	if !ok || u.TenantID != tenantID {
		return apperrors.New(apperrors.ErrNotFound, "user not found")
	}
	delete(r.users, id)
	return nil
}

func (r *InMemoryUserRepository) HardDelete(_ context.Context, id, tenantID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[id]
	if !ok || u.TenantID != tenantID {
		return apperrors.New(apperrors.ErrNotFound, "user not found")
	}
	delete(r.users, id)
	return nil
}

func (r *InMemoryUserRepository) IncrementTokenVersion(_ context.Context, id, tenantID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[id]
	if !ok || u.TenantID != tenantID {
		return apperrors.New(apperrors.ErrNotFound, "user not found")
	}
	u.TokenVersion++
	r.users[id] = u
	return nil
}
