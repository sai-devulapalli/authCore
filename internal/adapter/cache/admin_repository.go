package cache

import (
	"context"
	"strings"
	"sync"

	"github.com/authplex/internal/domain/admin"
	apperrors "github.com/authplex/pkg/sdk/errors"
)

// InMemoryAdminUserRepository implements admin.AdminUserRepository.
type InMemoryAdminUserRepository struct {
	mu    sync.RWMutex
	users map[string]admin.AdminUser
}

// NewInMemoryAdminUserRepository creates a new in-memory admin user repository.
func NewInMemoryAdminUserRepository() *InMemoryAdminUserRepository {
	return &InMemoryAdminUserRepository{users: make(map[string]admin.AdminUser)}
}

var _ admin.AdminUserRepository = (*InMemoryAdminUserRepository)(nil)

func (r *InMemoryAdminUserRepository) Create(_ context.Context, u admin.AdminUser) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, existing := range r.users {
		if strings.EqualFold(existing.Email, u.Email) {
			return apperrors.New(apperrors.ErrConflict, "admin email already registered")
		}
	}

	r.users[u.ID] = u
	return nil
}

func (r *InMemoryAdminUserRepository) GetByEmail(_ context.Context, email string) (admin.AdminUser, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, u := range r.users {
		if strings.EqualFold(u.Email, email) {
			return u, nil
		}
	}
	return admin.AdminUser{}, apperrors.New(apperrors.ErrNotFound, "admin user not found")
}

func (r *InMemoryAdminUserRepository) GetByID(_ context.Context, id string) (admin.AdminUser, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	u, ok := r.users[id]
	if !ok {
		return admin.AdminUser{}, apperrors.New(apperrors.ErrNotFound, "admin user not found")
	}
	return u, nil
}

func (r *InMemoryAdminUserRepository) List(_ context.Context) ([]admin.AdminUser, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]admin.AdminUser, 0, len(r.users))
	for _, u := range r.users {
		result = append(result, u)
	}
	return result, nil
}

func (r *InMemoryAdminUserRepository) Count(_ context.Context) (int, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.users), nil
}
