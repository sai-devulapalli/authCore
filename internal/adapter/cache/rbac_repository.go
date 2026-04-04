package cache

import (
	"context"
	"sync"
	"time"

	"github.com/authplex/internal/domain/rbac"
	apperrors "github.com/authplex/pkg/sdk/errors"
)

// InMemoryRoleRepository implements rbac.RoleRepository.
type InMemoryRoleRepository struct {
	mu    sync.RWMutex
	roles map[string]rbac.Role
}

func NewInMemoryRoleRepository() *InMemoryRoleRepository {
	return &InMemoryRoleRepository{roles: make(map[string]rbac.Role)}
}

var _ rbac.RoleRepository = (*InMemoryRoleRepository)(nil)

func (r *InMemoryRoleRepository) Create(_ context.Context, role rbac.Role) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.roles[role.ID] = role
	return nil
}

func (r *InMemoryRoleRepository) GetByID(_ context.Context, id, tenantID string) (rbac.Role, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	role, ok := r.roles[id]
	if !ok || role.TenantID != tenantID {
		return rbac.Role{}, apperrors.New(apperrors.ErrNotFound, "role not found")
	}
	return role, nil
}

func (r *InMemoryRoleRepository) GetByName(_ context.Context, name, tenantID string) (rbac.Role, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, role := range r.roles {
		if role.TenantID == tenantID && role.Name == name {
			return role, nil
		}
	}
	return rbac.Role{}, apperrors.New(apperrors.ErrNotFound, "role not found")
}

func (r *InMemoryRoleRepository) List(_ context.Context, tenantID string) ([]rbac.Role, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var result []rbac.Role
	for _, role := range r.roles {
		if role.TenantID == tenantID {
			result = append(result, role)
		}
	}
	return result, nil
}

func (r *InMemoryRoleRepository) Update(_ context.Context, role rbac.Role) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.roles[role.ID]; !ok {
		return apperrors.New(apperrors.ErrNotFound, "role not found")
	}
	role.UpdatedAt = time.Now().UTC()
	r.roles[role.ID] = role
	return nil
}

func (r *InMemoryRoleRepository) Delete(_ context.Context, id, tenantID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	role, ok := r.roles[id]
	if !ok || role.TenantID != tenantID {
		return apperrors.New(apperrors.ErrNotFound, "role not found")
	}
	delete(r.roles, id)
	return nil
}

// InMemoryAssignmentRepository implements rbac.AssignmentRepository.
type InMemoryAssignmentRepository struct {
	mu          sync.RWMutex
	assignments []rbac.UserRoleAssignment
	roleRepo    rbac.RoleRepository
}

func NewInMemoryAssignmentRepository(roleRepo rbac.RoleRepository) *InMemoryAssignmentRepository {
	return &InMemoryAssignmentRepository{roleRepo: roleRepo}
}

var _ rbac.AssignmentRepository = (*InMemoryAssignmentRepository)(nil)

func (r *InMemoryAssignmentRepository) Assign(_ context.Context, userID, roleID, tenantID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, a := range r.assignments {
		if a.UserID == userID && a.RoleID == roleID && a.TenantID == tenantID {
			return apperrors.New(apperrors.ErrConflict, "role already assigned")
		}
	}
	r.assignments = append(r.assignments, rbac.UserRoleAssignment{
		UserID: userID, RoleID: roleID, TenantID: tenantID, AssignedAt: time.Now().UTC(),
	})
	return nil
}

func (r *InMemoryAssignmentRepository) Revoke(_ context.Context, userID, roleID, tenantID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, a := range r.assignments {
		if a.UserID == userID && a.RoleID == roleID && a.TenantID == tenantID {
			r.assignments = append(r.assignments[:i], r.assignments[i+1:]...)
			return nil
		}
	}
	return apperrors.New(apperrors.ErrNotFound, "assignment not found")
}

func (r *InMemoryAssignmentRepository) GetUserRoles(ctx context.Context, userID, tenantID string) ([]rbac.Role, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var roles []rbac.Role
	for _, a := range r.assignments {
		if a.UserID == userID && a.TenantID == tenantID {
			role, err := r.roleRepo.GetByID(ctx, a.RoleID, tenantID)
			if err == nil {
				roles = append(roles, role)
			}
		}
	}
	return roles, nil
}

func (r *InMemoryAssignmentRepository) GetRoleUsers(_ context.Context, roleID, tenantID string) ([]string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var users []string
	for _, a := range r.assignments {
		if a.RoleID == roleID && a.TenantID == tenantID {
			users = append(users, a.UserID)
		}
	}
	return users, nil
}
