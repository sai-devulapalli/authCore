package rbac

import "context"

// RoleRepository is the port interface for role persistence.
type RoleRepository interface {
	Create(ctx context.Context, role Role) error
	GetByID(ctx context.Context, id, tenantID string) (Role, error)
	GetByName(ctx context.Context, name, tenantID string) (Role, error)
	List(ctx context.Context, tenantID string) ([]Role, error)
	Update(ctx context.Context, role Role) error
	Delete(ctx context.Context, id, tenantID string) error
}

// AssignmentRepository is the port interface for user-role assignment persistence.
type AssignmentRepository interface {
	Assign(ctx context.Context, userID, roleID, tenantID string) error
	Revoke(ctx context.Context, userID, roleID, tenantID string) error
	GetUserRoles(ctx context.Context, userID, tenantID string) ([]Role, error)
	GetRoleUsers(ctx context.Context, roleID, tenantID string) ([]string, error)
}
