package rbac

import "github.com/authcore/internal/domain/rbac"

// CreateRoleRequest is the DTO for creating a role.
type CreateRoleRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
	TenantID    string   `json:"-"`
}

// UpdateRoleRequest is the DTO for updating a role.
type UpdateRoleRequest struct {
	Description string   `json:"description,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	TenantID    string   `json:"-"`
}

// RoleResponse is returned to the caller.
type RoleResponse struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
}

// AssignRoleRequest is the DTO for assigning a role.
type AssignRoleRequest struct {
	RoleID string `json:"role_id"`
}

func toRoleResponse(r rbac.Role) RoleResponse {
	return RoleResponse{
		ID:          r.ID,
		Name:        r.Name,
		Description: r.Description,
		Permissions: r.Permissions,
	}
}
