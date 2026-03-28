package rbac

import (
	"fmt"
	"strings"
	"time"
)

// Role represents a named set of permissions within a tenant.
type Role struct {
	ID          string
	TenantID    string
	Name        string
	Description string
	Permissions []string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// NewRole creates a validated Role.
func NewRole(id, tenantID, name, description string, permissions []string) (Role, error) {
	if id == "" {
		return Role{}, &ValidationError{Field: "id", Message: "must not be empty"}
	}
	if tenantID == "" {
		return Role{}, &ValidationError{Field: "tenant_id", Message: "must not be empty"}
	}
	if name == "" {
		return Role{}, &ValidationError{Field: "name", Message: "must not be empty"}
	}

	now := time.Now().UTC()
	return Role{
		ID:          id,
		TenantID:    tenantID,
		Name:        name,
		Description: description,
		Permissions: permissions,
		CreatedAt:   now,
		UpdatedAt:   now,
	}, nil
}

// UserRoleAssignment links a user to a role.
type UserRoleAssignment struct {
	UserID     string
	RoleID     string
	TenantID   string
	AssignedAt time.Time
}

// HasPermission checks if a permission is granted, supporting wildcards.
// "posts:*" matches "posts:read", "posts:write", etc.
// "*" matches everything.
func HasPermission(userPerms []string, required string) bool {
	for _, p := range userPerms {
		if p == "*" || p == required {
			return true
		}
		if strings.HasSuffix(p, ":*") {
			prefix := strings.TrimSuffix(p, ":*")
			if strings.HasPrefix(required, prefix+":") {
				return true
			}
		}
	}
	return false
}

// FlattenPermissions merges permissions from multiple roles, deduplicating.
func FlattenPermissions(roles []Role) []string {
	seen := make(map[string]bool)
	var result []string
	for _, r := range roles {
		for _, p := range r.Permissions {
			if !seen[p] {
				seen[p] = true
				result = append(result, p)
			}
		}
	}
	return result
}

// ValidationError is returned when an RBAC field fails validation.
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("rbac validation: %s %s", e.Field, e.Message)
}
