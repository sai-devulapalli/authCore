package rbac

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRole_Valid(t *testing.T) {
	r, err := NewRole("r1", "t1", "admin", "Full access", []string{"posts:*", "users:*"})
	require.NoError(t, err)
	assert.Equal(t, "r1", r.ID)
	assert.Equal(t, "admin", r.Name)
	assert.Len(t, r.Permissions, 2)
}

func TestNewRole_EmptyID(t *testing.T) {
	_, err := NewRole("", "t1", "admin", "", nil)
	require.Error(t, err)
}

func TestNewRole_EmptyName(t *testing.T) {
	_, err := NewRole("r1", "t1", "", "", nil)
	require.Error(t, err)
}

func TestHasPermission_ExactMatch(t *testing.T) {
	assert.True(t, HasPermission([]string{"posts:read", "posts:write"}, "posts:read"))
	assert.False(t, HasPermission([]string{"posts:read"}, "posts:write"))
}

func TestHasPermission_Wildcard(t *testing.T) {
	assert.True(t, HasPermission([]string{"posts:*"}, "posts:read"))
	assert.True(t, HasPermission([]string{"posts:*"}, "posts:write"))
	assert.True(t, HasPermission([]string{"posts:*"}, "posts:delete"))
	assert.False(t, HasPermission([]string{"posts:*"}, "users:read"))
}

func TestHasPermission_Superadmin(t *testing.T) {
	assert.True(t, HasPermission([]string{"*"}, "anything"))
	assert.True(t, HasPermission([]string{"*"}, "posts:delete"))
	assert.True(t, HasPermission([]string{"*"}, "users:admin"))
}

func TestHasPermission_Empty(t *testing.T) {
	assert.False(t, HasPermission(nil, "posts:read"))
	assert.False(t, HasPermission([]string{}, "posts:read"))
}

func TestFlattenPermissions(t *testing.T) {
	roles := []Role{
		{Permissions: []string{"posts:read", "posts:write"}},
		{Permissions: []string{"posts:read", "users:read"}},
	}
	perms := FlattenPermissions(roles)
	assert.Len(t, perms, 3) // deduplicated
	assert.Contains(t, perms, "posts:read")
	assert.Contains(t, perms, "posts:write")
	assert.Contains(t, perms, "users:read")
}

func TestFlattenPermissions_Empty(t *testing.T) {
	perms := FlattenPermissions(nil)
	assert.Empty(t, perms)
}

func TestValidationError_Error(t *testing.T) {
	err := &ValidationError{Field: "name", Message: "must not be empty"}
	assert.Equal(t, "rbac validation: name must not be empty", err.Error())
}
