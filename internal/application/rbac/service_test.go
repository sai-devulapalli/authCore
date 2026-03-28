package rbac

import (
	"context"
	"log/slog"
	"testing"

	"github.com/authcore/internal/adapter/cache"
	apperrors "github.com/authcore/pkg/sdk/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestService() *Service {
	roleRepo := cache.NewInMemoryRoleRepository()
	assignRepo := cache.NewInMemoryAssignmentRepository(roleRepo)
	return NewService(roleRepo, assignRepo, slog.Default())
}

func TestCreateRole(t *testing.T) {
	svc := newTestService()
	resp, appErr := svc.CreateRole(context.Background(), CreateRoleRequest{
		Name: "admin", Description: "Full access", Permissions: []string{"posts:*", "users:*"}, TenantID: "t1",
	})
	require.Nil(t, appErr)
	assert.NotEmpty(t, resp.ID)
	assert.Equal(t, "admin", resp.Name)
	assert.Len(t, resp.Permissions, 2)
}

func TestCreateRole_EmptyName(t *testing.T) {
	svc := newTestService()
	_, appErr := svc.CreateRole(context.Background(), CreateRoleRequest{TenantID: "t1"})
	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrBadRequest, appErr.Code)
}

func TestListRoles(t *testing.T) {
	svc := newTestService()
	svc.CreateRole(context.Background(), CreateRoleRequest{Name: "admin", TenantID: "t1"})
	svc.CreateRole(context.Background(), CreateRoleRequest{Name: "editor", TenantID: "t1"})

	roles, appErr := svc.ListRoles(context.Background(), "t1")
	require.Nil(t, appErr)
	assert.Len(t, roles, 2)
}

func TestAssignAndGetRoles(t *testing.T) {
	svc := newTestService()
	role, _ := svc.CreateRole(context.Background(), CreateRoleRequest{
		Name: "admin", Permissions: []string{"posts:*"}, TenantID: "t1",
	})

	appErr := svc.AssignRole(context.Background(), "user-1", role.ID, "t1")
	require.Nil(t, appErr)

	roles, appErr := svc.GetUserRoles(context.Background(), "user-1", "t1")
	require.Nil(t, appErr)
	assert.Len(t, roles, 1)
	assert.Equal(t, "admin", roles[0].Name)
}

func TestGetUserPermissions(t *testing.T) {
	svc := newTestService()
	r1, _ := svc.CreateRole(context.Background(), CreateRoleRequest{
		Name: "editor", Permissions: []string{"posts:read", "posts:write"}, TenantID: "t1",
	})
	r2, _ := svc.CreateRole(context.Background(), CreateRoleRequest{
		Name: "commenter", Permissions: []string{"posts:read", "comments:write"}, TenantID: "t1",
	})

	svc.AssignRole(context.Background(), "user-1", r1.ID, "t1")
	svc.AssignRole(context.Background(), "user-1", r2.ID, "t1")

	perms, appErr := svc.GetUserPermissions(context.Background(), "user-1", "t1")
	require.Nil(t, appErr)
	assert.Len(t, perms, 3) // deduplicated: posts:read, posts:write, comments:write
}

func TestRevokeRole(t *testing.T) {
	svc := newTestService()
	role, _ := svc.CreateRole(context.Background(), CreateRoleRequest{
		Name: "admin", TenantID: "t1",
	})
	svc.AssignRole(context.Background(), "user-1", role.ID, "t1")

	appErr := svc.RevokeRole(context.Background(), "user-1", role.ID, "t1")
	require.Nil(t, appErr)

	roles, _ := svc.GetUserRoles(context.Background(), "user-1", "t1")
	assert.Empty(t, roles)
}

func TestDeleteRole(t *testing.T) {
	svc := newTestService()
	role, _ := svc.CreateRole(context.Background(), CreateRoleRequest{
		Name: "admin", TenantID: "t1",
	})

	appErr := svc.DeleteRole(context.Background(), role.ID, "t1")
	require.Nil(t, appErr)

	_, appErr = svc.GetRole(context.Background(), role.ID, "t1")
	require.NotNil(t, appErr)
}

func TestUpdateRole(t *testing.T) {
	svc := newTestService()
	role, _ := svc.CreateRole(context.Background(), CreateRoleRequest{
		Name: "editor", Permissions: []string{"posts:read"}, TenantID: "t1",
	})

	updated, appErr := svc.UpdateRole(context.Background(), role.ID, UpdateRoleRequest{
		Permissions: []string{"posts:read", "posts:write"}, TenantID: "t1",
	})
	require.Nil(t, appErr)
	assert.Len(t, updated.Permissions, 2)
}
