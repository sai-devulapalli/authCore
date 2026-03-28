package cache

import (
	"context"
	"testing"

	"github.com/authcore/internal/domain/rbac"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRoleRepo_CreateAndGet(t *testing.T) {
	repo := NewInMemoryRoleRepository()
	ctx := context.Background()

	r, _ := rbac.NewRole("r1", "t1", "admin", "Full access", []string{"posts:*"})
	require.NoError(t, repo.Create(ctx, r))

	got, err := repo.GetByID(ctx, "r1", "t1")
	require.NoError(t, err)
	assert.Equal(t, "admin", got.Name)
}

func TestRoleRepo_GetByName(t *testing.T) {
	repo := NewInMemoryRoleRepository()
	ctx := context.Background()

	r, _ := rbac.NewRole("r1", "t1", "editor", "Edit stuff", []string{"posts:write"})
	repo.Create(ctx, r) //nolint:errcheck

	got, err := repo.GetByName(ctx, "editor", "t1")
	require.NoError(t, err)
	assert.Equal(t, "r1", got.ID)
}

func TestRoleRepo_List(t *testing.T) {
	repo := NewInMemoryRoleRepository()
	ctx := context.Background()

	r1, _ := rbac.NewRole("r1", "t1", "admin", "", nil)
	r2, _ := rbac.NewRole("r2", "t1", "editor", "", nil)
	repo.Create(ctx, r1) //nolint:errcheck
	repo.Create(ctx, r2) //nolint:errcheck

	roles, err := repo.List(ctx, "t1")
	require.NoError(t, err)
	assert.Len(t, roles, 2)
}

func TestRoleRepo_Update(t *testing.T) {
	repo := NewInMemoryRoleRepository()
	ctx := context.Background()

	r, _ := rbac.NewRole("r1", "t1", "editor", "Edit", []string{"posts:read"})
	repo.Create(ctx, r) //nolint:errcheck

	r.Permissions = []string{"posts:read", "posts:write"}
	require.NoError(t, repo.Update(ctx, r))

	got, _ := repo.GetByID(ctx, "r1", "t1")
	assert.Len(t, got.Permissions, 2)
}

func TestRoleRepo_Update_NotFound(t *testing.T) {
	repo := NewInMemoryRoleRepository()
	r, _ := rbac.NewRole("nonexistent", "t1", "x", "", nil)
	err := repo.Update(context.Background(), r)
	require.Error(t, err)
}

func TestRoleRepo_GetByName_NotFound(t *testing.T) {
	repo := NewInMemoryRoleRepository()
	_, err := repo.GetByName(context.Background(), "nonexistent", "t1")
	require.Error(t, err)
}

func TestRoleRepo_Delete(t *testing.T) {
	repo := NewInMemoryRoleRepository()
	ctx := context.Background()

	r, _ := rbac.NewRole("r1", "t1", "admin", "", nil)
	repo.Create(ctx, r) //nolint:errcheck

	require.NoError(t, repo.Delete(ctx, "r1", "t1"))
	_, err := repo.GetByID(ctx, "r1", "t1")
	require.Error(t, err)
}

func TestAssignmentRepo_AssignAndGetRoles(t *testing.T) {
	roleRepo := NewInMemoryRoleRepository()
	assignRepo := NewInMemoryAssignmentRepository(roleRepo)
	ctx := context.Background()

	r, _ := rbac.NewRole("r1", "t1", "admin", "", []string{"posts:*"})
	roleRepo.Create(ctx, r) //nolint:errcheck

	require.NoError(t, assignRepo.Assign(ctx, "u1", "r1", "t1"))

	roles, err := assignRepo.GetUserRoles(ctx, "u1", "t1")
	require.NoError(t, err)
	assert.Len(t, roles, 1)
	assert.Equal(t, "admin", roles[0].Name)
}

func TestAssignmentRepo_Revoke(t *testing.T) {
	roleRepo := NewInMemoryRoleRepository()
	assignRepo := NewInMemoryAssignmentRepository(roleRepo)
	ctx := context.Background()

	r, _ := rbac.NewRole("r1", "t1", "admin", "", nil)
	roleRepo.Create(ctx, r) //nolint:errcheck
	assignRepo.Assign(ctx, "u1", "r1", "t1") //nolint:errcheck

	require.NoError(t, assignRepo.Revoke(ctx, "u1", "r1", "t1"))

	roles, _ := assignRepo.GetUserRoles(ctx, "u1", "t1")
	assert.Empty(t, roles)
}

func TestAssignmentRepo_DuplicateAssign(t *testing.T) {
	roleRepo := NewInMemoryRoleRepository()
	assignRepo := NewInMemoryAssignmentRepository(roleRepo)
	ctx := context.Background()

	r, _ := rbac.NewRole("r1", "t1", "admin", "", nil)
	roleRepo.Create(ctx, r) //nolint:errcheck
	assignRepo.Assign(ctx, "u1", "r1", "t1") //nolint:errcheck

	err := assignRepo.Assign(ctx, "u1", "r1", "t1")
	require.Error(t, err)
}

func TestAssignmentRepo_GetRoleUsers(t *testing.T) {
	roleRepo := NewInMemoryRoleRepository()
	assignRepo := NewInMemoryAssignmentRepository(roleRepo)
	ctx := context.Background()

	r, _ := rbac.NewRole("r1", "t1", "admin", "", nil)
	roleRepo.Create(ctx, r) //nolint:errcheck
	assignRepo.Assign(ctx, "u1", "r1", "t1") //nolint:errcheck
	assignRepo.Assign(ctx, "u2", "r1", "t1") //nolint:errcheck

	users, err := assignRepo.GetRoleUsers(ctx, "r1", "t1")
	require.NoError(t, err)
	assert.Len(t, users, 2)
}
