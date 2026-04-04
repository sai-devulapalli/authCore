package cache

import (
	"context"
	"testing"

	"github.com/authplex/internal/domain/admin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAdminRepo_CreateAndGetByEmail(t *testing.T) {
	repo := NewInMemoryAdminUserRepository()
	ctx := context.Background()

	u := admin.AdminUser{ID: "a1", Email: "admin@example.com", Role: admin.RoleSuperAdmin}
	require.NoError(t, repo.Create(ctx, u))

	got, err := repo.GetByEmail(ctx, "admin@example.com")
	require.NoError(t, err)
	assert.Equal(t, "a1", got.ID)
	assert.Equal(t, admin.RoleSuperAdmin, got.Role)
}

func TestAdminRepo_DuplicateEmail(t *testing.T) {
	repo := NewInMemoryAdminUserRepository()
	ctx := context.Background()

	u1 := admin.AdminUser{ID: "a1", Email: "admin@example.com", Role: admin.RoleSuperAdmin}
	require.NoError(t, repo.Create(ctx, u1))

	u2 := admin.AdminUser{ID: "a2", Email: "admin@example.com", Role: admin.RoleTenantAdmin}
	err := repo.Create(ctx, u2)
	require.Error(t, err)
}

func TestAdminRepo_GetByEmail_NotFound(t *testing.T) {
	repo := NewInMemoryAdminUserRepository()
	_, err := repo.GetByEmail(context.Background(), "nobody@example.com")
	require.Error(t, err)
}

func TestAdminRepo_GetByID(t *testing.T) {
	repo := NewInMemoryAdminUserRepository()
	ctx := context.Background()

	u := admin.AdminUser{ID: "a1", Email: "admin@example.com", Role: admin.RoleSuperAdmin}
	require.NoError(t, repo.Create(ctx, u))

	got, err := repo.GetByID(ctx, "a1")
	require.NoError(t, err)
	assert.Equal(t, "admin@example.com", got.Email)
}

func TestAdminRepo_GetByID_NotFound(t *testing.T) {
	repo := NewInMemoryAdminUserRepository()
	_, err := repo.GetByID(context.Background(), "nonexistent")
	require.Error(t, err)
}

func TestAdminRepo_List(t *testing.T) {
	repo := NewInMemoryAdminUserRepository()
	ctx := context.Background()

	u1 := admin.AdminUser{ID: "a1", Email: "admin1@example.com", Role: admin.RoleSuperAdmin}
	u2 := admin.AdminUser{ID: "a2", Email: "admin2@example.com", Role: admin.RoleTenantAdmin}
	require.NoError(t, repo.Create(ctx, u1))
	require.NoError(t, repo.Create(ctx, u2))

	list, err := repo.List(ctx)
	require.NoError(t, err)
	assert.Len(t, list, 2)
}

func TestAdminRepo_Count(t *testing.T) {
	repo := NewInMemoryAdminUserRepository()
	ctx := context.Background()

	count, err := repo.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, count)

	u := admin.AdminUser{ID: "a1", Email: "admin@example.com", Role: admin.RoleSuperAdmin}
	require.NoError(t, repo.Create(ctx, u))

	count, err = repo.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}
