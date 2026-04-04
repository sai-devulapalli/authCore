package cache

import (
	"context"
	"testing"

	"github.com/authplex/internal/domain/tenant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTenantRepo_CreateAndGetByID(t *testing.T) {
	repo := NewInMemoryTenantRepository()
	ctx := context.Background()
	tn, _ := tenant.NewTenant("t1", "example.com", "https://example.com", tenant.RS256)
	require.NoError(t, repo.Create(ctx, tn))

	got, err := repo.GetByID(ctx, "t1")
	require.NoError(t, err)
	assert.Equal(t, "t1", got.ID)
}

func TestTenantRepo_GetByDomain(t *testing.T) {
	repo := NewInMemoryTenantRepository()
	ctx := context.Background()
	tn, _ := tenant.NewTenant("t1", "example.com", "https://example.com", tenant.RS256)
	repo.Create(ctx, tn) //nolint:errcheck

	got, err := repo.GetByDomain(ctx, "example.com")
	require.NoError(t, err)
	assert.Equal(t, "t1", got.ID)
}

func TestTenantRepo_Update(t *testing.T) {
	repo := NewInMemoryTenantRepository()
	ctx := context.Background()
	tn, _ := tenant.NewTenant("t1", "old.com", "https://old.com", tenant.RS256)
	repo.Create(ctx, tn) //nolint:errcheck

	tn.Domain = "new.com"
	require.NoError(t, repo.Update(ctx, tn))

	got, _ := repo.GetByID(ctx, "t1")
	assert.Equal(t, "new.com", got.Domain)
}

func TestTenantRepo_Delete(t *testing.T) {
	repo := NewInMemoryTenantRepository()
	ctx := context.Background()
	tn, _ := tenant.NewTenant("t1", "example.com", "https://example.com", tenant.RS256)
	repo.Create(ctx, tn) //nolint:errcheck

	require.NoError(t, repo.Delete(ctx, "t1"))
	_, err := repo.GetByDomain(ctx, "example.com")
	require.Error(t, err)
}

func TestTenantRepo_List(t *testing.T) {
	repo := NewInMemoryTenantRepository()
	ctx := context.Background()
	t1, _ := tenant.NewTenant("t1", "a.com", "https://a.com", tenant.RS256)
	t2, _ := tenant.NewTenant("t2", "b.com", "https://b.com", tenant.RS256)
	repo.Create(ctx, t1) //nolint:errcheck
	repo.Create(ctx, t2) //nolint:errcheck

	tenants, total, err := repo.List(ctx, 0, 10)
	require.NoError(t, err)
	assert.Equal(t, 2, total)
	assert.Len(t, tenants, 2)
}

func TestTenantRepo_GetByID_NotFound(t *testing.T) {
	repo := NewInMemoryTenantRepository()
	_, err := repo.GetByID(context.Background(), "nonexistent")
	require.Error(t, err)
}

func TestTenantRepo_Update_NotFound(t *testing.T) {
	repo := NewInMemoryTenantRepository()
	err := repo.Update(context.Background(), tenant.Tenant{ID: "nonexistent"})
	require.Error(t, err)
}

func TestTenantRepo_Delete_NotFound(t *testing.T) {
	repo := NewInMemoryTenantRepository()
	err := repo.Delete(context.Background(), "nonexistent")
	require.Error(t, err)
}

func TestTenantRepo_IncrementTokenVersion(t *testing.T) {
	repo := NewInMemoryTenantRepository()
	ctx := context.Background()

	tn, _ := tenant.NewTenant("t1", "example.com", "https://example.com", tenant.RS256)
	require.NoError(t, repo.Create(ctx, tn))

	before, _ := repo.GetByID(ctx, "t1")
	require.NoError(t, repo.IncrementTokenVersion(ctx, "t1"))

	after, err := repo.GetByID(ctx, "t1")
	require.NoError(t, err)
	assert.Equal(t, before.TokenVersion+1, after.TokenVersion)
}

func TestTenantRepo_IncrementTokenVersion_NotFound(t *testing.T) {
	repo := NewInMemoryTenantRepository()
	err := repo.IncrementTokenVersion(context.Background(), "nonexistent")
	require.Error(t, err)
}
