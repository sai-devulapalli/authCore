package cache

import (
	"context"
	"testing"

	"github.com/authplex/internal/domain/identity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProviderRepo_CreateAndGetByID(t *testing.T) {
	repo := NewInMemoryProviderRepository()
	ctx := context.Background()
	p, _ := identity.NewIdentityProvider("p1", "t1", identity.ProviderGoogle, "gid", nil, nil)
	require.NoError(t, repo.Create(ctx, p))

	got, err := repo.GetByID(ctx, "p1", "t1")
	require.NoError(t, err)
	assert.Equal(t, "p1", got.ID)
}

func TestProviderRepo_GetByType(t *testing.T) {
	repo := NewInMemoryProviderRepository()
	ctx := context.Background()
	p, _ := identity.NewIdentityProvider("p1", "t1", identity.ProviderGoogle, "gid", nil, nil)
	repo.Create(ctx, p) //nolint:errcheck

	got, err := repo.GetByType(ctx, "t1", identity.ProviderGoogle)
	require.NoError(t, err)
	assert.Equal(t, "p1", got.ID)
}

func TestProviderRepo_GetByType_NotFound(t *testing.T) {
	repo := NewInMemoryProviderRepository()
	_, err := repo.GetByType(context.Background(), "t1", identity.ProviderGitHub)
	require.Error(t, err)
}

func TestProviderRepo_List(t *testing.T) {
	repo := NewInMemoryProviderRepository()
	ctx := context.Background()
	p1, _ := identity.NewIdentityProvider("p1", "t1", identity.ProviderGoogle, "g", nil, nil)
	p2, _ := identity.NewIdentityProvider("p2", "t1", identity.ProviderGitHub, "gh", nil, nil)
	repo.Create(ctx, p1) //nolint:errcheck
	repo.Create(ctx, p2) //nolint:errcheck

	list, err := repo.List(ctx, "t1")
	require.NoError(t, err)
	assert.Len(t, list, 2)
}

func TestProviderRepo_Delete(t *testing.T) {
	repo := NewInMemoryProviderRepository()
	ctx := context.Background()
	p, _ := identity.NewIdentityProvider("p1", "t1", identity.ProviderGoogle, "gid", nil, nil)
	repo.Create(ctx, p) //nolint:errcheck

	require.NoError(t, repo.Delete(ctx, "p1", "t1"))
	_, err := repo.GetByID(ctx, "p1", "t1")
	require.Error(t, err)
}

func TestProviderRepo_Delete_NotFound(t *testing.T) {
	repo := NewInMemoryProviderRepository()
	err := repo.Delete(context.Background(), "x", "t1")
	require.Error(t, err)
}

func TestProviderRepo_Update(t *testing.T) {
	repo := NewInMemoryProviderRepository()
	ctx := context.Background()
	p, _ := identity.NewIdentityProvider("p1", "t1", identity.ProviderGoogle, "gid", nil, nil)
	repo.Create(ctx, p) //nolint:errcheck

	p.ClientID = "new-gid"
	require.NoError(t, repo.Update(ctx, p))
	got, _ := repo.GetByID(ctx, "p1", "t1")
	assert.Equal(t, "new-gid", got.ClientID)
}

func TestProviderRepo_GetByID_NotFound(t *testing.T) {
	repo := NewInMemoryProviderRepository()
	_, err := repo.GetByID(context.Background(), "x", "t1")
	require.Error(t, err)
}
