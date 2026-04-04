package cache

import (
	"context"
	"testing"

	"github.com/authplex/internal/domain/identity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExternalIdentityRepo_CreateAndGet(t *testing.T) {
	repo := NewInMemoryExternalIdentityRepository()
	ctx := context.Background()
	ei, _ := identity.NewExternalIdentity("ei1", "p1", "ext-sub", "int-sub", "t1")
	require.NoError(t, repo.Create(ctx, ei))

	got, err := repo.GetByExternalSubject(ctx, "p1", "ext-sub")
	require.NoError(t, err)
	assert.Equal(t, "int-sub", got.InternalSubject)
}

func TestExternalIdentityRepo_GetByExternalSubject_NotFound(t *testing.T) {
	repo := NewInMemoryExternalIdentityRepository()
	_, err := repo.GetByExternalSubject(context.Background(), "p1", "nonexistent")
	require.Error(t, err)
}

func TestExternalIdentityRepo_GetByInternalSubject(t *testing.T) {
	repo := NewInMemoryExternalIdentityRepository()
	ctx := context.Background()
	ei, _ := identity.NewExternalIdentity("ei1", "p1", "ext", "int-sub", "t1")
	repo.Create(ctx, ei) //nolint:errcheck

	list, err := repo.GetByInternalSubject(ctx, "t1", "int-sub")
	require.NoError(t, err)
	assert.Len(t, list, 1)
}

func TestExternalIdentityRepo_Update(t *testing.T) {
	repo := NewInMemoryExternalIdentityRepository()
	ctx := context.Background()
	ei, _ := identity.NewExternalIdentity("ei1", "p1", "ext", "int", "t1")
	repo.Create(ctx, ei) //nolint:errcheck

	ei.Email = "updated@example.com"
	require.NoError(t, repo.Update(ctx, ei))

	got, _ := repo.GetByExternalSubject(ctx, "p1", "ext")
	assert.Equal(t, "updated@example.com", got.Email)
}
