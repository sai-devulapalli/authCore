package cache

import (
	"context"
	"testing"
	"time"

	"github.com/authplex/internal/domain/user"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSessionRepo_CreateAndGet(t *testing.T) {
	repo := NewInMemorySessionRepository()
	ctx := context.Background()

	s, _ := user.NewSession("sess-1", "user-1", "t1", 24*time.Hour)
	require.NoError(t, repo.Create(ctx, s))

	got, err := repo.GetByID(ctx, "sess-1")
	require.NoError(t, err)
	assert.Equal(t, "user-1", got.UserID)
}

func TestSessionRepo_GetNotFound(t *testing.T) {
	repo := NewInMemorySessionRepository()
	_, err := repo.GetByID(context.Background(), "nonexistent")
	require.Error(t, err)
}

func TestSessionRepo_Delete(t *testing.T) {
	repo := NewInMemorySessionRepository()
	ctx := context.Background()

	s, _ := user.NewSession("sess-1", "user-1", "t1", time.Hour)
	repo.Create(ctx, s) //nolint:errcheck

	require.NoError(t, repo.Delete(ctx, "sess-1"))

	_, err := repo.GetByID(ctx, "sess-1")
	require.Error(t, err)
}

func TestSessionRepo_DeleteByUserID(t *testing.T) {
	repo := NewInMemorySessionRepository()
	ctx := context.Background()

	s1, _ := user.NewSession("sess-1", "user-1", "t1", time.Hour)
	s2, _ := user.NewSession("sess-2", "user-1", "t1", time.Hour)
	s3, _ := user.NewSession("sess-3", "user-2", "t1", time.Hour)
	repo.Create(ctx, s1) //nolint:errcheck
	repo.Create(ctx, s2) //nolint:errcheck
	repo.Create(ctx, s3) //nolint:errcheck

	require.NoError(t, repo.DeleteByUserID(ctx, "user-1"))

	_, err := repo.GetByID(ctx, "sess-1")
	require.Error(t, err)
	_, err = repo.GetByID(ctx, "sess-2")
	require.Error(t, err)

	// user-2's session should still exist
	got, err := repo.GetByID(ctx, "sess-3")
	require.NoError(t, err)
	assert.Equal(t, "user-2", got.UserID)
}
