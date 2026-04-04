package cache

import (
	"context"
	"testing"
	"time"

	"github.com/authplex/internal/domain/mfa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChallengeRepo_StoreAndGet(t *testing.T) {
	repo := NewInMemoryChallengeRepository()
	ctx := context.Background()

	c := mfa.MFAChallenge{ID: "ch1", Subject: "user-1", ExpiresAt: time.Now().UTC().Add(5 * time.Minute)}
	require.NoError(t, repo.Store(ctx, c))

	got, err := repo.GetByID(ctx, "ch1")
	require.NoError(t, err)
	assert.Equal(t, "user-1", got.Subject)
	assert.False(t, got.Verified)
}

func TestChallengeRepo_MarkVerified(t *testing.T) {
	repo := NewInMemoryChallengeRepository()
	ctx := context.Background()

	c := mfa.MFAChallenge{ID: "ch1", Subject: "user-1"}
	repo.Store(ctx, c) //nolint:errcheck

	require.NoError(t, repo.MarkVerified(ctx, "ch1"))

	got, _ := repo.GetByID(ctx, "ch1")
	assert.True(t, got.Verified)
}

func TestChallengeRepo_Delete(t *testing.T) {
	repo := NewInMemoryChallengeRepository()
	ctx := context.Background()

	c := mfa.MFAChallenge{ID: "ch1"}
	repo.Store(ctx, c) //nolint:errcheck

	require.NoError(t, repo.Delete(ctx, "ch1"))

	_, err := repo.GetByID(ctx, "ch1")
	require.Error(t, err)
}

func TestChallengeRepo_GetNotFound(t *testing.T) {
	repo := NewInMemoryChallengeRepository()
	_, err := repo.GetByID(context.Background(), "nonexistent")
	require.Error(t, err)
}
