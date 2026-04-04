package cache

import (
	"context"
	"testing"
	"time"

	"github.com/authplex/internal/domain/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRefreshRepo_StoreAndGet(t *testing.T) {
	repo := NewInMemoryRefreshRepository()
	ctx := context.Background()

	rt := token.RefreshToken{
		Token:    "rt-123",
		ClientID: "c1",
		Subject:  "user-1",
		FamilyID: "fam-1",
	}
	require.NoError(t, repo.Store(ctx, rt))

	got, err := repo.GetByToken(ctx, "rt-123")
	require.NoError(t, err)
	assert.Equal(t, "c1", got.ClientID)
	assert.Equal(t, "fam-1", got.FamilyID)
}

func TestRefreshRepo_GetNotFound(t *testing.T) {
	repo := NewInMemoryRefreshRepository()
	_, err := repo.GetByToken(context.Background(), "nonexistent")
	require.Error(t, err)
}

func TestRefreshRepo_RevokeByToken(t *testing.T) {
	repo := NewInMemoryRefreshRepository()
	ctx := context.Background()

	rt := token.RefreshToken{Token: "rt-123"}
	repo.Store(ctx, rt) //nolint:errcheck

	require.NoError(t, repo.RevokeByToken(ctx, "rt-123"))

	got, _ := repo.GetByToken(ctx, "rt-123")
	assert.True(t, got.IsRevoked())
}

func TestRefreshRepo_RevokeFamily(t *testing.T) {
	repo := NewInMemoryRefreshRepository()
	ctx := context.Background()

	repo.Store(ctx, token.RefreshToken{Token: "rt-1", FamilyID: "fam-1"}) //nolint:errcheck
	repo.Store(ctx, token.RefreshToken{Token: "rt-2", FamilyID: "fam-1"}) //nolint:errcheck
	repo.Store(ctx, token.RefreshToken{Token: "rt-3", FamilyID: "fam-2"}) //nolint:errcheck

	require.NoError(t, repo.RevokeFamily(ctx, "fam-1"))

	rt1, _ := repo.GetByToken(ctx, "rt-1")
	assert.True(t, rt1.IsRevoked())
	rt2, _ := repo.GetByToken(ctx, "rt-2")
	assert.True(t, rt2.IsRevoked())
	rt3, _ := repo.GetByToken(ctx, "rt-3")
	assert.False(t, rt3.IsRevoked())
}

func TestRefreshRepo_DeleteExpiredAndRevoked(t *testing.T) {
	repo := NewInMemoryRefreshRepository()
	ctx := context.Background()

	past := time.Now().UTC().Add(-48 * time.Hour)
	future := time.Now().UTC().Add(48 * time.Hour)
	oldRevoke := time.Now().UTC().Add(-72 * time.Hour)

	// Expired token
	repo.Store(ctx, token.RefreshToken{Token: "expired", ExpiresAt: past, FamilyID: "f1"}) //nolint:errcheck
	// Active token
	repo.Store(ctx, token.RefreshToken{Token: "active", ExpiresAt: future, FamilyID: "f2"}) //nolint:errcheck
	// Old revoked token (revoked 72 hours ago — manually set RevokedAt)
	rt := token.RefreshToken{Token: "revoked-old", ExpiresAt: future, FamilyID: "f3", RevokedAt: &oldRevoke}
	repo.Store(ctx, rt) //nolint:errcheck

	cutoff := time.Now().UTC().Add(-24 * time.Hour) // older than 24 hours
	count, err := repo.DeleteExpiredAndRevoked(ctx, cutoff)
	require.NoError(t, err)
	assert.Equal(t, int64(2), count) // expired + old revoked

	_, err = repo.GetByToken(ctx, "expired")
	assert.Error(t, err, "expired token should be deleted")

	_, err = repo.GetByToken(ctx, "revoked-old")
	assert.Error(t, err, "old revoked token should be deleted")

	_, err = repo.GetByToken(ctx, "active")
	assert.NoError(t, err, "active token should remain")
}
