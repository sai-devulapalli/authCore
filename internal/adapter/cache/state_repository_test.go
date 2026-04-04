package cache

import (
	"context"
	"testing"
	"time"

	"github.com/authplex/internal/domain/identity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStateRepo_StoreAndConsume(t *testing.T) {
	repo := NewInMemoryStateRepository()
	ctx := context.Background()

	state := identity.OAuthState{
		State:     "state-123",
		TenantID:  "t1",
		ExpiresAt: time.Now().UTC().Add(10 * time.Minute),
	}
	require.NoError(t, repo.Store(ctx, state))

	consumed, err := repo.Consume(ctx, "state-123")
	require.NoError(t, err)
	assert.Equal(t, "t1", consumed.TenantID)
}

func TestStateRepo_ConsumeDeletesState(t *testing.T) {
	repo := NewInMemoryStateRepository()
	ctx := context.Background()

	state := identity.OAuthState{
		State:     "state-123",
		ExpiresAt: time.Now().UTC().Add(10 * time.Minute),
	}
	repo.Store(ctx, state) //nolint:errcheck

	_, err := repo.Consume(ctx, "state-123")
	require.NoError(t, err)

	_, err = repo.Consume(ctx, "state-123")
	require.Error(t, err)
}

func TestStateRepo_ConsumeNotFound(t *testing.T) {
	repo := NewInMemoryStateRepository()
	_, err := repo.Consume(context.Background(), "nonexistent")
	require.Error(t, err)
}

func TestStateRepo_ConsumeExpired(t *testing.T) {
	repo := NewInMemoryStateRepository()
	ctx := context.Background()

	state := identity.OAuthState{
		State:     "state-expired",
		ExpiresAt: time.Now().UTC().Add(-1 * time.Minute),
	}
	repo.Store(ctx, state) //nolint:errcheck

	_, err := repo.Consume(ctx, "state-expired")
	require.Error(t, err)
}
