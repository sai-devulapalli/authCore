package cache

import (
	"context"
	"testing"

	"github.com/authplex/internal/domain/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeviceRepo_StoreAndGet(t *testing.T) {
	repo := NewInMemoryDeviceRepository()
	ctx := context.Background()

	dc := token.DeviceCode{
		DeviceCode: "dev-123",
		UserCode:   "ABCD-1234",
		ClientID:   "c1",
	}
	require.NoError(t, repo.Store(ctx, dc))

	got, err := repo.GetByDeviceCode(ctx, "dev-123")
	require.NoError(t, err)
	assert.Equal(t, "ABCD-1234", got.UserCode)
}

func TestDeviceRepo_GetByUserCode(t *testing.T) {
	repo := NewInMemoryDeviceRepository()
	ctx := context.Background()

	dc := token.DeviceCode{DeviceCode: "dev-123", UserCode: "ABCD-1234"}
	repo.Store(ctx, dc) //nolint:errcheck

	got, err := repo.GetByUserCode(ctx, "ABCD-1234")
	require.NoError(t, err)
	assert.Equal(t, "dev-123", got.DeviceCode)
}

func TestDeviceRepo_Authorize(t *testing.T) {
	repo := NewInMemoryDeviceRepository()
	ctx := context.Background()

	dc := token.DeviceCode{DeviceCode: "dev-123", UserCode: "ABCD-1234"}
	repo.Store(ctx, dc) //nolint:errcheck

	require.NoError(t, repo.Authorize(ctx, "ABCD-1234", "user-1"))

	got, _ := repo.GetByDeviceCode(ctx, "dev-123")
	assert.True(t, got.Authorized)
	assert.Equal(t, "user-1", got.Subject)
}

func TestDeviceRepo_Deny(t *testing.T) {
	repo := NewInMemoryDeviceRepository()
	ctx := context.Background()

	dc := token.DeviceCode{DeviceCode: "dev-123", UserCode: "ABCD-1234"}
	repo.Store(ctx, dc) //nolint:errcheck

	require.NoError(t, repo.Deny(ctx, "ABCD-1234"))

	got, _ := repo.GetByDeviceCode(ctx, "dev-123")
	assert.True(t, got.Denied)
}

func TestDeviceRepo_NotFound(t *testing.T) {
	repo := NewInMemoryDeviceRepository()
	_, err := repo.GetByDeviceCode(context.Background(), "nonexistent")
	require.Error(t, err)
}
