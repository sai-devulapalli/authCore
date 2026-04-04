package cache

import (
	"context"
	"testing"
	"time"

	"github.com/authplex/internal/domain/otp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOTPRepo_StoreAndGet(t *testing.T) {
	repo := NewInMemoryOTPRepository()
	ctx := context.Background()

	o := otp.OTP{
		Identifier: "user@example.com",
		Code:       "123456",
		Channel:    otp.ChannelEmail,
		TenantID:   "t1",
		ExpiresAt:  time.Now().UTC().Add(5 * time.Minute),
	}
	require.NoError(t, repo.Store(ctx, o))

	got, err := repo.Get(ctx, "user@example.com", "t1")
	require.NoError(t, err)
	assert.Equal(t, "123456", got.Code)
}

func TestOTPRepo_GetNotFound(t *testing.T) {
	repo := NewInMemoryOTPRepository()
	_, err := repo.Get(context.Background(), "nonexistent", "t1")
	require.Error(t, err)
}

func TestOTPRepo_IncrementAttempts(t *testing.T) {
	repo := NewInMemoryOTPRepository()
	ctx := context.Background()

	o := otp.OTP{Identifier: "user@example.com", TenantID: "t1", Code: "123456"}
	repo.Store(ctx, o) //nolint:errcheck

	require.NoError(t, repo.IncrementAttempts(ctx, "user@example.com", "t1"))

	got, _ := repo.Get(ctx, "user@example.com", "t1")
	assert.Equal(t, 1, got.Attempts)
}

func TestOTPRepo_Delete(t *testing.T) {
	repo := NewInMemoryOTPRepository()
	ctx := context.Background()

	o := otp.OTP{Identifier: "user@example.com", TenantID: "t1"}
	repo.Store(ctx, o) //nolint:errcheck

	require.NoError(t, repo.Delete(ctx, "user@example.com", "t1"))

	_, err := repo.Get(ctx, "user@example.com", "t1")
	require.Error(t, err)
}

func TestOTPRepo_TenantIsolation(t *testing.T) {
	repo := NewInMemoryOTPRepository()
	ctx := context.Background()

	repo.Store(ctx, otp.OTP{Identifier: "user@example.com", TenantID: "t1", Code: "111111"}) //nolint:errcheck
	repo.Store(ctx, otp.OTP{Identifier: "user@example.com", TenantID: "t2", Code: "222222"}) //nolint:errcheck

	got1, _ := repo.Get(ctx, "user@example.com", "t1")
	got2, _ := repo.Get(ctx, "user@example.com", "t2")

	assert.Equal(t, "111111", got1.Code)
	assert.Equal(t, "222222", got2.Code)
}
