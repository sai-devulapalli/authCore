package cache

import (
	"context"
	"testing"

	"github.com/authplex/internal/domain/mfa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTOTPRepo_StoreAndGet(t *testing.T) {
	repo := NewInMemoryTOTPRepository()
	ctx := context.Background()

	e := mfa.TOTPEnrollment{ID: "e1", Subject: "user-1", TenantID: "t1", Secret: []byte("secret")}
	require.NoError(t, repo.Store(ctx, e))

	got, err := repo.GetBySubject(ctx, "t1", "user-1")
	require.NoError(t, err)
	assert.Equal(t, "e1", got.ID)
	assert.False(t, got.Confirmed)
}

func TestTOTPRepo_Confirm(t *testing.T) {
	repo := NewInMemoryTOTPRepository()
	ctx := context.Background()

	e := mfa.TOTPEnrollment{ID: "e1", Subject: "user-1", TenantID: "t1"}
	repo.Store(ctx, e) //nolint:errcheck

	require.NoError(t, repo.Confirm(ctx, "e1"))

	got, _ := repo.GetBySubject(ctx, "t1", "user-1")
	assert.True(t, got.Confirmed)
}

func TestTOTPRepo_Delete(t *testing.T) {
	repo := NewInMemoryTOTPRepository()
	ctx := context.Background()

	e := mfa.TOTPEnrollment{ID: "e1", Subject: "user-1", TenantID: "t1"}
	repo.Store(ctx, e) //nolint:errcheck

	require.NoError(t, repo.Delete(ctx, "e1"))

	_, err := repo.GetBySubject(ctx, "t1", "user-1")
	require.Error(t, err)
}

func TestTOTPRepo_GetNotFound(t *testing.T) {
	repo := NewInMemoryTOTPRepository()
	_, err := repo.GetBySubject(context.Background(), "t1", "nonexistent")
	require.Error(t, err)
}
