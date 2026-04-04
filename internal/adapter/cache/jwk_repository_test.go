package cache

import (
	"context"
	"testing"
	"time"

	"github.com/authplex/internal/domain/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWKRepo_StoreAndGetActive(t *testing.T) {
	repo := NewInMemoryJWKRepository()
	ctx := context.Background()

	kp, _ := jwk.NewKeyPair("kid-1", "t1", jwk.RSA, "RS256", []byte("priv"), []byte("pub"))
	require.NoError(t, repo.Store(ctx, kp))

	active, err := repo.GetActive(ctx, "t1")
	require.NoError(t, err)
	assert.Equal(t, "kid-1", active.ID)
}

func TestJWKRepo_GetActive_NotFound(t *testing.T) {
	repo := NewInMemoryJWKRepository()
	_, err := repo.GetActive(context.Background(), "nonexistent")
	require.Error(t, err)
}

func TestJWKRepo_GetAllPublic(t *testing.T) {
	repo := NewInMemoryJWKRepository()
	ctx := context.Background()
	kp1, _ := jwk.NewKeyPair("k1", "t1", jwk.RSA, "RS256", []byte("p"), []byte("p"))
	kp2, _ := jwk.NewKeyPair("k2", "t1", jwk.EC, "ES256", []byte("p"), []byte("p"))
	repo.Store(ctx, kp1) //nolint:errcheck
	repo.Store(ctx, kp2) //nolint:errcheck

	pairs, err := repo.GetAllPublic(ctx, "t1")
	require.NoError(t, err)
	assert.Len(t, pairs, 2)
}

func TestJWKRepo_Deactivate(t *testing.T) {
	repo := NewInMemoryJWKRepository()
	ctx := context.Background()
	kp, _ := jwk.NewKeyPair("k1", "t1", jwk.RSA, "RS256", []byte("p"), []byte("p"))
	repo.Store(ctx, kp) //nolint:errcheck

	require.NoError(t, repo.Deactivate(ctx, "k1"))
	_, err := repo.GetActive(ctx, "t1")
	require.Error(t, err)
}

func TestJWKRepo_Deactivate_NotFound(t *testing.T) {
	repo := NewInMemoryJWKRepository()
	err := repo.Deactivate(context.Background(), "nonexistent")
	require.Error(t, err)
}

func TestJWKRepo_GetAllActiveTenantIDs(t *testing.T) {
	repo := NewInMemoryJWKRepository()
	ctx := context.Background()

	kp1, _ := jwk.NewKeyPair("k1", "t1", jwk.RSA, "RS256", []byte("p"), []byte("p"))
	kp2, _ := jwk.NewKeyPair("k2", "t2", jwk.RSA, "RS256", []byte("p"), []byte("p"))
	kp3, _ := jwk.NewKeyPair("k3", "t1", jwk.EC, "ES256", []byte("p"), []byte("p"))
	repo.Store(ctx, kp1) //nolint:errcheck
	repo.Store(ctx, kp2) //nolint:errcheck
	repo.Store(ctx, kp3) //nolint:errcheck

	ids, err := repo.GetAllActiveTenantIDs(ctx)
	require.NoError(t, err)
	assert.Len(t, ids, 2)
}

func TestJWKRepo_GetAllActiveTenantIDs_ExcludesInactive(t *testing.T) {
	repo := NewInMemoryJWKRepository()
	ctx := context.Background()

	kp, _ := jwk.NewKeyPair("k1", "t1", jwk.RSA, "RS256", []byte("p"), []byte("p"))
	repo.Store(ctx, kp)         //nolint:errcheck
	repo.Deactivate(ctx, "k1") //nolint:errcheck

	ids, err := repo.GetAllActiveTenantIDs(ctx)
	require.NoError(t, err)
	assert.Empty(t, ids)
}

func TestJWKRepo_DeleteInactive(t *testing.T) {
	repo := NewInMemoryJWKRepository()
	ctx := context.Background()

	// Create an inactive key with old expiry
	expired := time.Now().UTC().Add(-60 * 24 * time.Hour)
	kp := jwk.KeyPair{
		ID: "old-key", TenantID: "t1", KeyType: jwk.RSA, Algorithm: "RS256",
		Use: jwk.Sig, Active: false, ExpiresAt: &expired,
		PrivateKey: []byte("p"), PublicKey: []byte("p"),
	}
	repo.Store(ctx, kp) //nolint:errcheck

	// Active key should not be deleted
	kp2, _ := jwk.NewKeyPair("active-key", "t1", jwk.RSA, "RS256", []byte("p"), []byte("p"))
	repo.Store(ctx, kp2) //nolint:errcheck

	count, err := repo.DeleteInactive(ctx, time.Now().UTC().Add(-30*24*time.Hour))
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)

	keys, _ := repo.GetAllPublic(ctx, "t1")
	assert.Len(t, keys, 1)
	assert.Equal(t, "active-key", keys[0].ID)
}
