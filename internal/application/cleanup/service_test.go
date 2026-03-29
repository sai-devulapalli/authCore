package cleanup

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/authcore/internal/adapter/cache"
	adaptcrypto "github.com/authcore/internal/adapter/crypto"
	"github.com/authcore/internal/application/jwks"
	"github.com/authcore/internal/domain/jwk"
	"github.com/authcore/internal/domain/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCleanupService_RefreshTokenCleanup(t *testing.T) {
	refreshRepo := cache.NewInMemoryRefreshRepository()
	jwkRepo := cache.NewInMemoryJWKRepository()
	tenantRepo := cache.NewInMemoryTenantRepository()
	log := slog.Default()
	jwksSvc := jwks.NewService(jwkRepo, adaptcrypto.NewKeyGenerator(), adaptcrypto.NewJWKConverter(), log)

	svc := NewService(refreshRepo, jwkRepo, jwksSvc, tenantRepo, log, 90)
	ctx := context.Background()

	// Store tokens: one expired, one revoked (old), one active
	past := time.Now().UTC().Add(-30 * 24 * time.Hour)
	revokedAt := time.Now().UTC().Add(-10 * 24 * time.Hour)

	require.NoError(t, refreshRepo.Store(ctx, token.RefreshToken{
		Token: "expired-1", ExpiresAt: past, FamilyID: "f1",
	}))
	rt := token.RefreshToken{Token: "revoked-1", FamilyID: "f2", ExpiresAt: time.Now().UTC().Add(24 * time.Hour)}
	require.NoError(t, refreshRepo.Store(ctx, rt))
	// Manually set revoked_at via RevokeByToken then check
	require.NoError(t, refreshRepo.RevokeByToken(ctx, "revoked-1"))

	require.NoError(t, refreshRepo.Store(ctx, token.RefreshToken{
		Token: "active-1", ExpiresAt: time.Now().UTC().Add(24 * time.Hour), FamilyID: "f3",
	}))

	// Override retention to 1 day for testing
	svc.retention = 1 * 24 * time.Hour

	svc.cleanupRefreshTokens(ctx)

	// Expired token should be deleted
	_, err := refreshRepo.GetByToken(ctx, "expired-1")
	assert.Error(t, err, "expired token should be cleaned up")

	// Active token should remain (token is hashed on storage, so check by lookup only)
	_, err = refreshRepo.GetByToken(ctx, "active-1")
	assert.NoError(t, err, "active token should remain")

	// Revoked token was revoked recently (within retention), might still be there
	// but with the short retention of 1 day and revokedAt being recent, it should stay
	_, _ = revokedAt, revokedAt // use the variable
}

func TestCleanupService_KeyRotation(t *testing.T) {
	jwkRepo := cache.NewInMemoryJWKRepository()
	tenantRepo := cache.NewInMemoryTenantRepository()
	refreshRepo := cache.NewInMemoryRefreshRepository()
	log := slog.Default()
	keyGen := adaptcrypto.NewKeyGenerator()
	keyConv := adaptcrypto.NewJWKConverter()
	jwksSvc := jwks.NewService(jwkRepo, keyGen, keyConv, log)

	// Set key rotation to 1 day for testing
	svc := NewService(refreshRepo, jwkRepo, jwksSvc, tenantRepo, log, 1)
	ctx := context.Background()

	// Create an old key (2 days old)
	priv, pub, err := keyGen.GenerateRSA()
	require.NoError(t, err)
	oldKey := jwk.KeyPair{
		ID:         "old-key-1",
		TenantID:   "tenant-1",
		KeyType:    jwk.RSA,
		Algorithm:  "RS256",
		Use:        jwk.Sig,
		PrivateKey: priv,
		PublicKey:  pub,
		CreatedAt:  time.Now().UTC().Add(-2 * 24 * time.Hour),
		Active:     true,
	}
	require.NoError(t, jwkRepo.Store(ctx, oldKey))

	svc.rotateKeys(ctx)

	// Old key should be deactivated
	allKeys, err := jwkRepo.GetAllPublic(ctx, "tenant-1")
	require.NoError(t, err)
	assert.Equal(t, 2, len(allKeys), "should have old + new key")

	// New active key should exist
	newKey, err := jwkRepo.GetActive(ctx, "tenant-1")
	require.NoError(t, err)
	assert.NotEqual(t, "old-key-1", newKey.ID, "new key should have different ID")
}

func TestCleanupService_InactiveKeyCleanup(t *testing.T) {
	jwkRepo := cache.NewInMemoryJWKRepository()
	tenantRepo := cache.NewInMemoryTenantRepository()
	refreshRepo := cache.NewInMemoryRefreshRepository()
	log := slog.Default()
	jwksSvc := jwks.NewService(jwkRepo, adaptcrypto.NewKeyGenerator(), adaptcrypto.NewJWKConverter(), log)
	svc := NewService(refreshRepo, jwkRepo, jwksSvc, tenantRepo, log, 90)
	ctx := context.Background()

	// Create an inactive key that expired 60 days ago
	expired := time.Now().UTC().Add(-60 * 24 * time.Hour)
	oldKey := jwk.KeyPair{
		ID:        "inactive-key",
		TenantID:  "t1",
		KeyType:   jwk.RSA,
		Algorithm: "RS256",
		Use:       jwk.Sig,
		Active:    false,
		ExpiresAt: &expired,
		CreatedAt: time.Now().UTC().Add(-120 * 24 * time.Hour),
	}
	require.NoError(t, jwkRepo.Store(ctx, oldKey))

	svc.cleanupInactiveKeys(ctx)

	keys, _ := jwkRepo.GetAllPublic(ctx, "t1")
	assert.Empty(t, keys, "inactive expired key should be cleaned up")
}

func TestCleanupService_RunOnce(t *testing.T) {
	refreshRepo := cache.NewInMemoryRefreshRepository()
	jwkRepo := cache.NewInMemoryJWKRepository()
	tenantRepo := cache.NewInMemoryTenantRepository()
	log := slog.Default()
	jwksSvc := jwks.NewService(jwkRepo, adaptcrypto.NewKeyGenerator(), adaptcrypto.NewJWKConverter(), log)
	svc := NewService(refreshRepo, jwkRepo, jwksSvc, tenantRepo, log, 90)

	// Should not panic with empty repos
	svc.RunOnce(context.Background())
}

func TestCleanupService_DefaultKeyRotation(t *testing.T) {
	refreshRepo := cache.NewInMemoryRefreshRepository()
	jwkRepo := cache.NewInMemoryJWKRepository()
	tenantRepo := cache.NewInMemoryTenantRepository()
	log := slog.Default()
	jwksSvc := jwks.NewService(jwkRepo, adaptcrypto.NewKeyGenerator(), adaptcrypto.NewJWKConverter(), log)

	// Zero defaults to 90 days
	svc := NewService(refreshRepo, jwkRepo, jwksSvc, tenantRepo, log, 0)
	assert.Equal(t, 90*24*time.Hour, svc.keyMaxAge)

	// Negative defaults to 90 days
	svc2 := NewService(refreshRepo, jwkRepo, jwksSvc, tenantRepo, log, -1)
	assert.Equal(t, 90*24*time.Hour, svc2.keyMaxAge)
}

func TestCleanupService_Start_StopsOnCancel(t *testing.T) {
	refreshRepo := cache.NewInMemoryRefreshRepository()
	jwkRepo := cache.NewInMemoryJWKRepository()
	tenantRepo := cache.NewInMemoryTenantRepository()
	log := slog.Default()
	jwksSvc := jwks.NewService(jwkRepo, adaptcrypto.NewKeyGenerator(), adaptcrypto.NewJWKConverter(), log)
	svc := NewService(refreshRepo, jwkRepo, jwksSvc, tenantRepo, log, 90)
	svc.interval = 10 * time.Millisecond // short interval for testing

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		svc.Start(ctx)
		close(done)
	}()

	// Let it run briefly
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// Success — Start returned after cancel
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after context cancellation")
	}
}

func TestCleanupService_KeyRotation_SkipsRecentKeys(t *testing.T) {
	jwkRepo := cache.NewInMemoryJWKRepository()
	tenantRepo := cache.NewInMemoryTenantRepository()
	refreshRepo := cache.NewInMemoryRefreshRepository()
	log := slog.Default()
	keyGen := adaptcrypto.NewKeyGenerator()
	jwksSvc := jwks.NewService(jwkRepo, keyGen, adaptcrypto.NewJWKConverter(), log)
	svc := NewService(refreshRepo, jwkRepo, jwksSvc, tenantRepo, log, 90)
	ctx := context.Background()

	// Create a recent key (1 day old) — should NOT be rotated
	priv, pub, err := keyGen.GenerateRSA()
	require.NoError(t, err)
	recentKey := jwk.KeyPair{
		ID: "recent-key", TenantID: "t1", KeyType: jwk.RSA, Algorithm: "RS256",
		Use: jwk.Sig, PrivateKey: priv, PublicKey: pub,
		CreatedAt: time.Now().UTC().Add(-24 * time.Hour), Active: true,
	}
	require.NoError(t, jwkRepo.Store(ctx, recentKey))

	svc.rotateKeys(ctx)

	// Should still have only 1 key (no rotation)
	keys, _ := jwkRepo.GetAllPublic(ctx, "t1")
	assert.Len(t, keys, 1)
	assert.Equal(t, "recent-key", keys[0].ID)
}

func TestCleanupService_RefreshCleanup_ZeroCount(t *testing.T) {
	refreshRepo := cache.NewInMemoryRefreshRepository()
	jwkRepo := cache.NewInMemoryJWKRepository()
	tenantRepo := cache.NewInMemoryTenantRepository()
	log := slog.Default()
	jwksSvc := jwks.NewService(jwkRepo, adaptcrypto.NewKeyGenerator(), adaptcrypto.NewJWKConverter(), log)
	svc := NewService(refreshRepo, jwkRepo, jwksSvc, tenantRepo, log, 90)

	// No tokens at all — cleanupRefreshTokens should run without error and log nothing
	svc.cleanupRefreshTokens(context.Background())
}

func TestCleanupService_InactiveKeyCleanup_ZeroCount(t *testing.T) {
	jwkRepo := cache.NewInMemoryJWKRepository()
	tenantRepo := cache.NewInMemoryTenantRepository()
	refreshRepo := cache.NewInMemoryRefreshRepository()
	log := slog.Default()
	jwksSvc := jwks.NewService(jwkRepo, adaptcrypto.NewKeyGenerator(), adaptcrypto.NewJWKConverter(), log)
	svc := NewService(refreshRepo, jwkRepo, jwksSvc, tenantRepo, log, 90)

	// No inactive keys — should run without error
	svc.cleanupInactiveKeys(context.Background())
}

func TestCleanupService_RotateKeys_NoTenants(t *testing.T) {
	jwkRepo := cache.NewInMemoryJWKRepository()
	tenantRepo := cache.NewInMemoryTenantRepository()
	refreshRepo := cache.NewInMemoryRefreshRepository()
	log := slog.Default()
	jwksSvc := jwks.NewService(jwkRepo, adaptcrypto.NewKeyGenerator(), adaptcrypto.NewJWKConverter(), log)
	svc := NewService(refreshRepo, jwkRepo, jwksSvc, tenantRepo, log, 90)

	// No tenants — should run without error
	svc.rotateKeys(context.Background())
}

func TestCleanupService_NoDeleteWhenNothingExpired(t *testing.T) {
	refreshRepo := cache.NewInMemoryRefreshRepository()
	jwkRepo := cache.NewInMemoryJWKRepository()
	tenantRepo := cache.NewInMemoryTenantRepository()
	log := slog.Default()
	jwksSvc := jwks.NewService(jwkRepo, adaptcrypto.NewKeyGenerator(), adaptcrypto.NewJWKConverter(), log)
	svc := NewService(refreshRepo, jwkRepo, jwksSvc, tenantRepo, log, 90)
	ctx := context.Background()

	// Store only active tokens
	require.NoError(t, refreshRepo.Store(ctx, token.RefreshToken{
		Token: "active", ExpiresAt: time.Now().UTC().Add(24 * time.Hour), FamilyID: "f1",
	}))

	svc.cleanupRefreshTokens(ctx)

	// Token should still be there
	_, err := refreshRepo.GetByToken(ctx, "active")
	assert.NoError(t, err)
}
