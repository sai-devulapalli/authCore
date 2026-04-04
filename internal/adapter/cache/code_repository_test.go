package cache

import (
	"context"
	"testing"
	"time"

	"github.com/authplex/internal/domain/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInMemoryCodeRepository_StoreAndConsume(t *testing.T) {
	repo := NewInMemoryCodeRepository()
	ctx := context.Background()

	code := token.AuthorizationCode{
		Code:                "code-123",
		ClientID:            "client-1",
		RedirectURI:         "https://example.com/callback",
		Scope:               "openid",
		Subject:             "user-123",
		TenantID:            "tenant-1",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().UTC().Add(10 * time.Minute),
	}

	require.NoError(t, repo.Store(ctx, code))

	consumed, err := repo.Consume(ctx, "code-123")
	require.NoError(t, err)
	assert.Equal(t, "code-123", consumed.Code)
	assert.Equal(t, "client-1", consumed.ClientID)
	assert.Equal(t, "user-123", consumed.Subject)
	assert.Equal(t, "tenant-1", consumed.TenantID)
	assert.Equal(t, "challenge", consumed.CodeChallenge)
}

func TestInMemoryCodeRepository_ConsumeDeletesCode(t *testing.T) {
	repo := NewInMemoryCodeRepository()
	ctx := context.Background()

	code := token.AuthorizationCode{
		Code:      "code-123",
		ExpiresAt: time.Now().UTC().Add(10 * time.Minute),
	}

	require.NoError(t, repo.Store(ctx, code))

	_, err := repo.Consume(ctx, "code-123")
	require.NoError(t, err)

	// Second consume should fail
	_, err = repo.Consume(ctx, "code-123")
	require.Error(t, err)
}

func TestInMemoryCodeRepository_ConsumeNotFound(t *testing.T) {
	repo := NewInMemoryCodeRepository()
	ctx := context.Background()

	_, err := repo.Consume(ctx, "nonexistent")
	require.Error(t, err)
}

func TestInMemoryCodeRepository_ConsumeExpired(t *testing.T) {
	repo := NewInMemoryCodeRepository()
	ctx := context.Background()

	code := token.AuthorizationCode{
		Code:      "code-expired",
		ExpiresAt: time.Now().UTC().Add(-1 * time.Minute),
	}

	require.NoError(t, repo.Store(ctx, code))

	_, err := repo.Consume(ctx, "code-expired")
	require.Error(t, err)
}

func TestInMemoryCodeRepository_MultipleCodes(t *testing.T) {
	repo := NewInMemoryCodeRepository()
	ctx := context.Background()

	code1 := token.AuthorizationCode{
		Code:      "code-1",
		ClientID:  "client-1",
		ExpiresAt: time.Now().UTC().Add(10 * time.Minute),
	}
	code2 := token.AuthorizationCode{
		Code:      "code-2",
		ClientID:  "client-2",
		ExpiresAt: time.Now().UTC().Add(10 * time.Minute),
	}

	require.NoError(t, repo.Store(ctx, code1))
	require.NoError(t, repo.Store(ctx, code2))

	consumed1, err := repo.Consume(ctx, "code-1")
	require.NoError(t, err)
	assert.Equal(t, "client-1", consumed1.ClientID)

	consumed2, err := repo.Consume(ctx, "code-2")
	require.NoError(t, err)
	assert.Equal(t, "client-2", consumed2.ClientID)
}
