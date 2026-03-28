package authcore

import (
	"context"
	"net/http"
	"testing"

	tenantsvc "github.com/authcore/internal/application/tenant"
	"github.com/authcore/internal/domain/tenant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	auth := New(Config{Issuer: "https://test.com"}, nil, nil)
	assert.NotNil(t, auth)
	assert.NotNil(t, auth.Auth)
	assert.NotNil(t, auth.User)
	assert.NotNil(t, auth.Client)
	assert.NotNil(t, auth.Tenant)
	assert.NotNil(t, auth.JWKS)
	assert.NotNil(t, auth.MFA)
	assert.NotNil(t, auth.RBAC)
}

func TestRegisterAndLogin(t *testing.T) {
	auth := New(Config{Issuer: "https://test.com"}, nil, nil)
	ctx := context.Background()

	// Create tenant first
	auth.Tenant.Create(ctx, tenantsvc.CreateTenantRequest{
		ID: "t1", Domain: "test.com", Issuer: "https://test.com", Algorithm: tenant.RS256,
	})

	// Register
	reg, err := auth.Register(ctx, "test@example.com", "pass123", "Test User", "t1")
	require.NoError(t, err)
	assert.NotEmpty(t, reg.UserID)
	assert.Equal(t, "test@example.com", reg.Email)

	// Login
	login, err := auth.Login(ctx, "test@example.com", "pass123", "t1")
	require.NoError(t, err)
	assert.NotEmpty(t, login.SessionToken)
	assert.Greater(t, login.ExpiresIn, 0)

	// Resolve session
	userID, err := auth.ResolveSession(ctx, login.SessionToken)
	require.NoError(t, err)
	assert.Equal(t, reg.UserID, userID)
}

func TestNew_Defaults(t *testing.T) {
	auth := New(Config{}, nil, nil)
	assert.Equal(t, "https://authcore", auth.cfg.Issuer)
}

func TestMountRoutes(t *testing.T) {
	auth := New(Config{Issuer: "https://test.com"}, nil, nil)
	mux := http.NewServeMux()
	// Should not panic
	auth.MountRoutes(mux)
}
