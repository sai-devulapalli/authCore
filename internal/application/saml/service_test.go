package saml

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/authplex/internal/adapter/cache"
	adaptcrypto "github.com/authplex/internal/adapter/crypto"
	"github.com/authplex/internal/application/auth"
	"github.com/authplex/internal/application/jwks"
	"github.com/authplex/internal/domain/identity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestSAMLService() *Service {
	log := slog.Default()
	keyGen := adaptcrypto.NewKeyGenerator()
	keyConv := adaptcrypto.NewJWKConverter()
	signer := adaptcrypto.NewJWTSigner()

	jwksSvc := jwks.NewService(cache.NewInMemoryJWKRepository(), keyGen, keyConv, log)
	authSvc := auth.NewService(cache.NewInMemoryCodeRepository(), jwksSvc, signer, log)

	return NewService(
		cache.NewInMemoryProviderRepository(),
		cache.NewInMemoryExternalIdentityRepository(),
		cache.NewInMemoryStateRepository(),
		authSvc,
		"http://localhost:8080",
		log,
	)
}

func TestGenerateMetadata_ProviderNotFound(t *testing.T) {
	svc := newTestSAMLService()
	_, err := svc.GenerateMetadata(context.Background(), "tenant-1", "nonexistent")
	require.NotNil(t, err)
}

func TestInitiateSSO_MissingProvider(t *testing.T) {
	svc := newTestSAMLService()
	_, err := svc.InitiateSSO(context.Background(), SSORequest{
		ProviderID: "",
		TenantID:   "tenant-1",
	})
	require.NotNil(t, err)
}

func TestInitiateSSO_ProviderNotFound(t *testing.T) {
	svc := newTestSAMLService()
	_, err := svc.InitiateSSO(context.Background(), SSORequest{
		ProviderID: "nonexistent",
		TenantID:   "tenant-1",
		ClientID:   "client-1",
	})
	require.NotNil(t, err)
}

func TestHandleACS_EmptyRequest(t *testing.T) {
	svc := newTestSAMLService()
	req := httptest.NewRequest(http.MethodPost, "/saml/acs", nil)
	_, err := svc.HandleACS(context.Background(), req, "")
	require.NotNil(t, err)
}

func TestHandleACS_InvalidRelayState(t *testing.T) {
	svc := newTestSAMLService()
	req := httptest.NewRequest(http.MethodPost, "/saml/acs", nil)
	_, err := svc.HandleACS(context.Background(), req, "invalid-state")
	require.NotNil(t, err)
}

func TestGetServiceProvider_NoMetadata(t *testing.T) {
	svc := newTestSAMLService()
	provider := identity.IdentityProvider{
		ID:           "saml-1",
		TenantID:     "tenant-1",
		ProviderType: identity.ProviderSAML,
		ExtraConfig:  map[string]string{},
	}
	_, err := svc.GetServiceProvider(provider)
	require.NotNil(t, err)
}

func TestNewService_NotNil(t *testing.T) {
	svc := newTestSAMLService()
	assert.NotNil(t, svc)
	assert.Equal(t, "http://localhost:8080", svc.issuer)
}

func TestSAMLErrors_ReturnError(t *testing.T) {
	svc := newTestSAMLService()
	_, err := svc.GenerateMetadata(context.Background(), "t1", "missing")
	require.NotNil(t, err)
	assert.Contains(t, err.Error(), "not found")
}
