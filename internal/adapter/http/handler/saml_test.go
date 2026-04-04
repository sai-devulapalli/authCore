package handler

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/authplex/internal/adapter/cache"
	adaptcrypto "github.com/authplex/internal/adapter/crypto"
	"github.com/authplex/internal/application/auth"
	"github.com/authplex/internal/application/jwks"
	samlsvc "github.com/authplex/internal/application/saml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestSAMLHandler() *SAMLHandler {
	log := slog.Default()
	keyGen := adaptcrypto.NewKeyGenerator()
	keyConv := adaptcrypto.NewJWKConverter()
	signer := adaptcrypto.NewJWTSigner()

	jwksSvc := jwks.NewService(cache.NewInMemoryJWKRepository(), keyGen, keyConv, log)
	authSvc := auth.NewService(cache.NewInMemoryCodeRepository(), jwksSvc, signer, log)

	svc := samlsvc.NewService(
		cache.NewInMemoryProviderRepository(),
		cache.NewInMemoryExternalIdentityRepository(),
		cache.NewInMemoryStateRepository(),
		authSvc,
		"http://localhost:8080",
		log,
	)

	return NewSAMLHandler(svc)
}

func TestSAMLHandler_New(t *testing.T) {
	h := newTestSAMLHandler()
	assert.NotNil(t, h)
}

func TestSAMLHandler_HandleMetadata_ProviderNotFound(t *testing.T) {
	h := newTestSAMLHandler()

	req := httptest.NewRequest(http.MethodGet, "/saml/metadata?provider=nonexistent&tenant=tenant-1", nil)
	w := httptest.NewRecorder()

	h.HandleMetadata(w, req)

	// Provider not found → error response (not 200)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

func TestSAMLHandler_HandleMetadata_MissingProvider(t *testing.T) {
	h := newTestSAMLHandler()

	// No provider query param
	req := httptest.NewRequest(http.MethodGet, "/saml/metadata", nil)
	w := httptest.NewRecorder()

	h.HandleMetadata(w, req)

	assert.NotEqual(t, http.StatusOK, w.Code)
}

func TestSAMLHandler_HandleMetadata_WrongMethod(t *testing.T) {
	h := newTestSAMLHandler()

	req := httptest.NewRequest(http.MethodPost, "/saml/metadata?provider=p1", nil)
	w := httptest.NewRecorder()

	h.HandleMetadata(w, req)

	assert.NotEqual(t, http.StatusOK, w.Code)
}

func TestSAMLHandler_HandleSSO_MissingParams(t *testing.T) {
	h := newTestSAMLHandler()

	// No provider param, no tenant header
	req := httptest.NewRequest(http.MethodGet, "/saml/sso", nil)
	w := httptest.NewRecorder()

	h.HandleSSO(w, req)

	// Missing provider → error
	assert.NotEqual(t, http.StatusFound, w.Code)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

func TestSAMLHandler_HandleSSO_WrongMethod(t *testing.T) {
	h := newTestSAMLHandler()

	req := httptest.NewRequest(http.MethodPost, "/saml/sso?provider=p1", nil)
	w := httptest.NewRecorder()

	h.HandleSSO(w, req)

	assert.NotEqual(t, http.StatusFound, w.Code)
}

func TestSAMLHandler_HandleSSO_ProviderNotFound(t *testing.T) {
	h := newTestSAMLHandler()

	req := httptest.NewRequest(http.MethodGet, "/saml/sso?provider=nonexistent", nil)
	req.Header.Set("X-Tenant-ID", "tenant-1")
	w := httptest.NewRecorder()

	h.HandleSSO(w, req)

	// Provider not found → error, not a redirect
	assert.NotEqual(t, http.StatusFound, w.Code)
}

func TestSAMLHandler_HandleACS_EmptyBody(t *testing.T) {
	h := newTestSAMLHandler()

	req := httptest.NewRequest(http.MethodPost, "/saml/acs", bytes.NewBufferString(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.HandleACS(w, req)

	// Empty body → missing SAMLResponse → error
	assert.NotEqual(t, http.StatusFound, w.Code)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

func TestSAMLHandler_HandleACS_WrongMethod(t *testing.T) {
	h := newTestSAMLHandler()

	req := httptest.NewRequest(http.MethodGet, "/saml/acs", nil)
	w := httptest.NewRecorder()

	h.HandleACS(w, req)

	assert.NotEqual(t, http.StatusFound, w.Code)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

func TestSAMLHandler_HandleACS_MissingSAMLResponse(t *testing.T) {
	h := newTestSAMLHandler()

	// Has RelayState but no SAMLResponse
	body := "RelayState=some-state"
	req := httptest.NewRequest(http.MethodPost, "/saml/acs", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.HandleACS(w, req)

	// SAMLResponse missing → error
	assert.NotEqual(t, http.StatusFound, w.Code)
}

func TestSAMLHandler_HandleACS_MissingRelayState(t *testing.T) {
	h := newTestSAMLHandler()

	// Has SAMLResponse but no RelayState
	body := "SAMLResponse=dGVzdA"
	req := httptest.NewRequest(http.MethodPost, "/saml/acs", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.HandleACS(w, req)

	// RelayState missing → error
	assert.NotEqual(t, http.StatusFound, w.Code)
}

func TestSAMLHandler_HandleACS_InvalidRelayState(t *testing.T) {
	h := newTestSAMLHandler()

	// Both fields present but RelayState doesn't match any stored state
	body := "SAMLResponse=dGVzdA&RelayState=invalid-state-token"
	req := httptest.NewRequest(http.MethodPost, "/saml/acs", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.HandleACS(w, req)

	// Invalid RelayState → ACS service error → error response
	assert.NotEqual(t, http.StatusFound, w.Code)

	require.NotEmpty(t, w.Body.String())
}
