package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/authplex/internal/application/discovery"
	"github.com/authplex/internal/domain/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiscoveryHandler_Success(t *testing.T) {
	svc := discovery.NewService("https://auth.example.com", slog.Default())
	h := NewDiscoveryHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()

	h.HandleDiscovery(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json; charset=utf-8", w.Header().Get("Content-Type"))

	var doc oidc.DiscoveryDocument
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &doc))
	assert.Equal(t, "https://auth.example.com", doc.Issuer)
	assert.Equal(t, "https://auth.example.com/authorize", doc.AuthorizationEndpoint)
	assert.Equal(t, "https://auth.example.com/token", doc.TokenEndpoint)
	assert.Equal(t, "https://auth.example.com/jwks", doc.JWKSURI)
}

func TestDiscoveryHandler_TenantIssuerOverride(t *testing.T) {
	svc := discovery.NewService("https://auth.example.com", slog.Default())
	h := NewDiscoveryHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	req.Header.Set("X-Tenant-Issuer", "https://tenant1.example.com")
	w := httptest.NewRecorder()

	h.HandleDiscovery(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var doc oidc.DiscoveryDocument
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &doc))
	assert.Equal(t, "https://tenant1.example.com", doc.Issuer)
}

func TestDiscoveryHandler_MethodNotAllowed(t *testing.T) {
	svc := discovery.NewService("https://auth.example.com", slog.Default())
	h := NewDiscoveryHandler(svc)

	req := httptest.NewRequest(http.MethodPost, "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()

	h.HandleDiscovery(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDiscoveryHandler_ResponseNotEnveloped(t *testing.T) {
	svc := discovery.NewService("https://auth.example.com", slog.Default())
	h := NewDiscoveryHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()

	h.HandleDiscovery(w, req)

	// Verify the response is raw JSON, not wrapped in {data:...}
	var raw map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &raw))
	_, hasData := raw["data"]
	assert.False(t, hasData, "response should not be wrapped in data envelope")
	_, hasIssuer := raw["issuer"]
	assert.True(t, hasIssuer, "response should contain issuer at top level")
}

func TestDiscoveryHandler_AllRequiredFields(t *testing.T) {
	svc := discovery.NewService("https://auth.example.com", slog.Default())
	h := NewDiscoveryHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()

	h.HandleDiscovery(w, req)

	var doc oidc.DiscoveryDocument
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &doc))
	assert.NotEmpty(t, doc.ResponseTypesSupported)
	assert.NotEmpty(t, doc.SubjectTypesSupported)
	assert.NotEmpty(t, doc.IDTokenSigningAlgValuesSupported)
	assert.NotEmpty(t, doc.ScopesSupported)
	assert.NotEmpty(t, doc.CodeChallengeMethodsSupported)
	assert.NotEmpty(t, doc.GrantTypesSupported)
}
