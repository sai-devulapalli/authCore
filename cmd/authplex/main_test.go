package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/authplex/internal/config"
	"github.com/authplex/internal/domain/jwk"
	"github.com/authplex/pkg/sdk/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testConfig() config.Config {
	return config.Config{
		Environment: logger.Local,
		HTTPPort:    8080,
		Issuer:      "https://auth.test.com",
		TenantMode:  config.TenantModeHeader,
	}
}

func setupWithTenant(t *testing.T) (http.Handler, string) {
	t.Helper()
	cfg := testConfig()
	log := slog.Default()
	h := setupServer(cfg, log)

	// Create a tenant first
	body := `{"id":"test-tenant","domain":"test.example.com","issuer":"https://test.example.com","algorithm":"RS256"}`
	req := httptest.NewRequest(http.MethodPost, "/tenants", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	return h, "test-tenant"
}

func TestVersionVars(t *testing.T) {
	assert.Equal(t, "dev", version)
	assert.Equal(t, "none", commit)
}

func TestSetupInMemoryRepos(t *testing.T) {
	r := setupInMemoryRepos()
	assert.NotNil(t, r.jwk)
	assert.NotNil(t, r.tenant)
	assert.NotNil(t, r.client)
	assert.NotNil(t, r.user)
	assert.NotNil(t, r.session)
	assert.NotNil(t, r.code)
	assert.NotNil(t, r.refresh)
	assert.NotNil(t, r.device)
	assert.NotNil(t, r.blacklist)
	assert.NotNil(t, r.provider)
	assert.NotNil(t, r.externalID)
	assert.NotNil(t, r.state)
	assert.NotNil(t, r.totp)
	assert.NotNil(t, r.challenge)
}

func TestSetupPostgresRepos_NilDB(t *testing.T) {
	// Verify struct fields are populated (repos wrapping nil DB will fail on use, not on construction)
	r := setupPostgresRepos(nil)
	assert.NotNil(t, r.jwk)
	assert.NotNil(t, r.tenant)
	assert.NotNil(t, r.client)
	assert.NotNil(t, r.user)
}

func TestSetupServerWithRepos(t *testing.T) {
	cfg := testConfig()
	r := setupInMemoryRepos()
	h := setupServerWithRepos(cfg, slog.Default(), r)
	assert.NotNil(t, h)

	// Health should work
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestSetupServer_DiscoveryEndpoint(t *testing.T) {
	h, tenantID := setupWithTenant(t)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	req.Header.Set("X-Tenant-ID", tenantID)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var doc map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &doc))
	assert.Equal(t, "https://auth.test.com", doc["issuer"])
}

func TestSetupServer_JWKSEndpoint(t *testing.T) {
	h, tenantID := setupWithTenant(t)

	req := httptest.NewRequest(http.MethodGet, "/jwks", nil)
	req.Header.Set("X-Tenant-ID", tenantID)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var set jwk.Set
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &set))
	assert.NotNil(t, set.Keys)
}

func TestSetupServer_HealthEndpoint(t *testing.T) {
	cfg := testConfig()
	h := setupServer(cfg, slog.Default())

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var result map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	assert.Equal(t, "up", result["status"])
}

func TestSetupServer_TenantCRUD(t *testing.T) {
	cfg := testConfig()
	h := setupServer(cfg, slog.Default())

	// Create
	body := `{"id":"t1","domain":"example.com","issuer":"https://example.com","algorithm":"RS256"}`
	req := httptest.NewRequest(http.MethodPost, "/tenants", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)

	// List
	req = httptest.NewRequest(http.MethodGet, "/tenants", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Get
	req = httptest.NewRequest(http.MethodGet, "/tenants/t1", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Delete
	req = httptest.NewRequest(http.MethodDelete, "/tenants/t1", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNoContent, w.Code)
}

func TestSetupServer_OIDCRequiresTenant(t *testing.T) {
	cfg := testConfig()
	h := setupServer(cfg, slog.Default())

	// OIDC endpoint without tenant header should be rejected
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// In-memory repo tests moved to internal/adapter/cache/*_test.go

// --- Client CRUD via HTTP ---

func TestSetupServer_ClientCRUD(t *testing.T) {
	cfg := testConfig()
	h := setupServer(cfg, slog.Default())

	// Create tenant first
	tenantBody := `{"id":"t1","domain":"example.com","issuer":"https://example.com","algorithm":"RS256"}`
	req := httptest.NewRequest(http.MethodPost, "/tenants", strings.NewReader(tenantBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	// Create client
	clientBody := `{"client_name":"My SPA","client_type":"public","redirect_uris":["https://example.com/cb"],"allowed_scopes":["openid"],"grant_types":["authorization_code"]}`
	req = httptest.NewRequest(http.MethodPost, "/tenants/t1/clients", strings.NewReader(clientBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)

	var created map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &created))
	data := created["data"].(map[string]any)
	assert.NotEmpty(t, data["client_id"])

	// List clients
	req = httptest.NewRequest(http.MethodGet, "/tenants/t1/clients", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// --- Revoke endpoint ---

func TestSetupServer_RevokeEndpoint(t *testing.T) {
	h, tenantID := setupWithTenant(t)

	body := "token=some-token&token_type_hint=access_token"
	req := httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Tenant-ID", tenantID)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// --- Introspect endpoint ---

func TestSetupServer_IntrospectEndpoint(t *testing.T) {
	h, tenantID := setupWithTenant(t)

	body := "token=not-a-valid-jwt"
	req := httptest.NewRequest(http.MethodPost, "/introspect", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Tenant-ID", tenantID)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.False(t, resp["active"].(bool))
}

// --- Provider CRUD via HTTP ---

func TestSetupServer_ProviderCRUD(t *testing.T) {
	cfg := testConfig()
	h := setupServer(cfg, slog.Default())

	// Create tenant
	tenantBody := `{"id":"t1","domain":"example.com","issuer":"https://example.com","algorithm":"RS256"}`
	req := httptest.NewRequest(http.MethodPost, "/tenants", strings.NewReader(tenantBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	// Create provider
	providerBody := `{"provider_type":"google","client_id":"google-cid","client_secret":"google-secret","scopes":["openid","email"]}`
	req = httptest.NewRequest(http.MethodPost, "/tenants/t1/providers", strings.NewReader(providerBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)

	// List providers
	req = httptest.NewRequest(http.MethodGet, "/tenants/t1/providers", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}
