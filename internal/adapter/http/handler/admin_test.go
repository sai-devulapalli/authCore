package handler

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/authplex/internal/adapter/cache"
	adaptcrypto "github.com/authplex/internal/adapter/crypto"
	adminsvc "github.com/authplex/internal/application/admin"
	"github.com/authplex/internal/application/jwks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestAdminHandler() (*AdminHandler, *adminsvc.Service) {
	log := slog.Default()
	keyGen := adaptcrypto.NewKeyGenerator()
	keyConv := adaptcrypto.NewJWKConverter()
	signer := adaptcrypto.NewJWTSigner()
	hasher := adaptcrypto.NewBcryptHasher()
	jwksSvc := jwks.NewService(cache.NewInMemoryJWKRepository(), keyGen, keyConv, log)
	adminRepo := cache.NewInMemoryAdminUserRepository()
	adminSvc := adminsvc.NewService(adminRepo, hasher, log)
	handler := NewAdminHandler(adminSvc, jwksSvc, signer, "http://localhost:8080", "test-bootstrap-key")
	return handler, adminSvc
}

// bootstrapAdmin is a test helper that bootstraps an admin user and returns the handler.
func bootstrapAdmin(t *testing.T) *AdminHandler {
	t.Helper()
	h, _ := newTestAdminHandler()

	body := `{"email":"admin@test.com","password":"secret123","bootstrap_key":"test-bootstrap-key"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/bootstrap", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.HandleBootstrap(w, req)
	require.Equal(t, http.StatusCreated, w.Code, "bootstrap should succeed")
	return h
}

// --- Bootstrap tests ---

func TestAdminHandler_Bootstrap_Success(t *testing.T) {
	h, _ := newTestAdminHandler()

	body := `{"email":"admin@test.com","password":"secret123","bootstrap_key":"test-bootstrap-key"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/bootstrap", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.HandleBootstrap(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var outer map[string]any
	err := json.NewDecoder(w.Body).Decode(&outer)
	require.NoError(t, err)

	data, ok := outer["data"].(map[string]any)
	require.True(t, ok, "expected data envelope")
	assert.NotEmpty(t, data["id"])
	assert.Equal(t, "admin@test.com", data["email"])
	assert.Equal(t, "super_admin", data["role"])
}

func TestAdminHandler_Bootstrap_WrongMethod(t *testing.T) {
	h, _ := newTestAdminHandler()

	req := httptest.NewRequest(http.MethodGet, "/admin/bootstrap", nil)
	w := httptest.NewRecorder()

	h.HandleBootstrap(w, req)

	assert.NotEqual(t, http.StatusCreated, w.Code)

	var outer map[string]any
	err := json.NewDecoder(w.Body).Decode(&outer)
	require.NoError(t, err)
	assert.NotNil(t, outer["error"], "expected error field")
}

func TestAdminHandler_Bootstrap_InvalidJSON(t *testing.T) {
	h, _ := newTestAdminHandler()

	req := httptest.NewRequest(http.MethodPost, "/admin/bootstrap", bytes.NewBufferString(`{not-json}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.HandleBootstrap(w, req)

	assert.NotEqual(t, http.StatusCreated, w.Code)

	var outer map[string]any
	err := json.NewDecoder(w.Body).Decode(&outer)
	require.NoError(t, err)
	assert.NotNil(t, outer["error"], "expected error field")
}

// --- Login tests ---

func TestAdminHandler_Login_Success(t *testing.T) {
	h := bootstrapAdmin(t)

	body := `{"email":"admin@test.com","password":"secret123"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/login", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.HandleLogin(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var outer map[string]any
	err := json.NewDecoder(w.Body).Decode(&outer)
	require.NoError(t, err)

	data, ok := outer["data"].(map[string]any)
	require.True(t, ok, "expected data envelope")
	assert.NotEmpty(t, data["token"], "expected token field")
	assert.Equal(t, "Bearer", data["token_type"])
}

func TestAdminHandler_Login_WrongPassword(t *testing.T) {
	h := bootstrapAdmin(t)

	body := `{"email":"admin@test.com","password":"wrongpassword"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/login", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.HandleLogin(w, req)

	assert.NotEqual(t, http.StatusOK, w.Code)

	var outer map[string]any
	err := json.NewDecoder(w.Body).Decode(&outer)
	require.NoError(t, err)
	assert.NotNil(t, outer["error"], "expected error field")
}

func TestAdminHandler_Login_WrongMethod(t *testing.T) {
	h, _ := newTestAdminHandler()

	req := httptest.NewRequest(http.MethodGet, "/admin/login", nil)
	w := httptest.NewRecorder()

	h.HandleLogin(w, req)

	assert.NotEqual(t, http.StatusOK, w.Code)

	var outer map[string]any
	err := json.NewDecoder(w.Body).Decode(&outer)
	require.NoError(t, err)
	assert.NotNil(t, outer["error"], "expected error field")
}

// --- HandleUsers tests ---

func TestAdminHandler_HandleUsers_GetEmpty(t *testing.T) {
	h, _ := newTestAdminHandler()

	req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	w := httptest.NewRecorder()

	h.HandleUsers(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var outer map[string]any
	err := json.NewDecoder(w.Body).Decode(&outer)
	require.NoError(t, err)

	data, ok := outer["data"].(map[string]any)
	require.True(t, ok, "expected data envelope")
	admins, ok := data["admins"].([]any)
	require.True(t, ok, "expected admins list")
	assert.Empty(t, admins)
}

func TestAdminHandler_HandleUsers_Post(t *testing.T) {
	h, _ := newTestAdminHandler()

	body := `{"email":"tenant-admin@test.com","password":"secret123","role":"tenant_admin","tenant_ids":[]}`
	req := httptest.NewRequest(http.MethodPost, "/admin/users", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.HandleUsers(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var outer map[string]any
	err := json.NewDecoder(w.Body).Decode(&outer)
	require.NoError(t, err)

	data, ok := outer["data"].(map[string]any)
	require.True(t, ok, "expected data envelope")
	assert.NotEmpty(t, data["id"])
	assert.Equal(t, "tenant-admin@test.com", data["email"])
	assert.Equal(t, "tenant_admin", data["role"])
}

func TestAdminHandler_HandleUsers_MethodNotAllowed(t *testing.T) {
	h, _ := newTestAdminHandler()

	req := httptest.NewRequest(http.MethodPut, "/admin/users", nil)
	w := httptest.NewRecorder()

	h.HandleUsers(w, req)

	assert.NotEqual(t, http.StatusOK, w.Code)
	assert.NotEqual(t, http.StatusCreated, w.Code)

	var outer map[string]any
	err := json.NewDecoder(w.Body).Decode(&outer)
	require.NoError(t, err)
	assert.NotNil(t, outer["error"], "expected error field")
}

// --- generateAdminJTI test ---

func TestGenerateAdminJTI(t *testing.T) {
	jti, err := generateAdminJTI()
	require.NoError(t, err)
	assert.NotEmpty(t, jti)

	// Each call should produce a unique value
	jti2, err2 := generateAdminJTI()
	require.NoError(t, err2)
	assert.NotEqual(t, jti, jti2, "JTIs should be unique")
}
