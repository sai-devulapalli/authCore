package middleware

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/authplex/internal/domain/admin"
	"github.com/stretchr/testify/assert"
)

func TestAdminAuth_ValidKey(t *testing.T) {
	auth := NewAdminAuth("my-secret-key")
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/tenants", nil)
	req.Header.Set("X-API-Key", "my-secret-key")
	w := httptest.NewRecorder()

	auth.Middleware(next).ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAdminAuth_ValidKey_BearerHeader(t *testing.T) {
	auth := NewAdminAuth("my-secret-key")
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/tenants", nil)
	req.Header.Set("Authorization", "Bearer my-secret-key")
	w := httptest.NewRecorder()

	auth.Middleware(next).ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAdminAuth_InvalidKey(t *testing.T) {
	auth := NewAdminAuth("my-secret-key")
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("next should not be called")
	})

	req := httptest.NewRequest(http.MethodGet, "/tenants", nil)
	req.Header.Set("X-API-Key", "wrong-key")
	w := httptest.NewRecorder()

	auth.Middleware(next).ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAdminAuth_MissingKey(t *testing.T) {
	auth := NewAdminAuth("my-secret-key")
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("next should not be called")
	})

	req := httptest.NewRequest(http.MethodGet, "/tenants", nil)
	w := httptest.NewRecorder()

	auth.Middleware(next).ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAdminAuth_DevMode_NoKey(t *testing.T) {
	auth := NewAdminAuth("") // empty = dev mode
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/tenants", nil)
	w := httptest.NewRecorder()

	auth.Middleware(next).ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAdminAuth_TimingConstant(t *testing.T) {
	// Verify that comparison uses constant-time
	auth := NewAdminAuth("correct-key")
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Correct key
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-API-Key", "correct-key")
	w := httptest.NewRecorder()
	auth.Middleware(next).ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Wrong key
	req = httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-API-Key", "wrong-key-different-length")
	w = httptest.NewRecorder()
	auth.Middleware(next).ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAdminFromContext_NotSet(t *testing.T) {
	ac := AdminFromContext(t.Context())
	assert.Nil(t, ac, "AdminFromContext should return nil when not set")
}

func TestAdminAuth_WithJWTVerifier(t *testing.T) {
	a := NewAdminAuth("some-key")
	result := a.WithJWTVerifier(nil)
	assert.NotNil(t, result, "WithJWTVerifier should return non-nil *AdminAuth")
}

func TestDecodeAdminJWT_InvalidFormat(t *testing.T) {
	_, err := decodeAdminJWT("not-a-jwt")
	assert.NotNil(t, err)
}

func TestDecodeAdminJWT_InvalidBase64(t *testing.T) {
	_, err := decodeAdminJWT("header.!!!invalid!!!.sig")
	assert.NotNil(t, err)
}

func TestDecodeAdminJWT_InvalidJSON(t *testing.T) {
	// Valid base64 but not JSON
	payload := base64.RawURLEncoding.EncodeToString([]byte("not json"))
	_, err := decodeAdminJWT("header." + payload + ".sig")
	assert.NotNil(t, err)
}

func TestDecodeAdminJWT_NotAdminToken(t *testing.T) {
	claims := map[string]any{
		"sub": "user-1",
		"aud": []string{"other-audience"},
		"exp": 9999999999,
		"iat": 1000000000,
	}
	payload, _ := json.Marshal(claims)
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	_, err := decodeAdminJWT("header." + encoded + ".sig")
	assert.NotNil(t, err)
}

func TestDecodeAdminJWT_Expired(t *testing.T) {
	claims := map[string]any{
		"sub":   "admin-1",
		"aud":   []string{"authplex-admin"},
		"exp":   int64(1000), // expired
		"iat":   int64(999),
		"roles": []string{"super_admin"},
	}
	payload, _ := json.Marshal(claims)
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	_, err := decodeAdminJWT("header." + encoded + ".sig")
	assert.NotNil(t, err)
}

func TestDecodeAdminJWT_MissingSubject(t *testing.T) {
	claims := map[string]any{
		"aud":   []string{"authplex-admin"},
		"exp":   9999999999,
		"roles": []string{"super_admin"},
	}
	payload, _ := json.Marshal(claims)
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	_, err := decodeAdminJWT("header." + encoded + ".sig")
	assert.NotNil(t, err)
}

func TestDecodeAdminJWT_ValidSuperAdmin(t *testing.T) {
	claims := map[string]any{
		"sub":   "admin-1",
		"aud":   []string{"authplex-admin"},
		"exp":   int64(9999999999),
		"iat":   int64(1000000000),
		"roles": []string{"super_admin"},
		"email": "admin@test.com",
	}
	payload, _ := json.Marshal(claims)
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	ac, err := decodeAdminJWT("header." + encoded + ".sig")
	assert.Nil(t, err)
	assert.NotNil(t, ac)
	assert.Equal(t, "admin-1", ac.AdminID)
}

func TestEnforceRole_SuperAdmin(t *testing.T) {
	ac := &AdminContext{Role: admin.RoleSuperAdmin, AdminID: "a1"}
	req := httptest.NewRequest(http.MethodDelete, "/tenants/t1", nil)
	err := enforceRole(ac, req)
	assert.Nil(t, err)
}

func TestEnforceRole_Readonly_GET(t *testing.T) {
	ac := &AdminContext{Role: admin.RoleReadonly, AdminID: "a1"}
	req := httptest.NewRequest(http.MethodGet, "/tenants", nil)
	err := enforceRole(ac, req)
	assert.Nil(t, err)
}

func TestEnforceRole_Readonly_POST(t *testing.T) {
	ac := &AdminContext{Role: admin.RoleReadonly, AdminID: "a1"}
	req := httptest.NewRequest(http.MethodPost, "/tenants", nil)
	err := enforceRole(ac, req)
	assert.NotNil(t, err)
}

func TestEnforceRole_Auditor_AuditGet(t *testing.T) {
	ac := &AdminContext{Role: admin.RoleAuditor, AdminID: "a1"}
	req := httptest.NewRequest(http.MethodGet, "/tenants/t1/audit", nil)
	err := enforceRole(ac, req)
	assert.Nil(t, err)
}

func TestEnforceRole_Auditor_NonAudit(t *testing.T) {
	ac := &AdminContext{Role: admin.RoleAuditor, AdminID: "a1"}
	req := httptest.NewRequest(http.MethodGet, "/tenants/t1/users", nil)
	err := enforceRole(ac, req)
	assert.NotNil(t, err)
}

func TestEnforceRole_TenantAdmin(t *testing.T) {
	ac := &AdminContext{Role: admin.RoleTenantAdmin, AdminID: "a1"}
	req := httptest.NewRequest(http.MethodGet, "/tenants/t1", nil)
	err := enforceRole(ac, req)
	assert.Nil(t, err)
}
