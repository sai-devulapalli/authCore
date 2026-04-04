package handler

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/authplex/internal/application/auth"
	clientsvc "github.com/authplex/internal/application/client"
	"github.com/authplex/internal/application/jwks"
	"github.com/authplex/internal/domain/client"
	"github.com/authplex/internal/domain/jwk"
	"github.com/authplex/internal/domain/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Mocks for authorize handler tests ---

type mockAuthCodeRepo struct {
	storeFunc   func(ctx context.Context, code token.AuthorizationCode) error
	consumeFunc func(ctx context.Context, code string) (token.AuthorizationCode, error)
}

func (m *mockAuthCodeRepo) Store(ctx context.Context, code token.AuthorizationCode) error {
	if m.storeFunc != nil {
		return m.storeFunc(ctx, code)
	}
	return nil
}

func (m *mockAuthCodeRepo) Consume(ctx context.Context, code string) (token.AuthorizationCode, error) {
	if m.consumeFunc != nil {
		return m.consumeFunc(ctx, code)
	}
	return token.AuthorizationCode{}, errors.New("not found")
}

type mockAuthJWKRepo struct{}

func (m *mockAuthJWKRepo) Store(_ context.Context, _ jwk.KeyPair) error { return nil }
func (m *mockAuthJWKRepo) GetActive(_ context.Context, _ string) (jwk.KeyPair, error) {
	return jwk.KeyPair{ID: "kid-1", Algorithm: "RS256", PrivateKey: []byte("key"), Active: true}, nil
}
func (m *mockAuthJWKRepo) GetAllPublic(_ context.Context, _ string) ([]jwk.KeyPair, error) {
	return nil, nil
}
func (m *mockAuthJWKRepo) Deactivate(_ context.Context, _ string) error { return nil }
func (m *mockAuthJWKRepo) GetAllActiveTenantIDs(_ context.Context) ([]string, error) { return nil, nil }
func (m *mockAuthJWKRepo) DeleteInactive(_ context.Context, _ time.Time) (int64, error) { return 0, nil }

type mockAuthGen struct{}

func (m *mockAuthGen) GenerateRSA() ([]byte, []byte, error) { return nil, nil, nil }
func (m *mockAuthGen) GenerateEC() ([]byte, []byte, error)  { return nil, nil, nil }

type mockAuthConv struct{}

func (m *mockAuthConv) PEMToPublicJWK(_ []byte, _ string, _ string) (jwk.PublicJWK, error) {
	return jwk.PublicJWK{}, nil
}

type mockAuthSigner struct{}

func (m *mockAuthSigner) Sign(_ token.Claims, _ string, _ []byte, _ string) (string, error) {
	return "mock-jwt", nil
}

func newAuthService(codeRepo token.CodeRepository) *auth.Service {
	jwksSvc := jwks.NewService(&mockAuthJWKRepo{}, &mockAuthGen{}, &mockAuthConv{}, slog.Default())
	return auth.NewService(codeRepo, jwksSvc, &mockAuthSigner{}, slog.Default())
}

// --- Tests ---

func TestAuthorizeHandler_Success_Redirect(t *testing.T) {
	svc := newAuthService(&mockAuthCodeRepo{})
	h := NewAuthorizeHandler(svc)

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])

	url := "/authorize?response_type=code&client_id=client-1&redirect_uri=https://example.com/callback" +
		"&scope=openid&state=xyz&code_challenge=" + challenge + "&code_challenge_method=S256"
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("X-Subject", "user-123")
	req.Header.Set("X-Tenant-ID", "tenant-1")
	w := httptest.NewRecorder()

	h.HandleAuthorize(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	location := w.Header().Get("Location")
	require.NotEmpty(t, location)
	assert.Contains(t, location, "https://example.com/callback")
	assert.Contains(t, location, "code=")
	assert.Contains(t, location, "state=xyz")
}

func TestAuthorizeHandler_NoAuth_LoginRequired(t *testing.T) {
	svc := newAuthService(&mockAuthCodeRepo{})
	h := NewAuthorizeHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/authorize?response_type=code", nil)
	w := httptest.NewRecorder()

	h.HandleAuthorize(w, req)

	// No session or X-Subject → OIDC login_required
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "login_required")
}

func TestResolveSubject_FromXSubject(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Subject", "user-123")

	subject := resolveSubject(req, nil)
	assert.Equal(t, "user-123", subject)
}

func TestResolveSubject_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	subject := resolveSubject(req, nil)
	assert.Empty(t, subject)
}

func TestAuthorizeHandler_XSubjectFallback(t *testing.T) {
	svc := newAuthService(&mockAuthCodeRepo{})
	h := NewAuthorizeHandler(svc)

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])

	url := "/authorize?response_type=code&client_id=c1&redirect_uri=https://example.com/cb" +
		"&code_challenge=" + challenge + "&code_challenge_method=S256"
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("X-Subject", "user-from-header")
	req.Header.Set("X-Tenant-ID", "t1")
	w := httptest.NewRecorder()

	h.HandleAuthorize(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
}

func TestAuthorizeHandler_InvalidScope(t *testing.T) {
	svc := newAuthService(&mockAuthCodeRepo{})

	// Create a mock client service that returns a client with restricted scopes
	clientRepo := &mockClientHandlerRepo{
		getByIDFunc: func(_ context.Context, _, _ string) (client.Client, error) {
			return client.Client{
				ID:            "c1",
				TenantID:      "t1",
				ClientType:    client.Public,
				RedirectURIs:  []string{"https://example.com/cb"},
				AllowedScopes: []string{"openid", "profile"},
			}, nil
		},
	}
	clientService := clientsvc.NewService(clientRepo, &mockHasher{}, slog.Default())

	h := NewAuthorizeHandler(svc).WithClientService(clientService)

	url := "/authorize?response_type=code&client_id=c1&redirect_uri=https://example.com/cb&scope=openid+admin&code_challenge=test&code_challenge_method=S256"
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("X-Subject", "user-1")
	req.Header.Set("X-Tenant-ID", "t1")
	w := httptest.NewRecorder()

	h.HandleAuthorize(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid_scope")
}

func TestAuthorizeHandler_ValidScope(t *testing.T) {
	svc := newAuthService(&mockAuthCodeRepo{})

	clientRepo := &mockClientHandlerRepo{
		getByIDFunc: func(_ context.Context, _, _ string) (client.Client, error) {
			return client.Client{
				ID:            "c1",
				TenantID:      "t1",
				ClientType:    client.Public,
				RedirectURIs:  []string{"https://example.com/cb"},
				AllowedScopes: []string{"openid", "profile"},
			}, nil
		},
	}
	clientService := clientsvc.NewService(clientRepo, &mockHasher{}, slog.Default())

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])

	h := NewAuthorizeHandler(svc).WithClientService(clientService)

	url := "/authorize?response_type=code&client_id=c1&redirect_uri=https://example.com/cb&scope=openid+profile&code_challenge=" + challenge + "&code_challenge_method=S256"
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("X-Subject", "user-1")
	req.Header.Set("X-Tenant-ID", "t1")
	w := httptest.NewRecorder()

	h.HandleAuthorize(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
}

func TestAuthorizeHandler_InvalidRedirectURI(t *testing.T) {
	svc := newAuthService(&mockAuthCodeRepo{})

	clientRepo := &mockClientHandlerRepo{
		getByIDFunc: func(_ context.Context, _, _ string) (client.Client, error) {
			return client.Client{
				ID:           "c1",
				TenantID:     "t1",
				ClientType:   client.Public,
				RedirectURIs: []string{"https://example.com/cb"},
			}, nil
		},
	}
	clientService := clientsvc.NewService(clientRepo, &mockHasher{}, slog.Default())

	h := NewAuthorizeHandler(svc).WithClientService(clientService)

	url := "/authorize?response_type=code&client_id=c1&redirect_uri=https://evil.com/cb&scope=openid"
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("X-Subject", "user-1")
	req.Header.Set("X-Tenant-ID", "t1")
	w := httptest.NewRecorder()

	h.HandleAuthorize(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid_redirect_uri")
}

func TestAuthorizeHandler_MethodNotAllowed(t *testing.T) {
	svc := newAuthService(&mockAuthCodeRepo{})
	h := NewAuthorizeHandler(svc)

	req := httptest.NewRequest(http.MethodPost, "/authorize", nil)
	w := httptest.NewRecorder()

	h.HandleAuthorize(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthorizeHandler_WithSocialService(t *testing.T) {
	svc := newAuthService(&mockAuthCodeRepo{})
	h := NewAuthorizeHandler(svc)
	result := h.WithSocialService(nil)
	assert.NotNil(t, result, "WithSocialService should return non-nil handler")
}

func TestAuthorizeHandler_WithUserService(t *testing.T) {
	svc := newAuthService(&mockAuthCodeRepo{})
	h := NewAuthorizeHandler(svc)
	result := h.WithUserService(nil)
	assert.NotNil(t, result, "WithUserService should return non-nil handler")
}

func TestAuthorizeHandler_WithMFA(t *testing.T) {
	svc := newAuthService(&mockAuthCodeRepo{})
	h := NewAuthorizeHandler(svc)
	result := h.WithMFA(nil, nil)
	assert.NotNil(t, result, "WithMFA should return non-nil handler")
}
