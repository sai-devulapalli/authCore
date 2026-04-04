package handler

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/authplex/internal/application/jwks"
	"github.com/authplex/internal/domain/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Mock implementations for JWKS handler tests ---

type mockJWKRepo struct {
	getAllPublicFunc func(ctx context.Context, tenantID string) ([]jwk.KeyPair, error)
}

func (m *mockJWKRepo) Store(_ context.Context, _ jwk.KeyPair) error          { return nil }
func (m *mockJWKRepo) GetActive(_ context.Context, _ string) (jwk.KeyPair, error) {
	return jwk.KeyPair{}, nil
}
func (m *mockJWKRepo) GetAllPublic(ctx context.Context, tenantID string) ([]jwk.KeyPair, error) {
	if m.getAllPublicFunc != nil {
		return m.getAllPublicFunc(ctx, tenantID)
	}
	return nil, nil
}
func (m *mockJWKRepo) Deactivate(_ context.Context, _ string) error { return nil }
func (m *mockJWKRepo) GetAllActiveTenantIDs(_ context.Context) ([]string, error) { return nil, nil }
func (m *mockJWKRepo) DeleteInactive(_ context.Context, _ time.Time) (int64, error) { return 0, nil }

type mockJWKGenerator struct{}

func (m *mockJWKGenerator) GenerateRSA() ([]byte, []byte, error) { return nil, nil, nil }
func (m *mockJWKGenerator) GenerateEC() ([]byte, []byte, error)  { return nil, nil, nil }

type mockJWKConverter struct{}

func (m *mockJWKConverter) PEMToPublicJWK(_ []byte, kid string, alg string) (jwk.PublicJWK, error) {
	return jwk.PublicJWK{KTY: "RSA", Use: "sig", KID: kid, ALG: alg, N: "modulus", E: "exponent"}, nil
}

// --- Tests ---

func TestJWKSHandler_Success(t *testing.T) {
	repo := &mockJWKRepo{
		getAllPublicFunc: func(_ context.Context, _ string) ([]jwk.KeyPair, error) {
			return []jwk.KeyPair{
				{ID: "kid-1", Algorithm: "RS256", PublicKey: []byte("pub")},
			}, nil
		},
	}
	svc := jwks.NewService(repo, &mockJWKGenerator{}, &mockJWKConverter{}, slog.Default())
	h := NewJWKSHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/jwks", nil)
	req.Header.Set("X-Tenant-ID", "tenant-1")
	w := httptest.NewRecorder()

	h.HandleJWKS(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json; charset=utf-8", w.Header().Get("Content-Type"))

	var set jwk.Set
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &set))
	assert.Len(t, set.Keys, 1)
	assert.Equal(t, "kid-1", set.Keys[0].KID)
	assert.Equal(t, "RS256", set.Keys[0].ALG)
}

func TestJWKSHandler_EmptyKeys(t *testing.T) {
	repo := &mockJWKRepo{
		getAllPublicFunc: func(_ context.Context, _ string) ([]jwk.KeyPair, error) {
			return []jwk.KeyPair{}, nil
		},
	}
	svc := jwks.NewService(repo, &mockJWKGenerator{}, &mockJWKConverter{}, slog.Default())
	h := NewJWKSHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/jwks", nil)
	w := httptest.NewRecorder()

	h.HandleJWKS(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var set jwk.Set
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &set))
	assert.Empty(t, set.Keys)
}

func TestJWKSHandler_MethodNotAllowed(t *testing.T) {
	svc := jwks.NewService(&mockJWKRepo{}, &mockJWKGenerator{}, &mockJWKConverter{}, slog.Default())
	h := NewJWKSHandler(svc)

	req := httptest.NewRequest(http.MethodPost, "/jwks", nil)
	w := httptest.NewRecorder()

	h.HandleJWKS(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestJWKSHandler_ResponseNotEnveloped(t *testing.T) {
	repo := &mockJWKRepo{
		getAllPublicFunc: func(_ context.Context, _ string) ([]jwk.KeyPair, error) {
			return []jwk.KeyPair{}, nil
		},
	}
	svc := jwks.NewService(repo, &mockJWKGenerator{}, &mockJWKConverter{}, slog.Default())
	h := NewJWKSHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/jwks", nil)
	w := httptest.NewRecorder()

	h.HandleJWKS(w, req)

	var raw map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &raw))
	_, hasData := raw["data"]
	assert.False(t, hasData, "response should not be wrapped in data envelope")
	_, hasKeys := raw["keys"]
	assert.True(t, hasKeys, "response should contain keys at top level")
}

func TestJWKSHandler_DefaultTenantID(t *testing.T) {
	var capturedTenantID string
	repo := &mockJWKRepo{
		getAllPublicFunc: func(_ context.Context, tenantID string) ([]jwk.KeyPair, error) {
			capturedTenantID = tenantID
			return []jwk.KeyPair{}, nil
		},
	}
	svc := jwks.NewService(repo, &mockJWKGenerator{}, &mockJWKConverter{}, slog.Default())
	h := NewJWKSHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/jwks", nil)
	// No X-Tenant-ID header
	w := httptest.NewRecorder()

	h.HandleJWKS(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "default", capturedTenantID)
}
