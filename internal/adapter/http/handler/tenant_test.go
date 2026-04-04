package handler

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	tenantsvc "github.com/authplex/internal/application/tenant"
	"github.com/authplex/internal/domain/tenant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Mock Repository for Tenant Handler ---

type mockTenantHandlerRepo struct {
	getByIDFunc func(ctx context.Context, id string) (tenant.Tenant, error)
	createFunc  func(ctx context.Context, t tenant.Tenant) error
	updateFunc  func(ctx context.Context, t tenant.Tenant) error
	deleteFunc  func(ctx context.Context, id string) error
	listFunc    func(ctx context.Context, offset, limit int) ([]tenant.Tenant, int, error)
}

func (m *mockTenantHandlerRepo) GetByID(ctx context.Context, id string) (tenant.Tenant, error) {
	if m.getByIDFunc != nil {
		return m.getByIDFunc(ctx, id)
	}
	return tenant.Tenant{}, errors.New("not found")
}

func (m *mockTenantHandlerRepo) GetByDomain(_ context.Context, _ string) (tenant.Tenant, error) {
	return tenant.Tenant{}, errors.New("not found")
}

func (m *mockTenantHandlerRepo) Create(ctx context.Context, t tenant.Tenant) error {
	if m.createFunc != nil {
		return m.createFunc(ctx, t)
	}
	return nil
}

func (m *mockTenantHandlerRepo) Update(ctx context.Context, t tenant.Tenant) error {
	if m.updateFunc != nil {
		return m.updateFunc(ctx, t)
	}
	return nil
}

func (m *mockTenantHandlerRepo) Delete(ctx context.Context, id string) error {
	if m.deleteFunc != nil {
		return m.deleteFunc(ctx, id)
	}
	return nil
}

func (m *mockTenantHandlerRepo) List(ctx context.Context, offset, limit int) ([]tenant.Tenant, int, error) {
	if m.listFunc != nil {
		return m.listFunc(ctx, offset, limit)
	}
	return nil, 0, nil
}

func (m *mockTenantHandlerRepo) IncrementTokenVersion(_ context.Context, _ string) error {
	return nil
}

func newTenantHandler(repo tenant.Repository) *TenantHandler {
	svc := tenantsvc.NewService(repo, slog.Default())
	return NewTenantHandler(svc)
}

// --- Tests ---

func TestTenantHandler_Create(t *testing.T) {
	h := newTenantHandler(&mockTenantHandlerRepo{})

	body := `{"id":"t1","domain":"example.com","issuer":"https://example.com","algorithm":"RS256"}`
	req := httptest.NewRequest(http.MethodPost, "/tenants", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.HandleTenants(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestTenantHandler_List(t *testing.T) {
	repo := &mockTenantHandlerRepo{
		listFunc: func(_ context.Context, _, _ int) ([]tenant.Tenant, int, error) {
			return []tenant.Tenant{{ID: "t1"}, {ID: "t2"}}, 2, nil
		},
	}
	h := newTenantHandler(repo)

	req := httptest.NewRequest(http.MethodGet, "/tenants?offset=0&limit=10", nil)
	w := httptest.NewRecorder()

	h.HandleTenants(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	data := resp["data"].(map[string]any)
	assert.Equal(t, float64(2), data["total"])
}

func TestTenantHandler_Get(t *testing.T) {
	repo := &mockTenantHandlerRepo{
		getByIDFunc: func(_ context.Context, id string) (tenant.Tenant, error) {
			return tenant.Tenant{ID: id, Domain: "example.com"}, nil
		},
	}
	h := newTenantHandler(repo)

	req := httptest.NewRequest(http.MethodGet, "/tenants/t1", nil)
	w := httptest.NewRecorder()

	h.HandleTenant(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestTenantHandler_Get_NotFound(t *testing.T) {
	h := newTenantHandler(&mockTenantHandlerRepo{})

	req := httptest.NewRequest(http.MethodGet, "/tenants/nonexistent", nil)
	w := httptest.NewRecorder()

	h.HandleTenant(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestTenantHandler_Update(t *testing.T) {
	repo := &mockTenantHandlerRepo{
		getByIDFunc: func(_ context.Context, id string) (tenant.Tenant, error) {
			return tenant.Tenant{ID: id, Domain: "old.com", Issuer: "https://old.com"}, nil
		},
	}
	h := newTenantHandler(repo)

	body := `{"domain":"new.com"}`
	req := httptest.NewRequest(http.MethodPut, "/tenants/t1", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.HandleTenant(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestTenantHandler_Delete(t *testing.T) {
	h := newTenantHandler(&mockTenantHandlerRepo{})

	req := httptest.NewRequest(http.MethodDelete, "/tenants/t1", nil)
	w := httptest.NewRecorder()

	h.HandleTenant(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
}

func TestTenantHandler_MethodNotAllowed(t *testing.T) {
	h := newTenantHandler(&mockTenantHandlerRepo{})

	req := httptest.NewRequest(http.MethodPatch, "/tenants", nil)
	w := httptest.NewRecorder()

	h.HandleTenants(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestExtractTenantID(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/tenants/t1", "t1"},
		{"/tenants/abc-123", "abc-123"},
		{"/tenants", ""},
		{"/other/path", ""},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.want, extractTenantID(tt.path))
		})
	}
}

func TestTenantHandler_ResponseEnveloped(t *testing.T) {
	h := newTenantHandler(&mockTenantHandlerRepo{})

	body := `{"id":"t1","domain":"example.com","issuer":"https://example.com","algorithm":"RS256"}`
	req := httptest.NewRequest(http.MethodPost, "/tenants", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.HandleTenants(w, req)

	// Management API uses WriteJSON with {data:...} envelope
	var raw map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &raw))
	_, hasData := raw["data"]
	assert.True(t, hasData, "management API should use data envelope")
}
