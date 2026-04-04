package handler

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	providersvc "github.com/authplex/internal/application/provider"
	"github.com/authplex/internal/domain/identity"
	"github.com/stretchr/testify/assert"
)

type mockProviderHandlerRepo struct{}

func (m *mockProviderHandlerRepo) Create(_ context.Context, _ identity.IdentityProvider) error {
	return nil
}
func (m *mockProviderHandlerRepo) GetByID(_ context.Context, id, _ string) (identity.IdentityProvider, error) {
	if id == "p1" {
		return identity.IdentityProvider{ID: "p1", ProviderType: identity.ProviderGoogle, ClientID: "cid", Enabled: true}, nil
	}
	return identity.IdentityProvider{}, errors.New("not found")
}
func (m *mockProviderHandlerRepo) GetByType(_ context.Context, _ string, _ identity.ProviderType) (identity.IdentityProvider, error) {
	return identity.IdentityProvider{}, errors.New("not found")
}
func (m *mockProviderHandlerRepo) List(_ context.Context, _ string) ([]identity.IdentityProvider, error) {
	return []identity.IdentityProvider{{ID: "p1", ProviderType: identity.ProviderGoogle, ClientID: "cid"}}, nil
}
func (m *mockProviderHandlerRepo) Update(_ context.Context, _ identity.IdentityProvider) error {
	return nil
}
func (m *mockProviderHandlerRepo) Delete(_ context.Context, _, _ string) error { return nil }

func TestProviderHandler_Create(t *testing.T) {
	svc := providersvc.NewService(&mockProviderHandlerRepo{}, slog.Default())
	h := NewProviderHandler(svc)

	body := `{"provider_type":"google","client_id":"gid","client_secret":"gsecret","scopes":["openid"]}`
	req := httptest.NewRequest(http.MethodPost, "/tenants/t1/providers", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.HandleProviders(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestProviderHandler_List(t *testing.T) {
	svc := providersvc.NewService(&mockProviderHandlerRepo{}, slog.Default())
	h := NewProviderHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/tenants/t1/providers", nil)
	w := httptest.NewRecorder()

	h.HandleProviders(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestProviderHandler_Get(t *testing.T) {
	svc := providersvc.NewService(&mockProviderHandlerRepo{}, slog.Default())
	h := NewProviderHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/tenants/t1/providers/p1", nil)
	w := httptest.NewRecorder()

	h.HandleProvider(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestProviderHandler_Delete(t *testing.T) {
	svc := providersvc.NewService(&mockProviderHandlerRepo{}, slog.Default())
	h := NewProviderHandler(svc)

	req := httptest.NewRequest(http.MethodDelete, "/tenants/t1/providers/p1", nil)
	w := httptest.NewRecorder()

	h.HandleProvider(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
}

func TestProviderHandler_MethodNotAllowed(t *testing.T) {
	svc := providersvc.NewService(&mockProviderHandlerRepo{}, slog.Default())
	h := NewProviderHandler(svc)

	req := httptest.NewRequest(http.MethodPatch, "/tenants/t1/providers", nil)
	w := httptest.NewRecorder()

	h.HandleProviders(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestProviderHandler_MissingTenantID(t *testing.T) {
	svc := providersvc.NewService(&mockProviderHandlerRepo{}, slog.Default())
	h := NewProviderHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/providers", nil)
	w := httptest.NewRecorder()

	h.HandleProviders(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestProviderHandler_HandleProvider_MethodNotAllowed(t *testing.T) {
	svc := providersvc.NewService(&mockProviderHandlerRepo{}, slog.Default())
	h := NewProviderHandler(svc)

	req := httptest.NewRequest(http.MethodPatch, "/tenants/t1/providers/p1", nil)
	w := httptest.NewRecorder()

	h.HandleProvider(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestProviderHandler_HandleProvider_MissingIDs(t *testing.T) {
	svc := providersvc.NewService(&mockProviderHandlerRepo{}, slog.Default())
	h := NewProviderHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/tenants/t1", nil)
	w := httptest.NewRecorder()

	h.HandleProvider(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}
