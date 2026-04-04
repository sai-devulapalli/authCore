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

	clientsvc "github.com/authplex/internal/application/client"
	"github.com/authplex/internal/domain/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockClientHandlerRepo struct {
	createFunc  func(ctx context.Context, c client.Client) error
	getByIDFunc func(ctx context.Context, id, tenantID string) (client.Client, error)
	updateFunc  func(ctx context.Context, c client.Client) error
	deleteFunc  func(ctx context.Context, id, tenantID string) error
	listFunc    func(ctx context.Context, tenantID string, offset, limit int) ([]client.Client, int, error)
}

func (m *mockClientHandlerRepo) Create(ctx context.Context, c client.Client) error {
	if m.createFunc != nil {
		return m.createFunc(ctx, c)
	}
	return nil
}
func (m *mockClientHandlerRepo) GetByID(ctx context.Context, id, tenantID string) (client.Client, error) {
	if m.getByIDFunc != nil {
		return m.getByIDFunc(ctx, id, tenantID)
	}
	return client.Client{}, errors.New("not found")
}
func (m *mockClientHandlerRepo) Update(ctx context.Context, c client.Client) error {
	if m.updateFunc != nil {
		return m.updateFunc(ctx, c)
	}
	return nil
}
func (m *mockClientHandlerRepo) Delete(ctx context.Context, id, tenantID string) error {
	if m.deleteFunc != nil {
		return m.deleteFunc(ctx, id, tenantID)
	}
	return nil
}
func (m *mockClientHandlerRepo) List(ctx context.Context, tenantID string, offset, limit int) ([]client.Client, int, error) {
	if m.listFunc != nil {
		return m.listFunc(ctx, tenantID, offset, limit)
	}
	return nil, 0, nil
}

func (m *mockClientHandlerRepo) UpdateAPIKey(_ context.Context, _, _ string, _ []byte) error {
	return nil
}

func (m *mockClientHandlerRepo) GetByAPIKeyHash(_ context.Context, _ []byte, _ string) (client.Client, error) {
	return client.Client{}, errors.New("not found")
}

type mockHasher struct{}

func (m *mockHasher) Hash(_ string) ([]byte, error)        { return []byte("hash"), nil }
func (m *mockHasher) Verify(_ string, _ []byte) error { return nil }

func newClientHandler(repo client.Repository) *ClientHandler {
	svc := clientsvc.NewService(repo, &mockHasher{}, slog.Default())
	return NewClientHandler(svc)
}

func TestClientHandler_Create(t *testing.T) {
	h := newClientHandler(&mockClientHandlerRepo{})

	body := `{"client_name":"App","client_type":"public","redirect_uris":["https://example.com/cb"],"allowed_scopes":["openid"],"grant_types":["authorization_code"]}`
	req := httptest.NewRequest(http.MethodPost, "/tenants/t1/clients", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.HandleClients(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestClientHandler_List(t *testing.T) {
	repo := &mockClientHandlerRepo{
		listFunc: func(_ context.Context, _ string, _, _ int) ([]client.Client, int, error) {
			return []client.Client{{ID: "c1", ClientType: client.Public}}, 1, nil
		},
	}
	h := newClientHandler(repo)

	req := httptest.NewRequest(http.MethodGet, "/tenants/t1/clients", nil)
	w := httptest.NewRecorder()

	h.HandleClients(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestClientHandler_Get(t *testing.T) {
	repo := &mockClientHandlerRepo{
		getByIDFunc: func(_ context.Context, id, _ string) (client.Client, error) {
			return client.Client{ID: id, ClientType: client.Public}, nil
		},
	}
	h := newClientHandler(repo)

	req := httptest.NewRequest(http.MethodGet, "/tenants/t1/clients/c1", nil)
	w := httptest.NewRecorder()

	h.HandleClient(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestClientHandler_Delete(t *testing.T) {
	h := newClientHandler(&mockClientHandlerRepo{})

	req := httptest.NewRequest(http.MethodDelete, "/tenants/t1/clients/c1", nil)
	w := httptest.NewRecorder()

	h.HandleClient(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
}

func TestClientHandler_MethodNotAllowed(t *testing.T) {
	h := newClientHandler(&mockClientHandlerRepo{})

	req := httptest.NewRequest(http.MethodPatch, "/tenants/t1/clients", nil)
	w := httptest.NewRecorder()

	h.HandleClients(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestExtractPathSegment(t *testing.T) {
	tests := []struct {
		path, key string
		offset    int
		want      string
	}{
		{"/tenants/t1/clients/c1", "tenants", 1, "t1"},
		{"/tenants/t1/clients/c1", "clients", 1, "c1"},
		{"/tenants/t1", "clients", 1, ""},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.want, extractPathSegment(tt.path, tt.key, tt.offset))
	}
}

func TestClientHandler_Update(t *testing.T) {
	repo := &mockClientHandlerRepo{
		getByIDFunc: func(_ context.Context, id, _ string) (client.Client, error) {
			return client.Client{ID: id, ClientName: "Old", ClientType: client.Public}, nil
		},
	}
	h := newClientHandler(repo)

	body := `{"client_name":"New"}`
	req := httptest.NewRequest(http.MethodPut, "/tenants/t1/clients/c1", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.HandleClient(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestClientHandler_GetNotFound(t *testing.T) {
	h := newClientHandler(&mockClientHandlerRepo{})

	req := httptest.NewRequest(http.MethodGet, "/tenants/t1/clients/nonexistent", nil)
	w := httptest.NewRecorder()

	h.HandleClient(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestClientHandler_HandleClient_MethodNotAllowed(t *testing.T) {
	h := newClientHandler(&mockClientHandlerRepo{})

	req := httptest.NewRequest(http.MethodPatch, "/tenants/t1/clients/c1", nil)
	w := httptest.NewRecorder()

	h.HandleClient(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestClientHandler_HandleClient_MissingID(t *testing.T) {
	h := newClientHandler(&mockClientHandlerRepo{})

	req := httptest.NewRequest(http.MethodGet, "/tenants/t1", nil)
	w := httptest.NewRecorder()

	h.HandleClient(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestClientHandler_HandleClients_MissingTenantID(t *testing.T) {
	h := newClientHandler(&mockClientHandlerRepo{})

	req := httptest.NewRequest(http.MethodGet, "/clients", nil)
	w := httptest.NewRecorder()

	h.HandleClients(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestClientHandler_ResponseEnveloped(t *testing.T) {
	h := newClientHandler(&mockClientHandlerRepo{})

	body := `{"client_name":"App","client_type":"public","redirect_uris":["https://example.com/cb"],"allowed_scopes":["openid"],"grant_types":["authorization_code"]}`
	req := httptest.NewRequest(http.MethodPost, "/tenants/t1/clients", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.HandleClients(w, req)

	var raw map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &raw))
	_, hasData := raw["data"]
	assert.True(t, hasData, "client management API should use data envelope")
}

func TestClientHandler_HandleAPIKey_Success(t *testing.T) {
	repo := &mockClientHandlerRepo{
		getByIDFunc: func(_ context.Context, id, _ string) (client.Client, error) {
			return client.Client{ID: id, TenantID: "t1", ClientType: client.Public}, nil
		},
	}
	h := newClientHandler(repo)

	req := httptest.NewRequest(http.MethodPost, "/tenants/t1/clients/c1/api-key", nil)
	w := httptest.NewRecorder()

	h.HandleAPIKey(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "api_key")
}

func TestClientHandler_HandleAPIKey_MethodNotAllowed(t *testing.T) {
	h := newClientHandler(&mockClientHandlerRepo{})

	req := httptest.NewRequest(http.MethodGet, "/tenants/t1/clients/c1/api-key", nil)
	w := httptest.NewRecorder()

	h.HandleAPIKey(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestClientHandler_HandleAPIKey_MissingTenantOrClient(t *testing.T) {
	h := newClientHandler(&mockClientHandlerRepo{})

	req := httptest.NewRequest(http.MethodPost, "/api-key", nil)
	w := httptest.NewRecorder()

	h.HandleAPIKey(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}
