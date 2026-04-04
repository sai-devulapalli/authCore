package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/authplex/internal/adapter/cache"
	webhooksvc "github.com/authplex/internal/application/webhook"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestWebhookHandler() *WebhookHandler {
	repo := cache.NewInMemoryWebhookRepository()
	svc := webhooksvc.NewService(repo, slog.Default())
	return NewWebhookHandler(svc)
}

func TestWebhookHandler_Create(t *testing.T) {
	h := newTestWebhookHandler()

	body := `{"url":"https://example.com","events":["login"]}`
	req := httptest.NewRequest(http.MethodPost, "/tenants/t1/webhooks", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.HandleWebhooks(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var outer map[string]any
	err := json.NewDecoder(w.Body).Decode(&outer)
	require.NoError(t, err)
	// WriteJSON wraps in {"data": ...}
	data, ok := outer["data"].(map[string]any)
	require.True(t, ok, "expected data envelope")
	assert.NotEmpty(t, data["ID"])
	assert.Equal(t, "https://example.com", data["URL"])
}

func TestWebhookHandler_Create_MissingURL(t *testing.T) {
	h := newTestWebhookHandler()

	body := `{"url":"","events":[]}`
	req := httptest.NewRequest(http.MethodPost, "/tenants/t1/webhooks", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.HandleWebhooks(w, req)

	assert.NotEqual(t, http.StatusCreated, w.Code)
}

func TestWebhookHandler_Create_InvalidJSON(t *testing.T) {
	h := newTestWebhookHandler()

	req := httptest.NewRequest(http.MethodPost, "/tenants/t1/webhooks", bytes.NewBufferString(`{not-json}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.HandleWebhooks(w, req)

	assert.NotEqual(t, http.StatusCreated, w.Code)
}

func TestWebhookHandler_Create_MissingTenantID(t *testing.T) {
	h := newTestWebhookHandler()

	body := `{"url":"https://example.com","events":["login"]}`
	req := httptest.NewRequest(http.MethodPost, "/webhooks", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.HandleWebhooks(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestWebhookHandler_List(t *testing.T) {
	// Pre-create a webhook via service directly
	ctx := context.Background()
	repo := cache.NewInMemoryWebhookRepository()
	svc := webhooksvc.NewService(repo, slog.Default())
	h2 := NewWebhookHandler(svc)

	_, err := svc.Create(ctx, "t1", "https://example.com", []string{"login"})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/tenants/t1/webhooks", nil)
	w := httptest.NewRecorder()

	h2.HandleWebhooks(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var outer map[string]any
	decodeErr := json.NewDecoder(w.Body).Decode(&outer)
	require.NoError(t, decodeErr)
	// WriteJSON wraps in {"data": ...}
	data, ok := outer["data"].(map[string]any)
	require.True(t, ok, "expected data envelope")
	assert.Contains(t, data, "webhooks")
	assert.Contains(t, data, "count")
	count, ok := data["count"].(float64)
	require.True(t, ok)
	assert.Equal(t, float64(1), count)
}

func TestWebhookHandler_List_MissingTenant(t *testing.T) {
	h := newTestWebhookHandler()

	req := httptest.NewRequest(http.MethodGet, "/webhooks", nil)
	w := httptest.NewRecorder()

	h.HandleWebhooks(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestWebhookHandler_HandleWebhooks_MethodNotAllowed(t *testing.T) {
	h := newTestWebhookHandler()

	// tenantID must be present so we get past the tenant check and hit the method switch.
	// httputil.MethodNotAllowed maps to ErrBadRequest → HTTP 400.
	req := httptest.NewRequest(http.MethodPut, "/tenants/t1/webhooks", nil)
	w := httptest.NewRecorder()

	h.HandleWebhooks(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestWebhookHandler_Delete(t *testing.T) {
	ctx := context.Background()
	repo := cache.NewInMemoryWebhookRepository()
	svc := webhooksvc.NewService(repo, slog.Default())
	h := NewWebhookHandler(svc)

	wh, err := svc.Create(ctx, "t1", "https://example.com", []string{"login"})
	require.NoError(t, err)
	require.NotNil(t, wh)

	req := httptest.NewRequest(http.MethodDelete, "/tenants/t1/webhooks/"+wh.ID, nil)
	w := httptest.NewRecorder()

	h.HandleWebhook(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
}

func TestWebhookHandler_Delete_MissingIDs(t *testing.T) {
	h := newTestWebhookHandler()

	// Missing tenant ID — path has no "tenants" segment
	req := httptest.NewRequest(http.MethodDelete, "/webhooks/wid", nil)
	w := httptest.NewRecorder()

	h.HandleWebhook(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}
