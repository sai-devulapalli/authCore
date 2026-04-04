package handler

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	auditsvc "github.com/authplex/internal/application/audit"
	"github.com/authplex/internal/adapter/cache"
	"github.com/stretchr/testify/assert"
)

func TestAuditHandler_Query(t *testing.T) {
	repo := cache.NewInMemoryAuditRepository()
	svc := auditsvc.NewService(repo, slog.Default())
	h := NewAuditHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/tenants/t1/audit?limit=10", nil)
	w := httptest.NewRecorder()
	h.HandleAuditLogs(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "events")
}

func TestAuditHandler_MethodNotAllowed(t *testing.T) {
	repo := cache.NewInMemoryAuditRepository()
	svc := auditsvc.NewService(repo, slog.Default())
	h := NewAuditHandler(svc)

	req := httptest.NewRequest(http.MethodPost, "/tenants/t1/audit", nil)
	w := httptest.NewRecorder()
	h.HandleAuditLogs(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuditHandler_MissingTenant(t *testing.T) {
	repo := cache.NewInMemoryAuditRepository()
	svc := auditsvc.NewService(repo, slog.Default())
	h := NewAuditHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/audit", nil)
	w := httptest.NewRecorder()
	h.HandleAuditLogs(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}
