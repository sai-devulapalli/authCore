package handler

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/authplex/internal/application/auth"
	"github.com/authplex/internal/application/jwks"
	"github.com/authplex/internal/adapter/cache"
	"github.com/stretchr/testify/assert"
)

func newDeviceService() *auth.Service {
	jwksSvc := jwks.NewService(&mockAuthJWKRepo{}, &mockAuthGen{}, &mockAuthConv{}, slog.Default())
	svc := auth.NewService(&mockAuthCodeRepo{}, jwksSvc, &mockAuthSigner{}, slog.Default())
	svc.WithDeviceRepo(cache.NewInMemoryDeviceRepository())
	return svc
}

func TestDeviceHandler_Success(t *testing.T) {
	svc := newDeviceService()
	h := NewDeviceHandler(svc)

	body := "client_id=client-1&scope=openid"
	req := httptest.NewRequest(http.MethodPost, "/device/authorize", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.HandleDeviceAuthorize(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDeviceHandler_MethodNotAllowed(t *testing.T) {
	h := NewDeviceHandler(newDeviceService())

	req := httptest.NewRequest(http.MethodGet, "/device/authorize", nil)
	w := httptest.NewRecorder()

	h.HandleDeviceAuthorize(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}
