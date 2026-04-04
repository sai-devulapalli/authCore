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

func newRevokeService() *auth.Service {
	jwksSvc := jwks.NewService(&mockAuthJWKRepo{}, &mockAuthGen{}, &mockAuthConv{}, slog.Default())
	svc := auth.NewService(&mockAuthCodeRepo{}, jwksSvc, &mockAuthSigner{}, slog.Default())
	svc.WithBlacklist(cache.NewInMemoryBlacklist())
	return svc
}

func TestRevokeHandler_Success(t *testing.T) {
	h := NewRevokeHandler(newRevokeService())

	body := "token=some-token&token_type_hint=access_token"
	req := httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.HandleRevoke(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRevokeHandler_MethodNotAllowed(t *testing.T) {
	h := NewRevokeHandler(newRevokeService())

	req := httptest.NewRequest(http.MethodGet, "/revoke", nil)
	w := httptest.NewRecorder()

	h.HandleRevoke(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}
