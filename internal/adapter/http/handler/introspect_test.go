package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/authplex/internal/application/auth"
	"github.com/authplex/internal/application/jwks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newIntrospectService() *auth.Service {
	jwksSvc := jwks.NewService(&mockAuthJWKRepo{}, &mockAuthGen{}, &mockAuthConv{}, slog.Default())
	return auth.NewService(&mockAuthCodeRepo{}, jwksSvc, &mockAuthSigner{}, slog.Default())
}

func TestIntrospectHandler_Inactive(t *testing.T) {
	h := NewIntrospectHandler(newIntrospectService())

	body := "token=not-a-jwt"
	req := httptest.NewRequest(http.MethodPost, "/introspect", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.HandleIntrospect(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.False(t, resp["active"].(bool))
}

func TestIntrospectHandler_MethodNotAllowed(t *testing.T) {
	h := NewIntrospectHandler(newIntrospectService())

	req := httptest.NewRequest(http.MethodGet, "/introspect", nil)
	w := httptest.NewRecorder()

	h.HandleIntrospect(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}
