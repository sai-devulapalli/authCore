package handler

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/authplex/internal/domain/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenHandler_Success(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])

	codeRepo := &mockAuthCodeRepo{
		consumeFunc: func(_ context.Context, _ string) (token.AuthorizationCode, error) {
			return token.AuthorizationCode{
				Code:                "code-123",
				ClientID:            "client-1",
				RedirectURI:         "https://example.com/callback",
				Subject:             "user-123",
				TenantID:            "tenant-1",
				Scope:               "openid",
				CodeChallenge:       challenge,
				CodeChallengeMethod: "S256",
				ExpiresAt:           time.Now().UTC().Add(10 * time.Minute),
			}, nil
		},
	}
	svc := newAuthService(codeRepo)
	h := NewTokenHandler(svc)

	body := "grant_type=authorization_code&code=code-123&redirect_uri=https://example.com/callback" +
		"&client_id=client-1&code_verifier=" + verifier

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.HandleToken(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	assert.Equal(t, "no-cache", w.Header().Get("Pragma"))

	var resp token.TokenResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "mock-jwt", resp.AccessToken)
	assert.Equal(t, "Bearer", resp.TokenType)
	assert.Equal(t, "mock-jwt", resp.IDToken)
}

func TestTokenHandler_MethodNotAllowed(t *testing.T) {
	svc := newAuthService(&mockAuthCodeRepo{})
	h := NewTokenHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/token", nil)
	w := httptest.NewRecorder()

	h.HandleToken(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTokenHandler_MissingGrantType(t *testing.T) {
	svc := newAuthService(&mockAuthCodeRepo{})
	h := NewTokenHandler(svc)

	body := "code=code-123&code_verifier=verifier&client_id=client-1"
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.HandleToken(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTokenHandler_ResponseNotEnveloped(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])

	codeRepo := &mockAuthCodeRepo{
		consumeFunc: func(_ context.Context, _ string) (token.AuthorizationCode, error) {
			return token.AuthorizationCode{
				Code:                "code-123",
				ClientID:            "client-1",
				RedirectURI:         "https://example.com/callback",
				Subject:             "user-123",
				TenantID:            "tenant-1",
				CodeChallenge:       challenge,
				CodeChallengeMethod: "S256",
				ExpiresAt:           time.Now().UTC().Add(10 * time.Minute),
			}, nil
		},
	}
	svc := newAuthService(codeRepo)
	h := NewTokenHandler(svc)

	body := "grant_type=authorization_code&code=code-123&redirect_uri=https://example.com/callback" +
		"&client_id=client-1&code_verifier=" + verifier

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.HandleToken(w, req)

	// Verify response is raw JSON (no {data:...} envelope)
	var raw map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &raw))
	_, hasData := raw["data"]
	assert.False(t, hasData, "response should not be wrapped in data envelope")
	_, hasAccessToken := raw["access_token"]
	assert.True(t, hasAccessToken, "response should contain access_token at top level")
}

func TestTokenHandler_WithClientService(t *testing.T) {
	svc := newAuthService(&mockAuthCodeRepo{})
	h := NewTokenHandler(svc)
	result := h.WithClientService(nil)
	assert.NotNil(t, result, "WithClientService should return non-nil handler")
}
