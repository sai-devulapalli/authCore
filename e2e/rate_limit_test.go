//go:build e2e

package e2e

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The rate limiter is shared across /login, /token, /otp/verify, /mfa/verify
// and tracks per-IP. In the test server all requests come from 127.0.0.1.
// The rate limiter uses ErrBadRequest which maps to HTTP 400.
// Each test gets its own server instance so counters are fresh.

// TestE2E_RateLimiting_Login verifies that the /login endpoint rate limits
// at 20 requests per minute per IP.
func TestE2E_RateLimiting_Login(t *testing.T) {
	env := setupFullTestServer(t)
	defer env.server.Close()

	tenantID := env.createTenant(t, "rl-login-t", "RS256")
	env.registerUser(t, tenantID, "rl@example.com", "pass123", "RL User")

	headers := map[string]string{"X-Tenant-ID": tenantID}

	// Send 20 login requests — all should get 401 (wrong password, not rate limited)
	for i := 0; i < 20; i++ {
		status, _ := env.doJSON(t, http.MethodPost, "/login", map[string]any{
			"email":    "rl@example.com",
			"password": "wrongpass",
		}, headers)
		assert.Equal(t, http.StatusUnauthorized, status,
			"request %d: expected 401, got %d", i+1, status)
	}

	// 21st request should be rate limited (returns 400 with "rate limit exceeded")
	status, body := env.doJSON(t, http.MethodPost, "/login", map[string]any{
		"email":    "rl@example.com",
		"password": "wrongpass",
	}, headers)
	assert.Equal(t, http.StatusBadRequest, status, "21st request should be rate limited (400)")
	if errObj, ok := body["error"].(map[string]any); ok {
		msg, _ := errObj["message"].(string)
		assert.Contains(t, msg, "rate limit", "error should mention rate limit")
	}
}

// TestE2E_RateLimiting_Token verifies that the /token endpoint rate limits.
func TestE2E_RateLimiting_Token(t *testing.T) {
	env := setupFullTestServer(t)
	defer env.server.Close()

	tenantID := env.createTenant(t, "rl-token-t", "RS256")
	headers := map[string]string{"X-Tenant-ID": tenantID}

	// Send 20 token requests (they'll fail with bad params, but rate limiter still counts)
	for i := 0; i < 20; i++ {
		env.postForm(t, "/token", "grant_type=invalid", headers)
	}

	// 21st should be rate limited
	status, body := env.postForm(t, "/token", "grant_type=invalid", headers)
	assert.Equal(t, http.StatusBadRequest, status, "21st /token request should be rate limited")
	if errObj, ok := body["error"].(map[string]any); ok {
		msg, _ := errObj["message"].(string)
		assert.Contains(t, msg, "rate limit", "error should mention rate limit")
	}
}

// TestE2E_RateLimiting_RetryAfterHeader verifies rate limited responses include Retry-After header.
func TestE2E_RateLimiting_RetryAfterHeader(t *testing.T) {
	env := setupFullTestServer(t)
	defer env.server.Close()

	tenantID := env.createTenant(t, "rl-retry-t", "RS256")
	env.registerUser(t, tenantID, "retry@example.com", "pass123", "Retry User")

	// Exhaust rate limit on /login
	for i := 0; i < 20; i++ {
		env.doJSON(t, http.MethodPost, "/login", map[string]any{
			"email":    "retry@example.com",
			"password": "wrong",
		}, map[string]string{"X-Tenant-ID": tenantID})
	}

	// 21st request — check for Retry-After header
	req, err := http.NewRequest(http.MethodPost, env.server.URL+"/login", nil)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", tenantID)

	client := env.server.Client()
	resp, err := client.Do(req)
	require.NoError(t, err)
	resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "should be rate limited")
	retryAfter := resp.Header.Get("Retry-After")
	assert.Equal(t, "60", retryAfter, "should include Retry-After: 60 header")
}
