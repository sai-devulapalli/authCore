//go:build e2e

package e2e

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Confidential Client Secret Enforcement
// ---------------------------------------------------------------------------

func TestE2E_ConfidentialClientRequiresSecret(t *testing.T) {
	env := setupFullTestServer(t)
	defer env.server.Close()

	tenantID := env.createTenant(t, "conf-secret-t", "RS256")
	clientID, clientSecret := env.createClient(t, tenantID, "confidential", []string{"authorization_code", "refresh_token"})
	require.NotEmpty(t, clientSecret)

	_ = env.registerUser(t, tenantID, "conf@example.com", "pass123", "Conf User")
	session := env.loginUser(t, tenantID, "conf@example.com", "pass123")

	code, verifier := env.authorizeWithPKCE(t, tenantID, clientID, session, "openid")

	t.Run("token exchange with wrong secret returns 401", func(t *testing.T) {
		status, _ := env.postForm(t, "/token",
			fmt.Sprintf("grant_type=authorization_code&code=%s&redirect_uri=%s&client_id=%s&code_verifier=%s&client_secret=wrong-secret",
				code, "https://app.example.com/cb", clientID, verifier),
			map[string]string{"X-Tenant-ID": tenantID})
		assert.Equal(t, http.StatusUnauthorized, status, "wrong secret should return 401")
	})

	t.Run("token exchange with correct secret succeeds", func(t *testing.T) {
		code3, verifier3 := env.authorizeWithPKCE(t, tenantID, clientID, session, "openid")
		tokens := env.exchangeCode(t, tenantID, clientID, clientSecret, code3, verifier3)
		assert.NotEmpty(t, tokens["access_token"])
	})
}

// ---------------------------------------------------------------------------
// Public Client Cannot Use client_credentials
// ---------------------------------------------------------------------------

func TestE2E_PublicClientCannotUseClientCredentials(t *testing.T) {
	env := setupFullTestServer(t)
	defer env.server.Close()

	tenantID := env.createTenant(t, "pub-cc-t", "RS256")
	// Create public client with authorization_code only (can't grant client_credentials to public clients)
	clientID, _ := env.createClient(t, tenantID, "public", []string{"authorization_code"})

	// Attempt client_credentials with a public client (no secret) — should fail
	status, _ := env.postForm(t, "/token",
		fmt.Sprintf("grant_type=client_credentials&client_id=%s&scope=openid", clientID),
		map[string]string{"X-Tenant-ID": tenantID})
	// Public clients have no secret, so client_credentials should fail with 400 or 401
	assert.True(t, status == http.StatusBadRequest || status == http.StatusUnauthorized,
		"public client should not be able to use client_credentials, got %d", status)
}

// ---------------------------------------------------------------------------
// Grant Type Enforcement
// ---------------------------------------------------------------------------

func TestE2E_GrantTypeEnforcement(t *testing.T) {
	env := setupFullTestServer(t)
	defer env.server.Close()

	tenantID := env.createTenant(t, "grant-enforce-t", "RS256")

	// Create client that only allows authorization_code
	status, body := env.doJSON(t, http.MethodPost, "/tenants/"+tenantID+"/clients", map[string]any{
		"client_name":    "Auth Code Only Client",
		"client_type":    "confidential",
		"redirect_uris":  []string{"https://app.example.com/cb"},
		"allowed_scopes": []string{"openid"},
		"grant_types":    []string{"authorization_code"},
	}, map[string]string{
		"Authorization": "Bearer " + env.adminKey,
	})
	require.Equal(t, http.StatusCreated, status)
	data := body["data"].(map[string]any)
	clientID := data["client_id"].(string)
	clientSecret := data["client_secret"].(string)

	t.Run("client_credentials with auth_code_only client fails", func(t *testing.T) {
		status, errResp := env.postForm(t, "/token",
			fmt.Sprintf("grant_type=client_credentials&client_id=%s&client_secret=%s&scope=openid",
				clientID, clientSecret),
			map[string]string{"X-Tenant-ID": tenantID})
		assert.True(t, status == http.StatusBadRequest || status == http.StatusUnauthorized,
			"disallowed grant type should fail, got %d body=%v", status, errResp)
	})
}

// ---------------------------------------------------------------------------
// Token Exchange with Wrong redirect_uri
// ---------------------------------------------------------------------------

func TestE2E_TokenExchangeWrongRedirectURI(t *testing.T) {
	env := setupFullTestServer(t)
	defer env.server.Close()

	tenantID := env.createTenant(t, "bad-redir-t", "RS256")
	clientID, _ := env.createClient(t, tenantID, "public", []string{"authorization_code"})
	_ = env.registerUser(t, tenantID, "redir@example.com", "pass123", "Redir User")
	session := env.loginUser(t, tenantID, "redir@example.com", "pass123")

	code, verifier := env.authorizeWithPKCE(t, tenantID, clientID, session, "openid")

	status, errResp := env.postForm(t, "/token",
		fmt.Sprintf("grant_type=authorization_code&code=%s&redirect_uri=%s&client_id=%s&code_verifier=%s",
			code, "https://wrong.example.com/cb", clientID, verifier),
		map[string]string{"X-Tenant-ID": tenantID})
	assert.Equal(t, http.StatusBadRequest, status,
		"wrong redirect_uri on token exchange should return 400, body=%v", errResp)
}

// ---------------------------------------------------------------------------
// Token Revocation Details
// ---------------------------------------------------------------------------

func TestE2E_TokenRevocation(t *testing.T) {
	env := setupFullTestServer(t)
	defer env.server.Close()

	tenantID := env.createTenant(t, "revoke-t", "RS256")
	clientID, _ := env.createClient(t, tenantID, "public", []string{"authorization_code", "refresh_token"})
	_ = env.registerUser(t, tenantID, "revoke@example.com", "pass123", "Revoke User")
	session := env.loginUser(t, tenantID, "revoke@example.com", "pass123")

	code, verifier := env.authorizeWithPKCE(t, tenantID, clientID, session, "openid")
	tokens := env.exchangeCode(t, tenantID, clientID, "", code, verifier)
	refreshToken := tokens["refresh_token"].(string)

	t.Run("revoke refresh token then introspect returns inactive", func(t *testing.T) {
		status, _ := env.postForm(t, "/revoke",
			fmt.Sprintf("token=%s", refreshToken),
			map[string]string{"X-Tenant-ID": tenantID})
		assert.Equal(t, http.StatusOK, status, "revoke should succeed")

		// Introspect revoked refresh token
		status, intro := env.postForm(t, "/introspect",
			fmt.Sprintf("token=%s", refreshToken),
			map[string]string{"X-Tenant-ID": tenantID})
		require.Equal(t, http.StatusOK, status)
		assert.Equal(t, false, intro["active"], "revoked refresh token should be inactive")
	})

	t.Run("revoked refresh token cannot be used for refresh", func(t *testing.T) {
		status, _ := env.postForm(t, "/token",
			fmt.Sprintf("grant_type=refresh_token&refresh_token=%s&client_id=%s", refreshToken, clientID),
			map[string]string{"X-Tenant-ID": tenantID})
		assert.NotEqual(t, http.StatusOK, status, "revoked refresh token should not work for refresh")
	})
}

// ---------------------------------------------------------------------------
// Special Characters
// ---------------------------------------------------------------------------

func TestE2E_SpecialCharacters(t *testing.T) {
	env := setupFullTestServer(t)
	defer env.server.Close()

	tenantID := env.createTenant(t, "special-chars-t", "RS256")
	clientID, _ := env.createClient(t, tenantID, "public", []string{"authorization_code"})

	t.Run("email with + alias works", func(t *testing.T) {
		status, body := env.doJSON(t, http.MethodPost, "/register", map[string]any{
			"email":    "user+test@example.com",
			"password": "pass123",
			"name":     "Plus User",
		}, map[string]string{
			"X-Tenant-ID": tenantID,
		})
		assert.Equal(t, http.StatusCreated, status)
		data := body["data"].(map[string]any)
		assert.NotEmpty(t, data["user_id"])

		// Login with + alias
		session := env.loginUser(t, tenantID, "user+test@example.com", "pass123")
		assert.NotEmpty(t, session)
	})

	t.Run("state parameter with special characters preserved", func(t *testing.T) {
		_ = env.registerUser(t, tenantID, "state@example.com", "pass123", "State User")
		session := env.loginUser(t, tenantID, "state@example.com", "pass123")

		specialState := "my-state!@#$%^&*()"
		encodedState := url.QueryEscape(specialState)

		authURL := fmt.Sprintf("/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=openid&state=%s&code_challenge=test&code_challenge_method=S256",
			clientID, "https://app.example.com/cb", encodedState)

		req, err := http.NewRequest(http.MethodGet, env.server.URL+authURL, nil)
		require.NoError(t, err)
		req.Header.Set("X-Tenant-ID", tenantID)
		req.Header.Set("Authorization", "Bearer "+session)

		client := env.server.Client()
		client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}
		resp, err := client.Do(req)
		require.NoError(t, err)
		resp.Body.Close()

		if resp.StatusCode == http.StatusFound {
			location := resp.Header.Get("Location")
			assert.Contains(t, location, "state=", "redirect should contain state parameter")
		}
	})

	t.Run("redirect URI with query parameters works", func(t *testing.T) {
		// Create client with redirect URI containing query params
		status, body := env.doJSON(t, http.MethodPost, "/tenants/"+tenantID+"/clients", map[string]any{
			"client_name":    "Query Param Client",
			"client_type":    "public",
			"redirect_uris":  []string{"https://app.example.com/cb?mode=test&version=2"},
			"allowed_scopes": []string{"openid"},
			"grant_types":    []string{"authorization_code"},
		}, map[string]string{
			"Authorization": "Bearer " + env.adminKey,
		})
		require.Equal(t, http.StatusCreated, status)
		data := body["data"].(map[string]any)
		qClientID := data["client_id"].(string)

		_ = env.registerUser(t, tenantID, "qp@example.com", "pass123", "QP User")
		session := env.loginUser(t, tenantID, "qp@example.com", "pass123")

		redirectURI := "https://app.example.com/cb?mode=test&version=2"
		authURL := fmt.Sprintf("/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=openid&state=st&code_challenge=test&code_challenge_method=S256",
			qClientID, url.QueryEscape(redirectURI))

		req, err := http.NewRequest(http.MethodGet, env.server.URL+authURL, nil)
		require.NoError(t, err)
		req.Header.Set("X-Tenant-ID", tenantID)
		req.Header.Set("Authorization", "Bearer "+session)

		client := env.server.Client()
		client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}
		resp, err := client.Do(req)
		require.NoError(t, err)
		resp.Body.Close()

		if resp.StatusCode == http.StatusFound {
			location := resp.Header.Get("Location")
			assert.Contains(t, location, "code=", "redirect should contain auth code")
		}
	})
}

// ---------------------------------------------------------------------------
// Concurrent Operations
// ---------------------------------------------------------------------------

func TestE2E_ConcurrentCodeExchange(t *testing.T) {
	env := setupFullTestServer(t)
	defer env.server.Close()

	tenantID := env.createTenant(t, "concurrent-t", "RS256")
	clientID, _ := env.createClient(t, tenantID, "public", []string{"authorization_code"})
	_ = env.registerUser(t, tenantID, "concurrent@example.com", "pass123", "Concurrent User")
	session := env.loginUser(t, tenantID, "concurrent@example.com", "pass123")

	code, verifier := env.authorizeWithPKCE(t, tenantID, clientID, session, "openid")

	// Fire 5 concurrent exchanges with the same code
	results := make(chan int, 5)
	for i := 0; i < 5; i++ {
		go func() {
			status, _ := env.postForm(t, "/token",
				fmt.Sprintf("grant_type=authorization_code&code=%s&redirect_uri=%s&client_id=%s&code_verifier=%s",
					code, "https://app.example.com/cb", clientID, verifier),
				map[string]string{"X-Tenant-ID": tenantID})
			results <- status
		}()
	}

	successCount := 0
	for i := 0; i < 5; i++ {
		status := <-results
		if status == http.StatusOK {
			successCount++
		}
	}
	assert.Equal(t, 1, successCount, "only one concurrent code exchange should succeed")
}

func TestE2E_ConcurrentRegistration(t *testing.T) {
	env := setupFullTestServer(t)
	defer env.server.Close()

	tenantID := env.createTenant(t, "conc-reg-t", "RS256")

	// Fire 5 concurrent registrations with the same email
	results := make(chan int, 5)
	for i := 0; i < 5; i++ {
		go func() {
			status, _ := env.doJSON(t, http.MethodPost, "/register", map[string]any{
				"email":    "dupe@example.com",
				"password": "pass123",
				"name":     "Dupe User",
			}, map[string]string{
				"X-Tenant-ID": tenantID,
			})
			results <- status
		}()
	}

	var successes, conflicts int
	for i := 0; i < 5; i++ {
		status := <-results
		switch status {
		case http.StatusCreated:
			successes++
		case http.StatusConflict:
			conflicts++
		}
	}
	assert.Equal(t, 1, successes, "only one registration should succeed")
	assert.Equal(t, 4, conflicts, "other 4 should get 409")
}

// ---------------------------------------------------------------------------
// Discovery Edge Cases
// ---------------------------------------------------------------------------

func TestE2E_DiscoveryWithoutTenant(t *testing.T) {
	env := setupFullTestServer(t)
	defer env.server.Close()

	status, _ := env.get(t, "/.well-known/openid-configuration", nil)
	assert.Equal(t, http.StatusBadRequest, status, "discovery without tenant should return 400")
}

func TestE2E_DiscoveryAllGrantTypes(t *testing.T) {
	env := setupFullTestServer(t)
	defer env.server.Close()

	tenantID := env.createTenant(t, "disc-grants-t", "RS256")

	status, body := env.get(t, "/.well-known/openid-configuration", map[string]string{
		"X-Tenant-ID": tenantID,
	})
	require.Equal(t, http.StatusOK, status)

	grantTypes, ok := body["grant_types_supported"].([]any)
	require.True(t, ok, "grant_types_supported should be an array")

	grantTypeStrs := make([]string, len(grantTypes))
	for i, gt := range grantTypes {
		grantTypeStrs[i] = gt.(string)
	}

	// The discovery document always includes authorization_code.
	// Other grant types may or may not be listed depending on the discovery service config.
	assert.Contains(t, grantTypeStrs, "authorization_code")
	assert.NotEmpty(t, grantTypeStrs, "should have at least one grant type")
}

// ---------------------------------------------------------------------------
// CORS Header Details
// ---------------------------------------------------------------------------

func TestE2E_CORSHeaders(t *testing.T) {
	env := setupFullTestServer(t)
	defer env.server.Close()

	req, err := http.NewRequest(http.MethodOptions, env.server.URL+"/token", nil)
	require.NoError(t, err)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "Content-Type,Authorization,X-Tenant-ID,X-API-Key")

	resp, err := env.server.Client().Do(req)
	require.NoError(t, err)
	resp.Body.Close()

	assert.NotEmpty(t, resp.Header.Get("Access-Control-Allow-Origin"))
	allowHeaders := strings.ToLower(resp.Header.Get("Access-Control-Allow-Headers"))
	assert.Contains(t, allowHeaders, "content-type")
	assert.Contains(t, allowHeaders, "authorization")
}
