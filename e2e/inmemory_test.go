//go:build e2e

package e2e

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"context"

	"github.com/authplex/internal/adapter/cache"
	adaptcrypto "github.com/authplex/internal/adapter/crypto"
	adaptemail "github.com/authplex/internal/adapter/email"
	"github.com/authplex/internal/adapter/http/handler"
	adapthttp "github.com/authplex/internal/adapter/http/oauth"
	"github.com/authplex/internal/adapter/http/middleware"
	adaptsms "github.com/authplex/internal/adapter/sms"
	"github.com/authplex/internal/application/auth"
	clientsvc "github.com/authplex/internal/application/client"
	"github.com/authplex/internal/application/discovery"
	"github.com/authplex/internal/application/jwks"
	mfasvc "github.com/authplex/internal/application/mfa"
	providersvc "github.com/authplex/internal/application/provider"
	"github.com/authplex/internal/application/social"
	tenantsvc "github.com/authplex/internal/application/tenant"
	usersvc "github.com/authplex/internal/application/user"
	"github.com/authplex/internal/config"
	"github.com/authplex/internal/domain/tenant"
	"github.com/authplex/pkg/sdk/health"
	"github.com/authplex/pkg/sdk/httputil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testEnv struct {
	server  *httptest.Server
	jwksSvc *jwks.Service
}

// setupInMemoryTestServer creates a full AuthPlex server with in-memory storage.
// No Docker required.
func setupInMemoryTestServer(t *testing.T) *testEnv {
	t.Helper()
	log := slog.Default()
	hasher := adaptcrypto.NewBcryptHasher()
	keyGen := adaptcrypto.NewKeyGenerator()
	keyConv := adaptcrypto.NewJWKConverter()
	jwtSigner := adaptcrypto.NewJWTSigner()

	jwksSvc := jwks.NewService(cache.NewInMemoryJWKRepository(), keyGen, keyConv, log)
	discoverySvc := discovery.NewService("http://localhost", log)

	authSvc := auth.NewService(cache.NewInMemoryCodeRepository(), jwksSvc, jwtSigner, log).
		WithRefreshRepo(cache.NewInMemoryRefreshRepository()).
		WithDeviceRepo(cache.NewInMemoryDeviceRepository()).
		WithBlacklist(cache.NewInMemoryBlacklist())

	clientService := clientsvc.NewService(cache.NewInMemoryClientRepository(), hasher, log)
	tenantSvc := tenantsvc.NewService(cache.NewInMemoryTenantRepository(), log)

	providerService := providersvc.NewService(cache.NewInMemoryProviderRepository(), log)
	socialSvc := social.NewService(cache.NewInMemoryProviderRepository(), cache.NewInMemoryExternalIdentityRepository(),
		cache.NewInMemoryStateRepository(), adapthttp.NewHTTPOAuthClient(), authSvc, "http://localhost/callback", log)

	mfaService := mfasvc.NewService(cache.NewInMemoryTOTPRepository(), cache.NewInMemoryChallengeRepository(), authSvc, log)

	userService := usersvc.NewService(cache.NewInMemoryUserRepository(), cache.NewInMemorySessionRepository(), hasher, log).
		WithOTP(cache.NewInMemoryOTPRepository(), adaptemail.NewConsoleSender(log), adaptsms.NewConsoleSender(log))

	authSvc.WithUserValidator(userService)

	tenantResolver := middleware.NewTenantResolver(tenantSvc, config.TenantModeHeader, log)

	authorizeHandler := handler.NewAuthorizeHandler(authSvc).
		WithSocialService(socialSvc).WithUserService(userService).
		WithClientService(clientService).WithMFA(mfaService, tenantSvc)

	mux := http.NewServeMux()
	mux.Handle("/.well-known/openid-configuration", tenantResolver.Middleware(http.HandlerFunc(handler.NewDiscoveryHandler(discoverySvc).HandleDiscovery)))
	mux.Handle("/jwks", tenantResolver.Middleware(http.HandlerFunc(handler.NewJWKSHandler(jwksSvc).HandleJWKS)))
	mux.Handle("/authorize", tenantResolver.Middleware(http.HandlerFunc(authorizeHandler.HandleAuthorize)))
	mux.Handle("/token", tenantResolver.Middleware(http.HandlerFunc(handler.NewTokenHandler(authSvc).WithClientService(clientService).HandleToken)))
	mux.Handle("/register", tenantResolver.Middleware(http.HandlerFunc(handler.NewUserHandler(userService).HandleRegister)))
	mux.Handle("/login", tenantResolver.Middleware(http.HandlerFunc(handler.NewUserHandler(userService).HandleLogin)))
	mux.Handle("/userinfo", tenantResolver.Middleware(http.HandlerFunc(handler.NewUserHandler(userService).HandleUserInfo)))
	mux.HandleFunc("/tenants", handler.NewTenantHandler(tenantSvc).HandleTenants)
	mux.HandleFunc("/tenants/", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/clients") {
			ch := handler.NewClientHandler(clientService)
			if strings.Count(r.URL.Path, "/") >= 4 {
				ch.HandleClient(w, r)
			} else {
				ch.HandleClients(w, r)
			}
			return
		}
		if strings.Contains(r.URL.Path, "/providers") {
			ph := handler.NewProviderHandler(providerService)
			if strings.Count(r.URL.Path, "/") >= 4 {
				ph.HandleProvider(w, r)
			} else {
				ph.HandleProviders(w, r)
			}
			return
		}
		handler.NewTenantHandler(tenantSvc).HandleTenant(w, r)
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		status, checks := health.NewRegistry().CheckAll(r.Context())
		httputil.WriteRaw(w, http.StatusOK, map[string]any{"status": status, "checks": checks}) //nolint:errcheck
	})

	return &testEnv{
		server:  httptest.NewServer(middleware.NewCORS("*").Middleware(mux)),
		jwksSvc: jwksSvc,
	}
}

// TestInMemoryGoldenPath tests the complete flow without Docker.
func TestInMemoryGoldenPath(t *testing.T) {
	env := setupInMemoryTestServer(t)
	srv := env.server
	defer srv.Close()

	tenantID := "test-tenant"
	c := srv.Client()
	c.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// 1. Create tenant
	resp, err := c.Post(srv.URL+"/tenants", "application/json",
		strings.NewReader(`{"id":"test-tenant","domain":"test.example.com","issuer":"https://test.example.com","algorithm":"RS256"}`))
	require.NoError(t, err)
	require.Equal(t, 201, resp.StatusCode)
	resp.Body.Close()

	// Provision signing key for the tenant
	_, keyErr := env.jwksSvc.EnsureKeyPair(context.Background(), tenantID, "e2e-key", tenant.RS256)
	require.Nil(t, keyErr)

	// 2. Register client
	resp, err = c.Post(srv.URL+"/tenants/test-tenant/clients", "application/json",
		strings.NewReader(`{"client_name":"Test App","client_type":"public","redirect_uris":["https://app.example.com/cb"],"allowed_scopes":["openid","profile"],"grant_types":["authorization_code","refresh_token"]}`))
	require.NoError(t, err)
	require.Equal(t, 201, resp.StatusCode)
	var cResp map[string]any
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	json.Unmarshal(body, &cResp) //nolint:errcheck
	clientID := cResp["data"].(map[string]any)["client_id"].(string)

	// 3. Register user
	req, _ := http.NewRequest("POST", srv.URL+"/register", strings.NewReader(`{"email":"test@example.com","password":"pass123","name":"Test"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", tenantID)
	resp, err = c.Do(req)
	require.NoError(t, err)
	require.Equal(t, 201, resp.StatusCode)
	resp.Body.Close()

	// 4. Login
	req, _ = http.NewRequest("POST", srv.URL+"/login", strings.NewReader(`{"email":"test@example.com","password":"pass123"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", tenantID)
	resp, err = c.Do(req)
	require.NoError(t, err)
	require.Equal(t, 200, resp.StatusCode)
	var lResp map[string]any
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	json.Unmarshal(body, &lResp) //nolint:errcheck
	session := lResp["data"].(map[string]any)["session_token"].(string)

	// 5. Authorize (with session)
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	authURL := fmt.Sprintf("%s/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=openid+profile&state=st&code_challenge=%s&code_challenge_method=S256",
		srv.URL, clientID, "https://app.example.com/cb", challenge)
	req, _ = http.NewRequest("GET", authURL, nil)
	req.Header.Set("X-Tenant-ID", tenantID)
	req.Header.Set("Authorization", "Bearer "+session)
	resp, err = c.Do(req)
	require.NoError(t, err)
	require.Equal(t, 302, resp.StatusCode)

	location := resp.Header.Get("Location")
	resp.Body.Close()
	assert.Contains(t, location, "code=")

	code := strings.Split(strings.Split(location, "code=")[1], "&")[0]

	// 6. Token exchange
	tokenBody := fmt.Sprintf("grant_type=authorization_code&code=%s&redirect_uri=%s&client_id=%s&code_verifier=%s",
		code, "https://app.example.com/cb", clientID, verifier)
	req, _ = http.NewRequest("POST", srv.URL+"/token", strings.NewReader(tokenBody))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Tenant-ID", tenantID)
	resp, err = c.Do(req)
	require.NoError(t, err)
	require.Equal(t, 200, resp.StatusCode)

	var tResp map[string]any
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	json.Unmarshal(body, &tResp) //nolint:errcheck
	accessToken := tResp["access_token"].(string)
	assert.NotEmpty(t, accessToken)
	assert.Equal(t, "Bearer", tResp["token_type"])
	assert.NotEmpty(t, tResp["id_token"])

	// 7. JWT structure check
	assert.Len(t, strings.Split(accessToken, "."), 3)

	// 8. JWKS has keys
	req, _ = http.NewRequest("GET", srv.URL+"/jwks", nil)
	req.Header.Set("X-Tenant-ID", tenantID)
	resp, err = c.Do(req)
	require.NoError(t, err)
	var jResp map[string]any
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	json.Unmarshal(body, &jResp) //nolint:errcheck
	assert.NotEmpty(t, jResp["keys"])

	// 9. UserInfo
	req, _ = http.NewRequest("GET", srv.URL+"/userinfo", nil)
	req.Header.Set("X-Tenant-ID", tenantID)
	req.Header.Set("Authorization", "Bearer "+session)
	resp, err = c.Do(req)
	require.NoError(t, err)
	require.Equal(t, 200, resp.StatusCode)
	var uResp map[string]any
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	json.Unmarshal(body, &uResp) //nolint:errcheck
	assert.Equal(t, "test@example.com", uResp["email"])

	t.Log("In-memory golden path: register → login → authorize → token → JWKS → userinfo ✓")
}
