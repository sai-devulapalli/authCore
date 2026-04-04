//go:build e2e

package e2e

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/authplex/internal/adapter/cache"
	adaptcrypto "github.com/authplex/internal/adapter/crypto"
	adaptemail "github.com/authplex/internal/adapter/email"
	"github.com/authplex/internal/adapter/http/handler"
	adapthttp "github.com/authplex/internal/adapter/http/oauth"
	"github.com/authplex/internal/adapter/http/middleware"
	"github.com/authplex/internal/adapter/postgres"
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
	"github.com/authplex/pkg/sdk/health"
	"github.com/authplex/pkg/sdk/httputil"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// setupTestServer creates a full AuthPlex server backed by real Postgres.
func setupTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	ctx := context.Background()

	// Start Postgres container
	pgContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "postgres:16-alpine",
			ExposedPorts: []string{"5432/tcp"},
			Env: map[string]string{
				"POSTGRES_USER":     "test",
				"POSTGRES_PASSWORD": "test",
				"POSTGRES_DB":       "authplex_test",
			},
			WaitingFor: wait.ForListeningPort("5432/tcp").WithStartupTimeout(60 * time.Second),
		},
		Started: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { pgContainer.Terminate(ctx) }) //nolint:errcheck

	host, err := pgContainer.Host(ctx)
	require.NoError(t, err)
	port, err := pgContainer.MappedPort(ctx, "5432")
	require.NoError(t, err)

	dsn := fmt.Sprintf("postgres://test:test@%s:%s/authplex_test?sslmode=disable", host, port.Port())

	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	require.NoError(t, db.Ping())
	t.Cleanup(func() { db.Close() })

	log := slog.Default()

	// Run migrations
	require.NoError(t, postgres.RunMigrations(ctx, db, log))

	// Build server with Postgres repos + in-memory ephemeral
	hasher := adaptcrypto.NewBcryptHasher()
	keyGen := adaptcrypto.NewKeyGenerator()
	keyConv := adaptcrypto.NewJWKConverter()
	jwtSigner := adaptcrypto.NewJWTSigner()

	jwksSvc := jwks.NewService(postgres.NewJWKRepository(db), keyGen, keyConv, log)
	discoverySvc := discovery.NewService("http://localhost", log)

	codeRepo := cache.NewInMemoryCodeRepository()
	refreshRepo := cache.NewInMemoryRefreshRepository()
	deviceRepo := cache.NewInMemoryDeviceRepository()
	blacklist := cache.NewInMemoryBlacklist()

	authSvc := auth.NewService(codeRepo, jwksSvc, jwtSigner, log).
		WithRefreshRepo(refreshRepo).
		WithDeviceRepo(deviceRepo).
		WithBlacklist(blacklist)

	clientService := clientsvc.NewService(postgres.NewClientRepository(db), hasher, log)
	tenantSvc := tenantsvc.NewService(postgres.NewTenantRepository(db), log)

	oauthClient := adapthttp.NewHTTPOAuthClient()
	providerService := providersvc.NewService(cache.NewInMemoryProviderRepository(), log)
	socialSvc := social.NewService(cache.NewInMemoryProviderRepository(), cache.NewInMemoryExternalIdentityRepository(),
		cache.NewInMemoryStateRepository(), oauthClient, authSvc, "http://localhost/callback", log)

	totpRepo := cache.NewInMemoryTOTPRepository()
	challengeRepo := cache.NewInMemoryChallengeRepository()
	mfaService := mfasvc.NewService(totpRepo, challengeRepo, authSvc, log)

	otpRepo := cache.NewInMemoryOTPRepository()
	emailSender := adaptemail.NewConsoleSender(log)
	smsSender := adaptsms.NewConsoleSender(log)

	userService := usersvc.NewService(postgres.NewUserRepository(db), cache.NewInMemorySessionRepository(), hasher, log).
		WithOTP(otpRepo, emailSender, smsSender)

	authSvc.WithUserValidator(userService)

	corsMiddleware := middleware.NewCORS("*")
	tenantResolver := middleware.NewTenantResolver(tenantSvc, config.TenantModeHeader, log)

	discoveryHandler := handler.NewDiscoveryHandler(discoverySvc)
	jwksHandler := handler.NewJWKSHandler(jwksSvc)
	authorizeHandler := handler.NewAuthorizeHandler(authSvc).
		WithSocialService(socialSvc).
		WithUserService(userService).
		WithClientService(clientService).
		WithMFA(mfaService, tenantSvc)
	tokenHandler := handler.NewTokenHandler(authSvc).WithClientService(clientService)
	userHandler := handler.NewUserHandler(userService)
	tenantHandler := handler.NewTenantHandler(tenantSvc)
	clientHandler := handler.NewClientHandler(clientService)
	providerHandler := handler.NewProviderHandler(providerService)
	healthRegistry := health.NewRegistry()

	mux := http.NewServeMux()
	mux.Handle("/.well-known/openid-configuration", tenantResolver.Middleware(http.HandlerFunc(discoveryHandler.HandleDiscovery)))
	mux.Handle("/jwks", tenantResolver.Middleware(http.HandlerFunc(jwksHandler.HandleJWKS)))
	mux.Handle("/authorize", tenantResolver.Middleware(http.HandlerFunc(authorizeHandler.HandleAuthorize)))
	mux.Handle("/token", tenantResolver.Middleware(http.HandlerFunc(tokenHandler.HandleToken)))
	mux.Handle("/register", tenantResolver.Middleware(http.HandlerFunc(userHandler.HandleRegister)))
	mux.Handle("/login", tenantResolver.Middleware(http.HandlerFunc(userHandler.HandleLogin)))
	mux.Handle("/userinfo", tenantResolver.Middleware(http.HandlerFunc(userHandler.HandleUserInfo)))
	mux.HandleFunc("/tenants", tenantHandler.HandleTenants)
	mux.HandleFunc("/tenants/", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/clients") {
			if strings.Count(r.URL.Path, "/") >= 4 {
				clientHandler.HandleClient(w, r)
			} else {
				clientHandler.HandleClients(w, r)
			}
			return
		}
		if strings.Contains(r.URL.Path, "/providers") {
			if strings.Count(r.URL.Path, "/") >= 4 {
				providerHandler.HandleProvider(w, r)
			} else {
				providerHandler.HandleProviders(w, r)
			}
			return
		}
		tenantHandler.HandleTenant(w, r)
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		status, checks := healthRegistry.CheckAll(r.Context())
		httputil.WriteRaw(w, http.StatusOK, map[string]any{"status": status, "checks": checks}) //nolint:errcheck
	})

	return httptest.NewServer(corsMiddleware.Middleware(mux))
}

// --- Golden Path Test ---

func TestGoldenPath_RegisterLoginAuthorizeToken(t *testing.T) {
	srv := setupTestServer(t)
	defer srv.Close()

	tenantID := "e2e-tenant"
	client := srv.Client()

	// Step 1: Health check
	resp, err := client.Get(srv.URL + "/health")
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	resp.Body.Close()

	// Step 2: Create tenant
	tenantBody := fmt.Sprintf(`{"id":"%s","domain":"e2e.example.com","issuer":"https://e2e.example.com","algorithm":"RS256"}`, tenantID)
	resp, err = client.Post(srv.URL+"/tenants", "application/json", strings.NewReader(tenantBody))
	require.NoError(t, err)
	assert.Equal(t, 201, resp.StatusCode)
	resp.Body.Close()

	// Step 3: Register client
	clientBody := `{"client_name":"E2E App","client_type":"public","redirect_uris":["https://e2e.example.com/callback"],"allowed_scopes":["openid","profile"],"grant_types":["authorization_code","refresh_token"]}`
	resp, err = client.Post(srv.URL+"/tenants/"+tenantID+"/clients", "application/json", strings.NewReader(clientBody))
	require.NoError(t, err)
	assert.Equal(t, 201, resp.StatusCode)

	var clientResp map[string]any
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	json.Unmarshal(body, &clientResp) //nolint:errcheck
	data := clientResp["data"].(map[string]any)
	clientID := data["client_id"].(string)
	assert.NotEmpty(t, clientID)

	// Step 4: Register user
	userBody := `{"email":"e2e@example.com","password":"e2e-secret-123","name":"E2E User"}`
	req, _ := http.NewRequest("POST", srv.URL+"/register", strings.NewReader(userBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", tenantID)
	resp, err = client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 201, resp.StatusCode)
	resp.Body.Close()

	// Step 5: Login
	loginBody := `{"email":"e2e@example.com","password":"e2e-secret-123"}`
	req, _ = http.NewRequest("POST", srv.URL+"/login", strings.NewReader(loginBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", tenantID)
	resp, err = client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)

	var loginResp map[string]any
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	json.Unmarshal(body, &loginResp) //nolint:errcheck
	loginData := loginResp["data"].(map[string]any)
	sessionToken := loginData["session_token"].(string)
	assert.NotEmpty(t, sessionToken)

	// Step 6: OIDC Discovery
	req, _ = http.NewRequest("GET", srv.URL+"/.well-known/openid-configuration", nil)
	req.Header.Set("X-Tenant-ID", tenantID)
	resp, err = client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)

	var discovery map[string]any
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	json.Unmarshal(body, &discovery) //nolint:errcheck
	assert.NotEmpty(t, discovery["issuer"])
	assert.NotEmpty(t, discovery["jwks_uri"])

	// Step 7: Authorize (session-based, no X-Subject needed)
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])

	authURL := fmt.Sprintf("%s/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=openid+profile&state=e2e-state&code_challenge=%s&code_challenge_method=S256",
		srv.URL, clientID, "https://e2e.example.com/callback", challenge)

	req, _ = http.NewRequest("GET", authURL, nil)
	req.Header.Set("X-Tenant-ID", tenantID)
	req.Header.Set("Authorization", "Bearer "+sessionToken)

	// Don't follow redirects — we want the 302
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err = client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 302, resp.StatusCode)

	location := resp.Header.Get("Location")
	resp.Body.Close()
	assert.Contains(t, location, "code=")
	assert.Contains(t, location, "state=e2e-state")

	// Extract auth code from redirect
	locParts := strings.Split(location, "code=")
	require.True(t, len(locParts) > 1)
	code := strings.Split(locParts[1], "&")[0]
	assert.NotEmpty(t, code)

	// Step 8: Token exchange
	tokenBody := fmt.Sprintf("grant_type=authorization_code&code=%s&redirect_uri=%s&client_id=%s&code_verifier=%s",
		code, "https://e2e.example.com/callback", clientID, verifier)

	req, _ = http.NewRequest("POST", srv.URL+"/token", strings.NewReader(tokenBody))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Tenant-ID", tenantID)
	resp, err = client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)

	var tokenResp map[string]any
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	json.Unmarshal(body, &tokenResp) //nolint:errcheck
	accessToken := tokenResp["access_token"].(string)
	assert.NotEmpty(t, accessToken)
	assert.Equal(t, "Bearer", tokenResp["token_type"])
	assert.NotEmpty(t, tokenResp["id_token"])

	// Step 9: Verify JWT structure (3 parts)
	jwtParts := strings.Split(accessToken, ".")
	assert.Len(t, jwtParts, 3, "access_token should be a valid JWT with 3 parts")

	// Step 10: JWKS endpoint (verify keys exist)
	req, _ = http.NewRequest("GET", srv.URL+"/jwks", nil)
	req.Header.Set("X-Tenant-ID", tenantID)
	resp, err = client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)

	var jwksResp map[string]any
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	json.Unmarshal(body, &jwksResp) //nolint:errcheck
	keys := jwksResp["keys"].([]any)
	assert.NotEmpty(t, keys, "JWKS should contain at least one key")

	// Step 11: UserInfo (with session)
	req, _ = http.NewRequest("GET", srv.URL+"/userinfo", nil)
	req.Header.Set("X-Tenant-ID", tenantID)
	req.Header.Set("Authorization", "Bearer "+sessionToken)
	resp, err = client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)

	var userInfo map[string]any
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	json.Unmarshal(body, &userInfo) //nolint:errcheck
	assert.Equal(t, "e2e@example.com", userInfo["email"])
	assert.Equal(t, "E2E User", userInfo["name"])

	t.Log("Golden path complete: register → login → discovery → authorize → token → JWKS → userinfo")
}

func TestE2E_ScopeValidation(t *testing.T) {
	srv := setupTestServer(t)
	defer srv.Close()
	client := srv.Client()
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// Setup tenant + client with restricted scopes
	client.Post(srv.URL+"/tenants", "application/json", //nolint:errcheck
		strings.NewReader(`{"id":"scope-tenant","domain":"scope.example.com","issuer":"https://scope.example.com","algorithm":"RS256"}`))

	resp, _ := client.Post(srv.URL+"/tenants/scope-tenant/clients", "application/json",
		strings.NewReader(`{"client_name":"Scoped App","client_type":"public","redirect_uris":["https://scope.example.com/cb"],"allowed_scopes":["openid"],"grant_types":["authorization_code"]}`))
	var cresp map[string]any
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	json.Unmarshal(body, &cresp) //nolint:errcheck
	cid := cresp["data"].(map[string]any)["client_id"].(string)

	// Try to authorize with invalid scope
	url := fmt.Sprintf("%s/authorize?response_type=code&client_id=%s&redirect_uri=https://scope.example.com/cb&scope=openid+admin&code_challenge=test&code_challenge_method=S256",
		srv.URL, cid)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("X-Tenant-ID", "scope-tenant")
	req.Header.Set("X-Subject", "user-1")
	resp, _ = client.Do(req)
	assert.Equal(t, 400, resp.StatusCode)

	var errResp map[string]any
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	json.Unmarshal(body, &errResp) //nolint:errcheck
	assert.Equal(t, "invalid_scope", errResp["error"])
}

func TestE2E_ClientEnforcement(t *testing.T) {
	srv := setupTestServer(t)
	defer srv.Close()
	client := srv.Client()
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// Setup tenant
	client.Post(srv.URL+"/tenants", "application/json", //nolint:errcheck
		strings.NewReader(`{"id":"client-tenant","domain":"client.example.com","issuer":"https://client.example.com","algorithm":"RS256"}`))

	// Register client with specific redirect URI
	resp, _ := client.Post(srv.URL+"/tenants/client-tenant/clients", "application/json",
		strings.NewReader(`{"client_name":"Strict App","client_type":"public","redirect_uris":["https://legit.example.com/cb"],"allowed_scopes":["openid"],"grant_types":["authorization_code"]}`))
	var cresp map[string]any
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	json.Unmarshal(body, &cresp) //nolint:errcheck
	cid := cresp["data"].(map[string]any)["client_id"].(string)

	// Try to authorize with wrong redirect URI
	url := fmt.Sprintf("%s/authorize?response_type=code&client_id=%s&redirect_uri=https://evil.com/cb&scope=openid&code_challenge=test&code_challenge_method=S256",
		srv.URL, cid)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("X-Tenant-ID", "client-tenant")
	req.Header.Set("X-Subject", "user-1")
	resp, _ = client.Do(req)
	assert.Equal(t, 400, resp.StatusCode)

	var errResp map[string]any
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	json.Unmarshal(body, &errResp) //nolint:errcheck
	assert.Equal(t, "invalid_redirect_uri", errResp["error"])
}
