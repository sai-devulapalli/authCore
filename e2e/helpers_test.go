//go:build e2e

package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/authplex/internal/adapter/cache"
	adaptcrypto "github.com/authplex/internal/adapter/crypto"
	"github.com/authplex/internal/adapter/http/handler"
	adapthttp "github.com/authplex/internal/adapter/http/oauth"
	"github.com/authplex/internal/adapter/http/middleware"
	adaptsms "github.com/authplex/internal/adapter/sms"
	"github.com/authplex/internal/application/auth"
	auditsvc "github.com/authplex/internal/application/audit"
	clientsvc "github.com/authplex/internal/application/client"
	"github.com/authplex/internal/application/discovery"
	"github.com/authplex/internal/application/jwks"
	mfasvc "github.com/authplex/internal/application/mfa"
	providersvc "github.com/authplex/internal/application/provider"
	rbacsvc "github.com/authplex/internal/application/rbac"
	"github.com/authplex/internal/application/social"
	tenantsvc "github.com/authplex/internal/application/tenant"
	usersvc "github.com/authplex/internal/application/user"
	webhooksvc "github.com/authplex/internal/application/webhook"
	"github.com/authplex/internal/config"
	"github.com/authplex/internal/domain/tenant"
	"github.com/authplex/pkg/sdk/health"
	"github.com/authplex/pkg/sdk/httputil"
	"github.com/stretchr/testify/require"
)

const testAdminKey = "test-admin-key-e2e"

// capturingEmailSender captures the last OTP code sent via email.
type capturingEmailSender struct {
	mu       sync.Mutex
	lastCode map[string]string // key: email address -> code
}

func newCapturingEmailSender() *capturingEmailSender {
	return &capturingEmailSender{lastCode: make(map[string]string)}
}

func (s *capturingEmailSender) SendOTP(_ context.Context, to, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastCode[to] = code
	return nil
}

func (s *capturingEmailSender) getCode(email string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastCode[email]
}

// fullTestEnv holds references to the test server and key services
// for the full-featured E2E test setup.
type fullTestEnv struct {
	server      *httptest.Server
	jwksSvc     *jwks.Service
	adminKey    string // for management API auth
	emailSender *capturingEmailSender
}

// setupFullTestServer creates a complete AuthPlex server with ALL routes wired,
// matching the production wiring in cmd/authplex/main.go but using in-memory repos.
// This includes RBAC, audit, MFA (TOTP + WebAuthn), rate limiting, and admin auth.
func setupFullTestServer(t *testing.T) *fullTestEnv {
	t.Helper()
	log := slog.Default()

	// Crypto adapters
	hasher := adaptcrypto.NewBcryptHasher()
	keyGen := adaptcrypto.NewKeyGenerator()
	keyConv := adaptcrypto.NewJWKConverter()
	jwtSigner := adaptcrypto.NewJWTSigner()

	// In-memory repositories (mirrors setupInMemoryRepos in main.go)
	roleRepo := cache.NewInMemoryRoleRepository()
	assignmentRepo := cache.NewInMemoryAssignmentRepository(roleRepo)
	auditRepo := cache.NewInMemoryAuditRepository()
	webauthnRepo := cache.NewInMemoryWebAuthnRepository()

	// Application services
	jwksSvc := jwks.NewService(cache.NewInMemoryJWKRepository(), keyGen, keyConv, log)
	discoverySvc := discovery.NewService("http://localhost", log)

	authSvc := auth.NewService(cache.NewInMemoryCodeRepository(), jwksSvc, jwtSigner, log).
		WithRefreshRepo(cache.NewInMemoryRefreshRepository()).
		WithDeviceRepo(cache.NewInMemoryDeviceRepository()).
		WithBlacklist(cache.NewInMemoryBlacklist())

	clientService := clientsvc.NewService(cache.NewInMemoryClientRepository(), hasher, log)
	tenantSvc := tenantsvc.NewService(cache.NewInMemoryTenantRepository(), log)

	rbacService := rbacsvc.NewService(roleRepo, assignmentRepo, log)
	auditService := auditsvc.NewService(auditRepo, log)
	_ = auditService // available for handlers

	// Wire RBAC into auth service for JWT claims
	authSvc.WithRBAC(assignmentRepo)

	providerService := providersvc.NewService(cache.NewInMemoryProviderRepository(), log)
	socialSvc := social.NewService(
		cache.NewInMemoryProviderRepository(),
		cache.NewInMemoryExternalIdentityRepository(),
		cache.NewInMemoryStateRepository(),
		adapthttp.NewHTTPOAuthClient(),
		authSvc, "http://localhost/callback", log,
	)

	mfaService := mfasvc.NewService(cache.NewInMemoryTOTPRepository(), cache.NewInMemoryChallengeRepository(), authSvc, log)
	mfaService.WithWebAuthn(webauthnRepo, "localhost", "Test", []string{"http://localhost"})

	emailSender := newCapturingEmailSender()
	userService := usersvc.NewService(cache.NewInMemoryUserRepository(), cache.NewInMemorySessionRepository(), hasher, log).
		WithOTP(cache.NewInMemoryOTPRepository(), emailSender, adaptsms.NewConsoleSender(log))

	authSvc.WithUserValidator(userService)

	// Middleware
	tenantResolver := middleware.NewTenantResolver(tenantSvc, config.TenantModeHeader, log)
	adminAuth := middleware.NewAdminAuth(testAdminKey)
	authRateLimiter := middleware.NewRateLimiter(20, 1*time.Minute)

	// HTTP handlers
	discoveryHandler := handler.NewDiscoveryHandler(discoverySvc)
	jwksHandler := handler.NewJWKSHandler(jwksSvc)
	authorizeHandler := handler.NewAuthorizeHandler(authSvc).
		WithSocialService(socialSvc).
		WithUserService(userService).
		WithClientService(clientService).
		WithMFA(mfaService, tenantSvc)
	tokenHandler := handler.NewTokenHandler(authSvc).WithClientService(clientService)
	deviceHandler := handler.NewDeviceHandler(authSvc)
	revokeHandler := handler.NewRevokeHandler(authSvc)
	introspectHandler := handler.NewIntrospectHandler(authSvc)
	clientHandler := handler.NewClientHandler(clientService)
	socialHandler := handler.NewSocialHandler(socialSvc)
	providerHandler := handler.NewProviderHandler(providerService)
	mfaHandler := handler.NewMFAHandler(mfaService)
	userHandler := handler.NewUserHandler(userService)
	rbacHandler := handler.NewRBACHandler(rbacService)
	auditHandler := handler.NewAuditHandler(auditService)
	webhookService := webhooksvc.NewService(cache.NewInMemoryWebhookRepository(), log)
	webhookHandler := handler.NewWebhookHandler(webhookService)
	tenantHandler := handler.NewTenantHandler(tenantSvc)

	mux := http.NewServeMux()

	// OIDC/OAuth routes (tenant-scoped)
	mux.Handle("/.well-known/openid-configuration",
		tenantResolver.Middleware(http.HandlerFunc(discoveryHandler.HandleDiscovery)))
	mux.HandleFunc("/jwks", jwksHandler.HandleJWKS)
	mux.Handle("/authorize",
		tenantResolver.Middleware(http.HandlerFunc(authorizeHandler.HandleAuthorize)))
	mux.Handle("/token",
		authRateLimiter.Middleware(tenantResolver.Middleware(http.HandlerFunc(tokenHandler.HandleToken))))

	// OAuth endpoints (tenant-scoped)
	mux.Handle("/device/authorize",
		tenantResolver.Middleware(http.HandlerFunc(deviceHandler.HandleDeviceAuthorize)))
	mux.Handle("/revoke",
		tenantResolver.Middleware(http.HandlerFunc(revokeHandler.HandleRevoke)))
	mux.Handle("/introspect",
		tenantResolver.Middleware(http.HandlerFunc(introspectHandler.HandleIntrospect)))

	// Social login callback
	mux.HandleFunc("/callback", socialHandler.HandleCallback)

	// MFA endpoints
	mux.HandleFunc("/mfa/totp/enroll", mfaHandler.HandleEnroll)
	mux.HandleFunc("/mfa/totp/confirm", mfaHandler.HandleConfirm)
	mux.Handle("/mfa/verify", authRateLimiter.Middleware(http.HandlerFunc(mfaHandler.HandleVerify)))
	mux.HandleFunc("/mfa/webauthn/register/begin", mfaHandler.HandleWebAuthnRegisterBegin)
	mux.HandleFunc("/mfa/webauthn/register/finish", mfaHandler.HandleWebAuthnRegisterFinish)
	mux.HandleFunc("/mfa/webauthn/login/begin", mfaHandler.HandleWebAuthnLoginBegin)
	mux.HandleFunc("/mfa/webauthn/login/finish", mfaHandler.HandleWebAuthnLoginFinish)

	// User authentication endpoints (tenant-scoped)
	mux.Handle("/register",
		tenantResolver.Middleware(http.HandlerFunc(userHandler.HandleRegister)))
	mux.Handle("/login",
		authRateLimiter.Middleware(tenantResolver.Middleware(http.HandlerFunc(userHandler.HandleLogin))))
	mux.Handle("/logout",
		tenantResolver.Middleware(http.HandlerFunc(userHandler.HandleLogout)))
	mux.Handle("/userinfo",
		tenantResolver.Middleware(http.HandlerFunc(userHandler.HandleUserInfo)))

	// OTP endpoints (tenant-scoped)
	mux.Handle("/otp/request",
		tenantResolver.Middleware(http.HandlerFunc(userHandler.HandleRequestOTP)))
	mux.Handle("/otp/verify",
		authRateLimiter.Middleware(tenantResolver.Middleware(http.HandlerFunc(userHandler.HandleVerifyOTP))))
	mux.Handle("/password/reset",
		tenantResolver.Middleware(http.HandlerFunc(userHandler.HandleResetPassword)))

	// Management routes (admin auth required)
	mux.Handle("/tenants", adminAuth.Middleware(http.HandlerFunc(tenantHandler.HandleTenants)))
	mux.Handle("/tenants/", adminAuth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		if strings.HasSuffix(r.URL.Path, "/users") && !strings.Contains(r.URL.Path, "/users/") {
			userHandler.HandleListUsers(w, r)
			return
		}
		if strings.Contains(r.URL.Path, "/users/") && strings.Contains(r.URL.Path, "/permissions") {
			rbacHandler.HandleUserPermissions(w, r)
			return
		}
		if strings.Contains(r.URL.Path, "/users/") && strings.HasSuffix(r.URL.Path, "/roles") {
			rbacHandler.HandleUserRoles(w, r)
			return
		}
		if strings.Contains(r.URL.Path, "/roles") {
			if strings.Count(r.URL.Path, "/") >= 4 {
				rbacHandler.HandleRole(w, r)
			} else {
				rbacHandler.HandleRoles(w, r)
			}
			return
		}
		if strings.Contains(r.URL.Path, "/webhooks") {
			if strings.Count(r.URL.Path, "/") >= 4 {
				webhookHandler.HandleWebhook(w, r)
			} else {
				webhookHandler.HandleWebhooks(w, r)
			}
			return
		}
		if strings.Contains(r.URL.Path, "/audit") {
			auditHandler.HandleAuditLogs(w, r)
			return
		}
		tenantHandler.HandleTenant(w, r)
	})))

	// Health check
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		status, checks := health.NewRegistry().CheckAll(r.Context())
		httputil.WriteRaw(w, http.StatusOK, map[string]any{"status": status, "checks": checks}) //nolint:errcheck
	})

	return &fullTestEnv{
		server:      httptest.NewServer(middleware.NewCORS("*").Middleware(mux)),
		jwksSvc:     jwksSvc,
		adminKey:    testAdminKey,
		emailSender: emailSender,
	}
}

// ---------------------------------------------------------------------------
// HTTP helper methods
// ---------------------------------------------------------------------------

// doJSON makes a JSON request with the given method and returns (statusCode, parsedBody).
func (e *fullTestEnv) doJSON(t *testing.T, method, path string, body any, headers map[string]string) (int, map[string]any) {
	t.Helper()

	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		bodyReader = strings.NewReader(string(b))
	}

	req, err := http.NewRequest(method, e.server.URL+path, bodyReader)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	client := e.server.Client()
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var result map[string]any
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &result)
	}
	return resp.StatusCode, result
}

// get makes a GET request with optional headers and returns (statusCode, parsedBody).
func (e *fullTestEnv) get(t *testing.T, path string, headers map[string]string) (int, map[string]any) {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, e.server.URL+path, nil)
	require.NoError(t, err)
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	client := e.server.Client()
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var result map[string]any
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &result)
	}
	return resp.StatusCode, result
}

// postForm makes a form-urlencoded POST request and returns (statusCode, parsedBody).
func (e *fullTestEnv) postForm(t *testing.T, path string, form string, headers map[string]string) (int, map[string]any) {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, e.server.URL+path, strings.NewReader(form))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	client := e.server.Client()
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var result map[string]any
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &result)
	}
	return resp.StatusCode, result
}

// ---------------------------------------------------------------------------
// Composite helper methods for common E2E flows
// ---------------------------------------------------------------------------

// createTenant creates a tenant via the management API and provisions its signing key.
// Returns the tenant ID.
func (e *fullTestEnv) createTenant(t *testing.T, id, algorithm string) string {
	t.Helper()

	alg := algorithm
	if alg == "" {
		alg = "RS256"
	}

	status, _ := e.doJSON(t, http.MethodPost, "/tenants", map[string]any{
		"id":        id,
		"domain":    id + ".example.com",
		"issuer":    "https://" + id + ".example.com",
		"algorithm": alg,
	}, map[string]string{
		"Authorization": "Bearer " + e.adminKey,
	})
	require.Equal(t, http.StatusCreated, status, "failed to create tenant %s", id)

	// Provision signing key for the tenant
	algEnum := tenant.RS256
	if alg == "ES256" {
		algEnum = tenant.ES256
	}
	_, keyErr := e.jwksSvc.EnsureKeyPair(context.Background(), id, id+"-key", algEnum)
	require.Nil(t, keyErr, "failed to provision key for tenant %s", id)

	return id
}

// createClient creates an OAuth client under the given tenant.
// Returns (clientID, clientSecret). clientSecret may be empty for public clients.
func (e *fullTestEnv) createClient(t *testing.T, tenantID string, clientType string, grantTypes []string) (string, string) {
	t.Helper()

	if grantTypes == nil {
		grantTypes = []string{"authorization_code", "refresh_token"}
	}

	status, body := e.doJSON(t, http.MethodPost, "/tenants/"+tenantID+"/clients", map[string]any{
		"client_name":    "Test Client",
		"client_type":    clientType,
		"redirect_uris":  []string{"https://app.example.com/cb"},
		"allowed_scopes": []string{"openid", "profile", "email"},
		"grant_types":    grantTypes,
	}, map[string]string{
		"Authorization": "Bearer " + e.adminKey,
	})
	require.Equal(t, http.StatusCreated, status, "failed to create client for tenant %s", tenantID)

	data := body["data"].(map[string]any)
	clientID := data["client_id"].(string)

	var clientSecret string
	if sec, ok := data["client_secret"]; ok && sec != nil {
		clientSecret = sec.(string)
	}
	return clientID, clientSecret
}

// registerUser registers a user under the given tenant and returns the user ID.
func (e *fullTestEnv) registerUser(t *testing.T, tenantID, email, password, name string) string {
	t.Helper()

	status, body := e.doJSON(t, http.MethodPost, "/register", map[string]any{
		"email":    email,
		"password": password,
		"name":     name,
	}, map[string]string{
		"X-Tenant-ID": tenantID,
	})
	require.Equal(t, http.StatusCreated, status, "failed to register user %s", email)

	data := body["data"].(map[string]any)
	return data["user_id"].(string)
}

// loginUser logs in a user and returns the session token.
func (e *fullTestEnv) loginUser(t *testing.T, tenantID, email, password string) string {
	t.Helper()

	status, body := e.doJSON(t, http.MethodPost, "/login", map[string]any{
		"email":    email,
		"password": password,
	}, map[string]string{
		"X-Tenant-ID": tenantID,
	})
	require.Equal(t, http.StatusOK, status, "failed to login user %s", email)

	data := body["data"].(map[string]any)
	return data["session_token"].(string)
}

// authorizeWithPKCE performs the full authorize flow with PKCE and returns (authCode, codeVerifier).
func (e *fullTestEnv) authorizeWithPKCE(t *testing.T, tenantID, clientID, sessionToken, scope string) (string, string) {
	t.Helper()

	if scope == "" {
		scope = "openid profile"
	}

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	authURL := fmt.Sprintf("/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=%s&state=teststate&code_challenge=%s&code_challenge_method=S256",
		clientID, "https://app.example.com/cb", strings.ReplaceAll(scope, " ", "+"), challenge)

	req, err := http.NewRequest(http.MethodGet, e.server.URL+authURL, nil)
	require.NoError(t, err)
	req.Header.Set("X-Tenant-ID", tenantID)
	req.Header.Set("Authorization", "Bearer "+sessionToken)

	client := e.server.Client()
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err := client.Do(req)
	require.NoError(t, err)
	resp.Body.Close()

	require.Equal(t, http.StatusFound, resp.StatusCode, "authorize did not redirect")
	location := resp.Header.Get("Location")
	require.Contains(t, location, "code=", "authorize response missing code")

	code := strings.Split(strings.Split(location, "code=")[1], "&")[0]
	return code, verifier
}

// exchangeCode exchanges an authorization code for tokens and returns the full token response.
func (e *fullTestEnv) exchangeCode(t *testing.T, tenantID, clientID, clientSecret, code, verifier string) map[string]any {
	t.Helper()

	form := fmt.Sprintf("grant_type=authorization_code&code=%s&redirect_uri=%s&client_id=%s&code_verifier=%s",
		code, "https://app.example.com/cb", clientID, verifier)
	if clientSecret != "" {
		form += "&client_secret=" + clientSecret
	}

	status, body := e.postForm(t, "/token", form, map[string]string{
		"X-Tenant-ID": tenantID,
	})
	require.Equal(t, http.StatusOK, status, "token exchange failed")
	require.NotEmpty(t, body["access_token"], "missing access_token in token response")

	return body
}
