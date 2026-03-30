package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/authcore/internal/adapter/cache"
	adaptcrypto "github.com/authcore/internal/adapter/crypto"
	adaptemail "github.com/authcore/internal/adapter/email"
	"github.com/authcore/internal/adapter/http/handler"
	adapthttp "github.com/authcore/internal/adapter/http/oauth"
	"github.com/authcore/internal/adapter/http/middleware"
	"github.com/authcore/internal/adapter/postgres"
	adaptredis "github.com/authcore/internal/adapter/redis"
	adaptsms "github.com/authcore/internal/adapter/sms"
	adminsvc "github.com/authcore/internal/application/admin"
	"github.com/authcore/internal/application/auth"
	"github.com/authcore/internal/application/cleanup"
	clientsvc "github.com/authcore/internal/application/client"
	"github.com/authcore/internal/application/discovery"
	"github.com/authcore/internal/application/jwks"
	mfasvc "github.com/authcore/internal/application/mfa"
	providersvc "github.com/authcore/internal/application/provider"
	auditsvc "github.com/authcore/internal/application/audit"
	webhooksvc "github.com/authcore/internal/application/webhook"
	rbacsvc "github.com/authcore/internal/application/rbac"
	domainadmin "github.com/authcore/internal/domain/admin"
	domainaudit "github.com/authcore/internal/domain/audit"
	samlsvc "github.com/authcore/internal/application/saml"
	"github.com/authcore/internal/application/social"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	tenantsvc "github.com/authcore/internal/application/tenant"
	usersvc "github.com/authcore/internal/application/user"
	"github.com/authcore/internal/config"
	"github.com/authcore/internal/domain/client"
	"github.com/authcore/internal/domain/identity"
	"github.com/authcore/internal/domain/jwk"
	"github.com/authcore/internal/domain/mfa"
	domainotp "github.com/authcore/internal/domain/otp"
	"github.com/authcore/internal/domain/rbac"
	"github.com/authcore/internal/domain/tenant"
	"github.com/authcore/internal/domain/token"
	"github.com/authcore/internal/domain/webhook"
	"github.com/authcore/internal/domain/user"
	"github.com/authcore/pkg/sdk/health"
	"github.com/authcore/pkg/sdk/httputil"
	"github.com/authcore/pkg/sdk/logger"

	_ "github.com/jackc/pgx/v5/stdlib"
)

var (
	version = "dev"
	commit  = "none"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Printf("authcore %s (%s)\n", version, commit)
		return
	}

	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// repos holds all repository implementations.
type repos struct {
	jwk             jwk.Repository
	tenant          tenant.Repository
	client          client.Repository
	user            user.Repository
	session         user.SessionRepository
	code            token.CodeRepository
	refresh         token.RefreshTokenRepository
	device          token.DeviceCodeRepository
	blacklist       token.TokenBlacklist
	provider        identity.ProviderRepository
	externalID      identity.ExternalIdentityRepository
	state           identity.StateRepository
	totp            mfa.TOTPRepository
	challenge       mfa.ChallengeRepository
	webauthn        mfa.WebAuthnRepository
	role            rbac.RoleRepository
	assignment      rbac.AssignmentRepository
	audit           domainaudit.Repository
	adminUser       domainadmin.AdminUserRepository
	webhook         webhook.Repository
}

// setupInMemoryRepos creates all in-memory repositories (development mode).
func setupInMemoryRepos() repos {
	roleRepo := cache.NewInMemoryRoleRepository()
	return repos{
		jwk:        cache.NewInMemoryJWKRepository(),
		tenant:     cache.NewInMemoryTenantRepository(),
		client:     cache.NewInMemoryClientRepository(),
		user:       cache.NewInMemoryUserRepository(),
		session:    cache.NewInMemorySessionRepository(),
		code:       cache.NewInMemoryCodeRepository(),
		refresh:    cache.NewInMemoryRefreshRepository(),
		device:     cache.NewInMemoryDeviceRepository(),
		blacklist:  cache.NewInMemoryBlacklist(),
		provider:   cache.NewInMemoryProviderRepository(),
		externalID: cache.NewInMemoryExternalIdentityRepository(),
		state:      cache.NewInMemoryStateRepository(),
		totp:       cache.NewInMemoryTOTPRepository(),
		challenge:  cache.NewInMemoryChallengeRepository(),
		webauthn:   cache.NewInMemoryWebAuthnRepository(),
		role:       roleRepo,
		assignment: cache.NewInMemoryAssignmentRepository(roleRepo),
		audit:      cache.NewInMemoryAuditRepository(),
		adminUser:  cache.NewInMemoryAdminUserRepository(),
		webhook:    cache.NewInMemoryWebhookRepository(),
	}
}

// setupProdRepos creates Postgres + Redis backed repos for production.
func setupProdRepos(db *sql.DB, redisClient *adaptredis.Client) repos {
	rdb := redisClient.Redis()
	roleRepo := postgres.NewRoleRepository(db)
	return repos{
		jwk:        postgres.NewJWKRepository(db),
		tenant:     postgres.NewTenantRepository(db),
		client:     postgres.NewClientRepository(db),
		user:       postgres.NewUserRepository(db),
		refresh:    postgres.NewRefreshTokenRepository(db),
		provider:   postgres.NewProviderRepository(db),
		externalID: postgres.NewExternalIdentityRepository(db),
		session:    adaptredis.NewSessionRepository(rdb),
		code:       adaptredis.NewCodeRepository(rdb),
		device:     adaptredis.NewDeviceCodeRepository(rdb),
		blacklist:  adaptredis.NewTokenBlacklist(rdb),
		state:      adaptredis.NewStateRepository(rdb),
		totp:       cache.NewInMemoryTOTPRepository(),
		challenge:  cache.NewInMemoryChallengeRepository(),
		webauthn:   cache.NewInMemoryWebAuthnRepository(),
		role:       roleRepo,
		assignment: postgres.NewAssignmentRepository(db, roleRepo),
		audit:      postgres.NewAuditRepository(db),
		adminUser:  cache.NewInMemoryAdminUserRepository(),
		webhook:    cache.NewInMemoryWebhookRepository(),
	}
}

// setupPostgresRepos creates Postgres-backed repos without Redis (fallback).
func setupPostgresRepos(db *sql.DB) repos {
	roleRepo := postgres.NewRoleRepository(db)
	return repos{
		jwk:        postgres.NewJWKRepository(db),
		tenant:     postgres.NewTenantRepository(db),
		client:     postgres.NewClientRepository(db),
		user:       postgres.NewUserRepository(db),
		refresh:    postgres.NewRefreshTokenRepository(db),
		provider:   postgres.NewProviderRepository(db),
		externalID: postgres.NewExternalIdentityRepository(db),
		session:    cache.NewInMemorySessionRepository(),
		code:       cache.NewInMemoryCodeRepository(),
		device:     cache.NewInMemoryDeviceRepository(),
		blacklist:  cache.NewInMemoryBlacklist(),
		state:      cache.NewInMemoryStateRepository(),
		totp:       cache.NewInMemoryTOTPRepository(),
		challenge:  cache.NewInMemoryChallengeRepository(),
		webauthn:   cache.NewInMemoryWebAuthnRepository(),
		role:       roleRepo,
		assignment: postgres.NewAssignmentRepository(db, roleRepo),
		audit:      postgres.NewAuditRepository(db),
		adminUser:  cache.NewInMemoryAdminUserRepository(),
		webhook:    cache.NewInMemoryWebhookRepository(),
	}
}

// setupServer creates the HTTP handler with all routes wired.
func setupServer(cfg config.Config, log *slog.Logger) http.Handler {
	return setupServerWithRepos(cfg, log, setupInMemoryRepos())
}

// setupServerWithRepos creates the HTTP handler with the given repositories.
func setupServerWithRepos(cfg config.Config, log *slog.Logger, r repos) http.Handler {
	keyGen := adaptcrypto.NewKeyGenerator()
	keyConv := adaptcrypto.NewJWKConverter()
	hasher := adaptcrypto.NewBcryptHasher()
	jwtSigner := adaptcrypto.NewJWTSigner()

	// Application services
	jwksSvc := jwks.NewService(r.jwk, keyGen, keyConv, log)
	discoverySvc := discovery.NewService(cfg.Issuer, log)

	authSvc := auth.NewService(r.code, jwksSvc, jwtSigner, log).
		WithRefreshRepo(r.refresh).
		WithDeviceRepo(r.device).
		WithBlacklist(r.blacklist)

	webhookService := webhooksvc.NewService(r.webhook, log)
	auditService := auditsvc.NewService(r.audit, log)
	auditService.WithWebhooks(webhookService)

	clientService := clientsvc.NewService(r.client, hasher, log)
	clientService.WithAudit(auditService)
	tenantSvc := tenantsvc.NewService(r.tenant, log)
	tenantSvc.WithAudit(auditService)
	rbacService := rbacsvc.NewService(r.role, r.assignment, log)
	rbacService.WithAudit(auditService)

	// Wire RBAC into auth service for JWT claims
	authSvc.WithRBAC(r.assignment)
	authSvc.WithAudit(auditService)
	authSvc.WithClientRepo(r.client)

	oauthClient := adapthttp.NewHTTPOAuthClient()
	providerService := providersvc.NewService(r.provider, log)
	providerService.WithAudit(auditService)
	socialSvc := social.NewService(r.provider, r.externalID, r.state, oauthClient,
		authSvc, cfg.Issuer+"/callback", log)

	samlService := samlsvc.NewService(r.provider, r.externalID, r.state, authSvc, cfg.Issuer, log)

	mfaService := mfasvc.NewService(r.totp, r.challenge, authSvc, log)
	mfaService.WithAudit(auditService)
	mfaService.WithWebAuthn(r.webauthn, cfg.WebAuthnRPID, cfg.WebAuthnRPName, strings.Split(cfg.WebAuthnRPOrigins, ","))

	// OTP senders (console for local, SMTP/Twilio for prod)
	var emailSender domainotp.EmailSender
	var smsSender domainotp.SMSSender
	if cfg.SMTPHost != "" {
		emailSender = adaptemail.NewSMTPSender(cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPUsername, cfg.SMTPPassword, cfg.SMTPFrom)
	} else {
		emailSender = adaptemail.NewConsoleSender(log)
	}
	if cfg.SMSProvider == "twilio" {
		smsSender = adaptsms.NewTwilioSender(cfg.SMSAccountID, cfg.SMSAuthToken, cfg.SMSFromNumber)
	} else {
		smsSender = adaptsms.NewConsoleSender(log)
	}

	otpRepo := cache.NewInMemoryOTPRepository()
	userService := usersvc.NewService(r.user, r.session, hasher, log).
		WithOTP(otpRepo, emailSender, smsSender)
	userService.WithAudit(auditService)

	authSvc.WithUserValidator(userService)

	// Admin service
	adminService := adminsvc.NewService(r.adminUser, hasher, log)

	// Middleware
	corsMiddleware := middleware.NewCORS(cfg.CORSOrigins)
	tracingMiddleware := middleware.NewTracing()
	adminAuth := middleware.NewAdminAuth(cfg.AdminAPIKey).
		WithJWTVerifier(buildAdminJWTVerifier(jwksSvc))
	authRateLimiter := middleware.NewRateLimiter(20, 1*time.Minute)
	tenantResolver := middleware.NewTenantResolver(tenantSvc, cfg.TenantMode, log)

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
	samlHandler := handler.NewSAMLHandler(samlService)
	providerHandler := handler.NewProviderHandler(providerService)
	mfaHandler := handler.NewMFAHandler(mfaService)
	userHandler := handler.NewUserHandler(userService)
	rbacHandler := handler.NewRBACHandler(rbacService)
	auditHandler := handler.NewAuditHandler(auditService)
	tenantHandler := handler.NewTenantHandler(tenantSvc)
	webhookHandler := handler.NewWebhookHandler(webhookService)
	adminHandler := handler.NewAdminHandler(adminService, jwksSvc, jwtSigner, cfg.Issuer, cfg.AdminAPIKey)

	healthRegistry := health.NewRegistry()

	mux := http.NewServeMux()

	// OIDC/OAuth routes (wrapped with tenant middleware)
	mux.Handle("/.well-known/openid-configuration",
		tenantResolver.Middleware(http.HandlerFunc(discoveryHandler.HandleDiscovery)))
	// JWKS is public (no tenant middleware) — allows standard OIDC libraries to fetch keys
	// The handler falls back to X-Tenant-ID header or "default" tenant
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

	// Social login callback (no tenant middleware — state contains tenant info)
	mux.HandleFunc("/callback", socialHandler.HandleCallback)

	// SAML endpoints
	mux.HandleFunc("/saml/metadata", samlHandler.HandleMetadata) // public
	mux.Handle("/saml/sso",
		tenantResolver.Middleware(http.HandlerFunc(samlHandler.HandleSSO))) // tenant-scoped
	mux.HandleFunc("/saml/acs", samlHandler.HandleACS) // public (IdP posts here)

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

	// Admin routes (no tenant middleware)
	mux.HandleFunc("/admin/bootstrap", adminHandler.HandleBootstrap)
	mux.HandleFunc("/admin/login", adminHandler.HandleLogin)
	mux.Handle("/admin/users", adminAuth.Middleware(http.HandlerFunc(adminHandler.HandleUsers)))

	// Management routes (admin auth required, no tenant middleware)
	mux.Handle("/tenants", adminAuth.Middleware(http.HandlerFunc(tenantHandler.HandleTenants)))
	mux.Handle("/tenants/", adminAuth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Route to sub-resources
		if strings.Contains(r.URL.Path, "/clients") {
			if strings.Contains(r.URL.Path, "/api-key") {
				clientHandler.HandleAPIKey(w, r)
				return
			}
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
		if strings.Contains(r.URL.Path, "/roles") {
			if strings.Count(r.URL.Path, "/") >= 4 {
				rbacHandler.HandleRole(w, r)
			} else {
				rbacHandler.HandleRoles(w, r)
			}
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

	// Prometheus metrics
	mux.Handle("/metrics", promhttp.Handler())

	// Health check
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		status, checks := healthRegistry.CheckAll(r.Context())
		code := http.StatusOK
		if status != health.StatusUp {
			code = http.StatusServiceUnavailable
		}
		httputil.WriteRaw(w, code, map[string]any{ //nolint:errcheck
			"status": status,
			"checks": checks,
		})
	})

	// Wrap entire mux: request ID → security headers → tracing → CORS
	return middleware.RequestID(middleware.SecurityHeaders(tracingMiddleware.Middleware(corsMiddleware.Middleware(mux))))
}

// connectDB opens and verifies a database connection, runs migrations.
func connectDB(ctx context.Context, cfg config.Config, log *slog.Logger) (*sql.DB, error) {
	db, err := sql.Open("pgx", cfg.DatabaseDSN)
	if err != nil {
		return nil, fmt.Errorf("database open: %w", err)
	}

	// Connection pool settings for production use
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)
	db.SetConnMaxIdleTime(5 * time.Minute)

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("database ping: %w", err)
	}
	log.Info("database connected", "driver", cfg.DatabaseDriver)

	if err := postgres.RunMigrations(ctx, db, log); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrations: %w", err)
	}

	return db, nil
}

// buildAdminJWTVerifier creates a JWT verification function that uses the JWKS
// service to cryptographically verify admin JWT signatures before trusting claims.
func buildAdminJWTVerifier(jwksSvc *jwks.Service) middleware.JWTVerifier {
	return func(tokenStr string) (*middleware.AdminContext, error) {
		parts := strings.Split(tokenStr, ".")
		if len(parts) != 3 {
			return nil, fmt.Errorf("malformed JWT")
		}

		// Decode header for algorithm
		headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			return nil, fmt.Errorf("invalid header encoding")
		}
		var header struct {
			Alg string `json:"alg"`
		}
		if err := json.Unmarshal(headerJSON, &header); err != nil {
			return nil, fmt.Errorf("invalid header")
		}

		// Decode payload to get audience (admin tokens use "authcore-admin")
		payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, fmt.Errorf("invalid payload encoding")
		}
		var claims struct {
			Subject   string   `json:"sub"`
			Audience  []string `json:"aud"`
			ExpiresAt int64    `json:"exp"`
			Roles     []string `json:"roles"`
		}
		if err := json.Unmarshal(payloadJSON, &claims); err != nil {
			return nil, fmt.Errorf("invalid claims")
		}

		// Verify audience
		isAdmin := false
		for _, aud := range claims.Audience {
			if aud == "authcore-admin" {
				isAdmin = true
				break
			}
		}
		if !isAdmin {
			return nil, fmt.Errorf("not an admin token")
		}

		// Check expiry
		if claims.ExpiresAt > 0 && time.Now().Unix() > claims.ExpiresAt {
			return nil, fmt.Errorf("token expired")
		}

		if claims.Subject == "" {
			return nil, fmt.Errorf("missing subject")
		}

		// Get signing key for "default" tenant (admin tokens are signed with default tenant key)
		kp, kpErr := jwksSvc.GetActiveKeyPair(context.Background(), "default")
		if kpErr != nil {
			return nil, fmt.Errorf("no signing key available for verification")
		}

		// Verify signature
		signingInput := parts[0] + "." + parts[1]
		sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			return nil, fmt.Errorf("invalid signature encoding")
		}

		if err := adminVerifySignature(signingInput, sigBytes, kp.PublicKey, header.Alg); err != nil {
			return nil, fmt.Errorf("signature verification failed: %w", err)
		}

		// Extract role
		var role domainadmin.AdminRole
		if len(claims.Roles) > 0 {
			role = domainadmin.AdminRole(claims.Roles[0])
		}
		if !role.IsValid() {
			return nil, fmt.Errorf("invalid admin role")
		}

		return &middleware.AdminContext{
			Role:    role,
			AdminID: claims.Subject,
		}, nil
	}
}

// adminVerifySignature verifies RSA or ECDSA signature with a PEM-encoded public key.
func adminVerifySignature(signingInput string, signature, publicKeyPEM []byte, algorithm string) error {
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return fmt.Errorf("failed to decode public key PEM")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	hash := sha256.Sum256([]byte(signingInput))

	switch algorithm {
	case "RS256":
		rsaPub, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("expected RSA public key")
		}
		return rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hash[:], signature)
	case "ES256":
		ecPub, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("expected EC public key")
		}
		byteLen := (ecPub.Curve.Params().BitSize + 7) / 8
		if len(signature) != 2*byteLen {
			return fmt.Errorf("invalid ECDSA signature length")
		}
		r := new(big.Int).SetBytes(signature[:byteLen])
		s := new(big.Int).SetBytes(signature[byteLen:])
		if !ecdsa.Verify(ecPub, hash[:], r, s) {
			return fmt.Errorf("ECDSA verification failed")
		}
		return nil
	default:
		return fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

func run() error {
	cfgResult := config.Load()
	cfg, appErr := cfgResult.Unwrap()
	if appErr != nil {
		return fmt.Errorf("config: %w", appErr)
	}

	log := logger.New(cfg.Environment)
	log.Info("authcore starting", "version", version, "commit", commit, "port", cfg.HTTPPort, "env", cfg.Environment)

	var mux http.Handler
	var r repos

	if cfg.Environment != logger.Local {
		db, err := connectDB(context.Background(), cfg, log)
		if err != nil {
			return err
		}
		defer db.Close()

		// Connect to Redis if URL is configured
		if cfg.RedisURL != "" {
			redisClient, err := adaptredis.NewClient(context.Background(), cfg.RedisURL)
			if err != nil {
				log.Warn("redis connection failed, using in-memory for ephemeral stores", "error", err)
				r = setupPostgresRepos(db)
			} else {
				defer redisClient.Close()
				log.Info("redis connected")
				r = setupProdRepos(db, redisClient)
			}
		} else {
			r = setupPostgresRepos(db)
		}

		mux = setupServerWithRepos(cfg, log, r)
	} else {
		log.Info("using in-memory storage (local mode)")
		r = setupInMemoryRepos()
		mux = setupServerWithRepos(cfg, log, r)
	}

	// Start background cleanup service (token cleanup + key rotation)
	keyGen := adaptcrypto.NewKeyGenerator()
	keyConv := adaptcrypto.NewJWKConverter()
	jwksSvc := jwks.NewService(r.jwk, keyGen, keyConv, log)
	cleanupSvc := cleanup.NewService(r.refresh, r.jwk, jwksSvc, r.tenant, log, cfg.KeyRotationDays)
	cleanupCtx, cleanupCancel := context.WithCancel(context.Background())
	defer cleanupCancel()
	go cleanupSvc.Start(cleanupCtx)

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.HTTPPort),
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("HTTP server listening", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-quit:
		log.Info("shutting down", "signal", sig.String())
	case err := <-errCh:
		if err != nil {
			return err
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return srv.Shutdown(ctx)
}
