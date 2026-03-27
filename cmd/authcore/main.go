package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
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
	"github.com/authcore/internal/application/auth"
	clientsvc "github.com/authcore/internal/application/client"
	"github.com/authcore/internal/application/discovery"
	"github.com/authcore/internal/application/jwks"
	mfasvc "github.com/authcore/internal/application/mfa"
	providersvc "github.com/authcore/internal/application/provider"
	"github.com/authcore/internal/application/social"
	tenantsvc "github.com/authcore/internal/application/tenant"
	usersvc "github.com/authcore/internal/application/user"
	"github.com/authcore/internal/config"
	"github.com/authcore/internal/domain/client"
	"github.com/authcore/internal/domain/identity"
	"github.com/authcore/internal/domain/jwk"
	"github.com/authcore/internal/domain/mfa"
	domainotp "github.com/authcore/internal/domain/otp"
	"github.com/authcore/internal/domain/tenant"
	"github.com/authcore/internal/domain/token"
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
}

// setupInMemoryRepos creates all in-memory repositories (development mode).
func setupInMemoryRepos() repos {
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
	}
}

// setupProdRepos creates Postgres + Redis backed repos for production.
func setupProdRepos(db *sql.DB, redisClient *adaptredis.Client) repos {
	rdb := redisClient.Redis()
	return repos{
		// Persistent repos (Postgres)
		jwk:        postgres.NewJWKRepository(db),
		tenant:     postgres.NewTenantRepository(db),
		client:     postgres.NewClientRepository(db),
		user:       postgres.NewUserRepository(db),
		refresh:    postgres.NewRefreshTokenRepository(db),
		provider:   postgres.NewProviderRepository(db),
		externalID: postgres.NewExternalIdentityRepository(db),
		// Ephemeral repos (Redis with TTL)
		session:    adaptredis.NewSessionRepository(rdb),
		code:       adaptredis.NewCodeRepository(rdb),
		device:     adaptredis.NewDeviceCodeRepository(rdb),
		blacklist:  adaptredis.NewTokenBlacklist(rdb),
		state:      adaptredis.NewStateRepository(rdb),
		// MFA repos stay in-memory (low volume, short TTL)
		totp:       cache.NewInMemoryTOTPRepository(),
		challenge:  cache.NewInMemoryChallengeRepository(),
	}
}

// setupPostgresRepos creates Postgres-backed repos without Redis (fallback).
func setupPostgresRepos(db *sql.DB) repos {
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

	clientService := clientsvc.NewService(r.client, hasher, log)
	tenantSvc := tenantsvc.NewService(r.tenant, log)

	oauthClient := adapthttp.NewHTTPOAuthClient()
	providerService := providersvc.NewService(r.provider, log)
	socialSvc := social.NewService(r.provider, r.externalID, r.state, oauthClient,
		authSvc, cfg.Issuer+"/callback", log)

	mfaService := mfasvc.NewService(r.totp, r.challenge, authSvc, log)

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

	authSvc.WithUserValidator(userService)

	// Middleware
	corsMiddleware := middleware.NewCORS(cfg.CORSOrigins)
	adminAuth := middleware.NewAdminAuth(cfg.AdminAPIKey)
	authRateLimiter := middleware.NewRateLimiter(20, 1*time.Minute) // 20 req/min per IP for auth endpoints
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
	providerHandler := handler.NewProviderHandler(providerService)
	mfaHandler := handler.NewMFAHandler(mfaService)
	userHandler := handler.NewUserHandler(userService)
	tenantHandler := handler.NewTenantHandler(tenantSvc)

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

	// MFA endpoints
	mux.HandleFunc("/mfa/totp/enroll", mfaHandler.HandleEnroll)
	mux.HandleFunc("/mfa/totp/confirm", mfaHandler.HandleConfirm)
	mux.Handle("/mfa/verify", authRateLimiter.Middleware(http.HandlerFunc(mfaHandler.HandleVerify)))

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

	// Management routes (admin auth required, no tenant middleware)
	mux.Handle("/tenants", adminAuth.Middleware(http.HandlerFunc(tenantHandler.HandleTenants)))
	mux.Handle("/tenants/", adminAuth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Route to sub-resources
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
	})))

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

	// Wrap entire mux with CORS
	return corsMiddleware.Middleware(mux)
}

// connectDB opens and verifies a database connection, runs migrations.
func connectDB(ctx context.Context, cfg config.Config, log *slog.Logger) (*sql.DB, error) {
	db, err := sql.Open("pgx", cfg.DatabaseDSN)
	if err != nil {
		return nil, fmt.Errorf("database open: %w", err)
	}

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

func run() error {
	cfgResult := config.Load()
	cfg, appErr := cfgResult.Unwrap()
	if appErr != nil {
		return fmt.Errorf("config: %w", appErr)
	}

	log := logger.New(cfg.Environment)
	log.Info("authcore starting", "version", version, "commit", commit, "port", cfg.HTTPPort, "env", cfg.Environment)

	var mux http.Handler

	if cfg.Environment != logger.Local {
		db, err := connectDB(context.Background(), cfg, log)
		if err != nil {
			return err
		}
		defer db.Close()

		// Connect to Redis if URL is configured
		var r repos
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
		mux = setupServer(cfg, log)
	}

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
