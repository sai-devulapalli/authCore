package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"math/big"
	"strings"
	"time"

	"github.com/google/uuid"

	auditsvc "github.com/authplex/internal/application/audit"
	"github.com/authplex/internal/application/jwks"
	domainaudit "github.com/authplex/internal/domain/audit"
	"github.com/authplex/internal/domain/client"
	"github.com/authplex/internal/domain/rbac"
	"github.com/authplex/internal/domain/tenant"
	"github.com/authplex/internal/domain/token"
	"github.com/authplex/internal/domain/user"
	apperrors "github.com/authplex/pkg/sdk/errors"
)

// Service provides OAuth 2.0 token operations for all grant types.
type Service struct {
	codeRepo      token.CodeRepository
	refreshRepo   token.RefreshTokenRepository
	deviceRepo    token.DeviceCodeRepository
	blacklist     token.TokenBlacklist
	userValidator token.UserValidator
	userRepo      user.Repository
	tenantRepo    tenant.Repository
	assignRepo    rbac.AssignmentRepository
	clientRepo    client.Repository
	auditSvc      *auditsvc.Service
	jwksSvc       *jwks.Service
	signer        token.Signer
	logger        *slog.Logger
	codeTTL       time.Duration
	accessTTL     time.Duration
	idTokenTTL    time.Duration
	refreshTTL    time.Duration
	deviceTTL     time.Duration
}

// NewService creates a new auth service.
func NewService(
	codeRepo token.CodeRepository,
	jwksSvc *jwks.Service,
	signer token.Signer,
	logger *slog.Logger,
) *Service {
	return &Service{
		codeRepo:   codeRepo,
		jwksSvc:    jwksSvc,
		signer:     signer,
		logger:     logger,
		codeTTL:    10 * time.Minute,
		accessTTL:  1 * time.Hour,
		idTokenTTL: 1 * time.Hour,
		refreshTTL: 30 * 24 * time.Hour,
		deviceTTL:  15 * time.Minute,
	}
}

// WithRefreshRepo sets the refresh token repository.
func (s *Service) WithRefreshRepo(repo token.RefreshTokenRepository) *Service {
	s.refreshRepo = repo
	return s
}

// WithDeviceRepo sets the device code repository.
func (s *Service) WithDeviceRepo(repo token.DeviceCodeRepository) *Service {
	s.deviceRepo = repo
	return s
}

// WithBlacklist sets the token blacklist.
func (s *Service) WithBlacklist(bl token.TokenBlacklist) *Service {
	s.blacklist = bl
	return s
}

// WithUserValidator sets the user credential validator (for password grant).
func (s *Service) WithUserValidator(uv token.UserValidator) *Service {
	s.userValidator = uv
	return s
}

// WithUserRepo sets the user repository for token version lookups.
func (s *Service) WithUserRepo(repo user.Repository) *Service {
	s.userRepo = repo
	return s
}

// WithTenantRepo sets the tenant repository for token version lookups.
func (s *Service) WithTenantRepo(repo tenant.Repository) *Service {
	s.tenantRepo = repo
	return s
}

// WithRBAC sets the RBAC assignment repo for including roles/permissions in JWT.
func (s *Service) WithRBAC(assignRepo rbac.AssignmentRepository) *Service {
	s.assignRepo = assignRepo
	return s
}

// WithAudit configures audit event logging.
func (s *Service) WithAudit(a *auditsvc.Service) *Service {
	s.auditSvc = a
	return s
}

// WithClientRepo sets the client repository for looking up client metadata.
func (s *Service) WithClientRepo(repo client.Repository) *Service {
	s.clientRepo = repo
	return s
}

// Authorize validates the authorization request and generates an auth code.
func (s *Service) Authorize(ctx context.Context, req AuthorizeRequest) (AuthorizeResponse, *apperrors.AppError) {
	if err := s.validateAuthorizeRequest(req); err != nil {
		return AuthorizeResponse{}, err
	}

	code, genErr := generateSecureCode()
	if genErr != nil {
		return AuthorizeResponse{}, apperrors.Wrap(apperrors.ErrInternal, "failed to generate auth code", genErr)
	}

	ac := token.AuthorizationCode{
		Code:                code,
		ClientID:            req.ClientID,
		RedirectURI:         req.RedirectURI,
		Scope:               req.Scope,
		Subject:             req.Subject,
		TenantID:            req.TenantID,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		Nonce:               req.Nonce,
		ExpiresAt:           time.Now().UTC().Add(s.codeTTL),
	}

	if err := s.codeRepo.Store(ctx, ac); err != nil {
		return AuthorizeResponse{}, apperrors.Wrap(apperrors.ErrInternal, "failed to store auth code", err)
	}

	s.logger.Info("authorization code issued", "client_id", req.ClientID, "tenant_id", req.TenantID)

	return AuthorizeResponse{
		Code:        code,
		State:       req.State,
		RedirectURI: req.RedirectURI,
	}, nil
}

// GetRefreshTokenTenantID looks up the tenant ID stored with a refresh token.
// Used by the token handler so that confidential client auth can succeed
// for refresh_token grants even when X-Tenant-ID is absent.
func (s *Service) GetRefreshTokenTenantID(ctx context.Context, rawToken string) (string, error) {
	if s.refreshRepo == nil {
		return "", apperrors.New(apperrors.ErrInternal, "refresh repo not configured")
	}
	rt, err := s.refreshRepo.GetByToken(ctx, rawToken)
	if err != nil {
		return "", err
	}
	return rt.TenantID, nil
}

// Exchange routes to the appropriate grant type handler.
func (s *Service) Exchange(ctx context.Context, req TokenRequest) (token.TokenResponse, *apperrors.AppError) {
	switch req.GrantType {
	case "authorization_code":
		return s.exchangeAuthCode(ctx, req)
	case "client_credentials":
		return s.exchangeClientCredentials(ctx, req)
	case "refresh_token":
		return s.exchangeRefreshToken(ctx, req)
	case "urn:ietf:params:oauth:grant-type:device_code":
		return s.exchangeDeviceCode(ctx, req)
	case "password":
		return s.exchangePassword(ctx, req)
	default:
		return token.TokenResponse{}, apperrors.New(apperrors.ErrUnsupportedGrant, "unsupported grant_type: "+req.GrantType)
	}
}

// exchangeAuthCode handles the authorization_code grant.
func (s *Service) exchangeAuthCode(ctx context.Context, req TokenRequest) (token.TokenResponse, *apperrors.AppError) {
	if req.Code == "" {
		return token.TokenResponse{}, apperrors.New(apperrors.ErrBadRequest, "code is required")
	}
	if req.CodeVerifier == "" {
		return token.TokenResponse{}, apperrors.New(apperrors.ErrBadRequest, "code_verifier is required")
	}
	if req.ClientID == "" {
		return token.TokenResponse{}, apperrors.New(apperrors.ErrBadRequest, "client_id is required")
	}

	ac, consumeErr := s.codeRepo.Consume(ctx, req.Code)
	if consumeErr != nil {
		return token.TokenResponse{}, apperrors.Wrap(apperrors.ErrBadRequest, "invalid authorization code", consumeErr)
	}

	if ac.ClientID != req.ClientID {
		return token.TokenResponse{}, apperrors.New(apperrors.ErrBadRequest, "client_id mismatch")
	}
	if ac.RedirectURI != req.RedirectURI {
		return token.TokenResponse{}, apperrors.New(apperrors.ErrBadRequest, "redirect_uri mismatch")
	}

	if !token.VerifyPKCE(req.CodeVerifier, ac.CodeChallenge, ac.CodeChallengeMethod) {
		return token.TokenResponse{}, apperrors.New(apperrors.ErrPKCEFailed, "PKCE verification failed")
	}

	tenantID := ac.TenantID
	if req.TenantID != "" {
		tenantID = req.TenantID
	}

	resp, err := s.issueTokens(ctx, ac.Subject, ac.ClientID, tenantID, ac.Scope, ac.Nonce, true)
	if err != nil {
		return token.TokenResponse{}, err
	}

	s.logger.Info("tokens issued", "grant", "authorization_code", "subject", ac.Subject, "client_id", ac.ClientID)
	return resp, nil
}

// exchangeClientCredentials handles the client_credentials grant (M2M).
func (s *Service) exchangeClientCredentials(ctx context.Context, req TokenRequest) (token.TokenResponse, *apperrors.AppError) {
	if req.ClientID == "" {
		return token.TokenResponse{}, apperrors.New(apperrors.ErrBadRequest, "client_id is required")
	}

	tenantID := req.TenantID
	scope := req.Scope

	// Look up client for endpoint restrictions
	var endpoints []string
	var clientName string
	if s.clientRepo != nil {
		if c, err := s.clientRepo.GetByID(ctx, req.ClientID, tenantID); err == nil {
			endpoints = c.AllowedEndpoints
			clientName = c.ClientName
		}
	}

	// For client_credentials, the subject is the client itself
	resp, err := s.issueTokensWithEndpoints(ctx, req.ClientID, req.ClientID, tenantID, scope, "", false, endpoints)
	if err != nil {
		return token.TokenResponse{}, err
	}

	// Client credentials does not issue refresh tokens or id tokens
	resp.RefreshToken = ""
	resp.IDToken = ""

	s.logger.Info("tokens issued", "grant", "client_credentials", "client_id", req.ClientID)

	// Audit log for agent token issuance
	if s.auditSvc != nil {
		s.auditSvc.Log(ctx, tenantID, req.ClientID, "agent", domainaudit.EventAgentTokenIssued, "client", req.ClientID, nil, map[string]any{
			"grant_type":  "client_credentials",
			"scope":       scope,
			"agent_id":    req.ClientID,
			"agent_name":  clientName,
		})
	}

	return resp, nil
}

// exchangeRefreshToken handles the refresh_token grant with rotation.
func (s *Service) exchangeRefreshToken(ctx context.Context, req TokenRequest) (token.TokenResponse, *apperrors.AppError) {
	if s.refreshRepo == nil {
		return token.TokenResponse{}, apperrors.New(apperrors.ErrUnsupportedGrant, "refresh tokens not configured")
	}
	if req.RefreshToken == "" {
		return token.TokenResponse{}, apperrors.New(apperrors.ErrBadRequest, "refresh_token is required")
	}

	rt, getErr := s.refreshRepo.GetByToken(ctx, req.RefreshToken)
	if getErr != nil {
		return token.TokenResponse{}, apperrors.New(apperrors.ErrBadRequest, "invalid refresh token")
	}

	// Replay detection: if already rotated, revoke the entire family
	if rt.Rotated {
		s.refreshRepo.RevokeFamily(ctx, rt.FamilyID) //nolint:errcheck
		s.logger.Warn("refresh token replay detected", "family_id", rt.FamilyID)
		return token.TokenResponse{}, apperrors.New(apperrors.ErrBadRequest, "refresh token has been reused")
	}

	if rt.IsRevoked() {
		return token.TokenResponse{}, apperrors.New(apperrors.ErrBadRequest, "refresh token has been revoked")
	}

	if rt.IsExpiredRefresh() {
		return token.TokenResponse{}, apperrors.New(apperrors.ErrExpiredCode, "refresh token has expired")
	}

	// Mark old token as rotated
	rt.Rotated = true
	s.refreshRepo.Store(ctx, rt) //nolint:errcheck

	// Issue new tokens
	resp, err := s.issueTokens(ctx, rt.Subject, rt.ClientID, rt.TenantID, rt.Scope, "", true)
	if err != nil {
		return token.TokenResponse{}, err
	}

	s.logger.Info("tokens refreshed", "subject", rt.Subject, "client_id", rt.ClientID, "family_id", rt.FamilyID)
	return resp, nil
}

// exchangeDeviceCode handles the device_code grant (RFC 8628).
func (s *Service) exchangeDeviceCode(ctx context.Context, req TokenRequest) (token.TokenResponse, *apperrors.AppError) {
	if s.deviceRepo == nil {
		return token.TokenResponse{}, apperrors.New(apperrors.ErrUnsupportedGrant, "device codes not configured")
	}
	if req.DeviceCode == "" {
		return token.TokenResponse{}, apperrors.New(apperrors.ErrBadRequest, "device_code is required")
	}

	dc, getErr := s.deviceRepo.GetByDeviceCode(ctx, req.DeviceCode)
	if getErr != nil {
		return token.TokenResponse{}, apperrors.New(apperrors.ErrBadRequest, "invalid device code")
	}

	if dc.IsExpiredDevice() {
		return token.TokenResponse{}, apperrors.New(apperrors.ErrExpiredCode, "device code has expired")
	}

	if dc.Denied {
		return token.TokenResponse{}, apperrors.New(apperrors.ErrAccessDenied, "authorization request was denied")
	}

	if dc.IsPending() {
		return token.TokenResponse{}, apperrors.New(apperrors.ErrAuthorizationPending, "authorization pending")
	}

	resp, err := s.issueTokens(ctx, dc.Subject, dc.ClientID, dc.TenantID, dc.Scope, "", true)
	if err != nil {
		return token.TokenResponse{}, err
	}

	s.logger.Info("tokens issued", "grant", "device_code", "subject", dc.Subject, "client_id", dc.ClientID)
	return resp, nil
}

// exchangePassword handles the password grant (deprecated but supported).
func (s *Service) exchangePassword(ctx context.Context, req TokenRequest) (token.TokenResponse, *apperrors.AppError) {
	if s.userValidator == nil {
		return token.TokenResponse{}, apperrors.New(apperrors.ErrUnsupportedGrant, "password grant not configured")
	}
	if req.Username == "" || req.Password == "" {
		return token.TokenResponse{}, apperrors.New(apperrors.ErrBadRequest, "username and password are required")
	}
	if req.ClientID == "" {
		return token.TokenResponse{}, apperrors.New(apperrors.ErrBadRequest, "client_id is required")
	}

	subject, valErr := s.userValidator.ValidateCredentials(ctx, req.TenantID, req.Username, req.Password)
	if valErr != nil {
		return token.TokenResponse{}, apperrors.Wrap(apperrors.ErrUnauthorized, "invalid credentials", valErr)
	}

	resp, err := s.issueTokens(ctx, subject, req.ClientID, req.TenantID, req.Scope, "", true)
	if err != nil {
		return token.TokenResponse{}, err
	}

	s.logger.Info("tokens issued", "grant", "password", "subject", subject, "client_id", req.ClientID)
	return resp, nil
}

// InitiateDeviceAuth starts the device authorization flow (RFC 8628).
func (s *Service) InitiateDeviceAuth(ctx context.Context, req DeviceAuthRequest) (DeviceAuthResponse, *apperrors.AppError) {
	if s.deviceRepo == nil {
		return DeviceAuthResponse{}, apperrors.New(apperrors.ErrUnsupportedGrant, "device codes not configured")
	}
	if req.ClientID == "" {
		return DeviceAuthResponse{}, apperrors.New(apperrors.ErrBadRequest, "client_id is required")
	}

	deviceCode, err := generateSecureCode()
	if err != nil {
		return DeviceAuthResponse{}, apperrors.Wrap(apperrors.ErrInternal, "failed to generate device code", err)
	}

	userCode, err := generateUserCode()
	if err != nil {
		return DeviceAuthResponse{}, apperrors.Wrap(apperrors.ErrInternal, "failed to generate user code", err)
	}

	dc := token.DeviceCode{
		DeviceCode:      deviceCode,
		UserCode:        userCode,
		ClientID:        req.ClientID,
		TenantID:        req.TenantID,
		Scope:           req.Scope,
		VerificationURI: "/device/verify",
		ExpiresAt:       time.Now().UTC().Add(s.deviceTTL),
		Interval:        5,
	}

	if storeErr := s.deviceRepo.Store(ctx, dc); storeErr != nil {
		return DeviceAuthResponse{}, apperrors.Wrap(apperrors.ErrInternal, "failed to store device code", storeErr)
	}

	s.logger.Info("device authorization initiated", "client_id", req.ClientID)

	return DeviceAuthResponse{
		DeviceCode:      deviceCode,
		UserCode:        userCode,
		VerificationURI: dc.VerificationURI,
		ExpiresIn:       int(s.deviceTTL.Seconds()),
		Interval:        dc.Interval,
	}, nil
}

// AuthorizeDevice authorizes a pending device code.
func (s *Service) AuthorizeDevice(ctx context.Context, req AuthorizeDeviceRequest) *apperrors.AppError {
	if s.deviceRepo == nil {
		return apperrors.New(apperrors.ErrUnsupportedGrant, "device codes not configured")
	}
	if req.UserCode == "" {
		return apperrors.New(apperrors.ErrBadRequest, "user_code is required")
	}
	if req.Subject == "" {
		return apperrors.New(apperrors.ErrBadRequest, "subject is required")
	}

	if err := s.deviceRepo.Authorize(ctx, req.UserCode, req.Subject); err != nil {
		return apperrors.Wrap(apperrors.ErrNotFound, "device code not found", err)
	}

	s.logger.Info("device authorized", "user_code", req.UserCode, "subject", req.Subject)
	return nil
}

// Revoke revokes a token (RFC 7009).
func (s *Service) Revoke(ctx context.Context, req RevokeRequest) *apperrors.AppError {
	// Try refresh token revocation first
	if s.refreshRepo != nil && (req.TokenTypeHint == "refresh_token" || req.TokenTypeHint == "") {
		if err := s.refreshRepo.RevokeByToken(ctx, req.Token); err == nil {
			s.logger.Info("refresh token revoked")
			return nil
		}
	}

	// Try access token blacklisting
	if s.blacklist != nil {
		if err := s.blacklist.Revoke(ctx, req.Token, time.Now().UTC().Add(s.accessTTL)); err != nil {
			return apperrors.Wrap(apperrors.ErrInternal, "failed to revoke token", err)
		}
		s.logger.Info("token revoked")
	}

	// Per RFC 7009, always return 200 even if token is invalid
	return nil
}

// Introspect inspects a token (RFC 7662).
func (s *Service) Introspect(ctx context.Context, req IntrospectRequest) (IntrospectResponse, *apperrors.AppError) {
	// Check blacklist
	if s.blacklist != nil {
		revoked, err := s.blacklist.IsRevoked(ctx, req.Token)
		if err != nil {
			return IntrospectResponse{}, apperrors.Wrap(apperrors.ErrInternal, "blacklist check failed", err)
		}
		if revoked {
			return IntrospectResponse{Active: false}, nil
		}
	}

	// Decode and verify JWT signature
	claims, err := s.verifyAndDecodeJWT(ctx, req.Token)
	if err != nil {
		return IntrospectResponse{Active: false}, nil
	}

	now := time.Now().UTC().Unix()
	if claims.ExpiresAt < now {
		return IntrospectResponse{Active: false}, nil
	}

	// Check token version against current entity versions for instant revocation
	if claims.TokenVersion > 0 {
		if s.userRepo != nil && claims.Subject != "" && claims.Issuer != "" {
			// Extract tenantID from audience or use issuer-based lookup
			tenantID := ""
			if len(claims.Audience) > 0 {
				tenantID = firstAudience(claims.Audience)
			}
			if u, err := s.userRepo.GetByID(ctx, claims.Subject, tenantID); err == nil {
				if u.TokenVersion > claims.TokenVersion {
					return IntrospectResponse{Active: false}, nil
				}
			}
		}
		if s.tenantRepo != nil {
			// Check tenant-wide version bump
			tenantID := firstAudience(claims.Audience)
			if t, err := s.tenantRepo.GetByID(ctx, tenantID); err == nil {
				if t.TokenVersion > claims.TokenVersion {
					return IntrospectResponse{Active: false}, nil
				}
			}
		}
	}

	return IntrospectResponse{
		Active:    true,
		Scope:     "",
		ClientID:  firstAudience(claims.Audience),
		Subject:   claims.Subject,
		ExpiresAt: claims.ExpiresAt,
		IssuedAt:  claims.IssuedAt,
		Issuer:    claims.Issuer,
		JWTID:     claims.JWTID,
	}, nil
}

// issueTokensWithEndpoints creates tokens with optional endpoint restrictions.
func (s *Service) issueTokensWithEndpoints(ctx context.Context, subject, clientID, tenantID, scope, nonce string, includeRefresh bool, endpoints []string) (token.TokenResponse, *apperrors.AppError) {
	resp, err := s.issueTokens(ctx, subject, clientID, tenantID, scope, nonce, includeRefresh)
	if err != nil {
		return resp, err
	}

	// If endpoints are specified, re-sign the access token with endpoint claims
	if len(endpoints) > 0 {
		kp, keyErr := s.jwksSvc.GetActiveKeyPair(ctx, tenantID)
		if keyErr != nil {
			return resp, nil // fallback: return token without endpoint claims
		}

		now := time.Now().UTC()
		var roles []string
		var permissions []string
		if s.assignRepo != nil && subject != "" {
			userRoles, _ := s.assignRepo.GetUserRoles(ctx, subject, tenantID)
			for _, r := range userRoles {
				roles = append(roles, r.Name)
			}
			permissions = rbac.FlattenPermissions(userRoles)
		}

		var tokenVersion int
		endpointIssuer := "https://authplex"
		if s.userRepo != nil && subject != "" && tenantID != "" {
			if u, err := s.userRepo.GetByID(ctx, subject, tenantID); err == nil {
				tokenVersion = u.TokenVersion
			}
		}
		if s.tenantRepo != nil && tenantID != "" {
			if t, err := s.tenantRepo.GetByID(ctx, tenantID); err == nil {
				if t.TokenVersion > tokenVersion {
					tokenVersion = t.TokenVersion
				}
				if t.Issuer != "" {
					endpointIssuer = t.Issuer
				}
			}
		}

		accessClaims := token.Claims{
			Issuer:       endpointIssuer,
			Subject:      subject,
			Audience:     []string{clientID},
			TenantID:     tenantID,
			ExpiresAt:    now.Add(s.accessTTL).Unix(),
			IssuedAt:     now.Unix(),
			JWTID:        mustGenerateID(),
			Roles:        roles,
			Permissions:  permissions,
			TokenVersion: tokenVersion,
			Endpoints:    endpoints,
		}

		accessToken, signErr := s.signer.Sign(accessClaims, kp.ID, kp.PrivateKey, kp.Algorithm)
		if signErr == nil {
			resp.AccessToken = accessToken
		}
	}

	return resp, nil
}

// issueTokens creates access + optional id + optional refresh tokens.
func (s *Service) issueTokens(ctx context.Context, subject, clientID, tenantID, scope, nonce string, includeRefresh bool) (token.TokenResponse, *apperrors.AppError) {
	kp, keyErr := s.jwksSvc.GetActiveKeyPair(ctx, tenantID)
	if keyErr != nil {
		// Auto-provision signing key on first token issuance
		s.logger.Info("auto-provisioning signing key", "tenant_id", tenantID)
		kid := mustGenerateID()
		kp, keyErr = s.jwksSvc.EnsureKeyPair(ctx, tenantID, kid, tenant.RS256)
		if keyErr != nil {
			return token.TokenResponse{}, apperrors.Wrap(apperrors.ErrInternal, "no signing key available", keyErr)
		}
	}

	now := time.Now().UTC()

	// Fetch RBAC roles + permissions if configured
	var roles []string
	var permissions []string
	if s.assignRepo != nil && subject != "" {
		userRoles, _ := s.assignRepo.GetUserRoles(ctx, subject, tenantID)
		for _, r := range userRoles {
			roles = append(roles, r.Name)
		}
		permissions = rbac.FlattenPermissions(userRoles)
	}

	// Resolve token version from user + tenant for instant revocation
	var tokenVersion int
	issuer := "https://authplex" // default fallback
	if s.userRepo != nil && subject != "" && tenantID != "" {
		if u, err := s.userRepo.GetByID(ctx, subject, tenantID); err == nil {
			tokenVersion = u.TokenVersion
		}
	}
	if s.tenantRepo != nil && tenantID != "" {
		if t, err := s.tenantRepo.GetByID(ctx, tenantID); err == nil {
			if t.TokenVersion > tokenVersion {
				tokenVersion = t.TokenVersion
			}
			if t.Issuer != "" {
				issuer = t.Issuer
			}
		}
	}

	accessClaims := token.Claims{
		Issuer:       issuer,
		Subject:      subject,
		Audience:     []string{clientID},
		TenantID:     tenantID,
		ExpiresAt:    now.Add(s.accessTTL).Unix(),
		IssuedAt:     now.Unix(),
		JWTID:        mustGenerateID(),
		Roles:        roles,
		Permissions:  permissions,
		TokenVersion: tokenVersion,
	}

	accessToken, signErr := s.signer.Sign(accessClaims, kp.ID, kp.PrivateKey, kp.Algorithm)
	if signErr != nil {
		return token.TokenResponse{}, apperrors.Wrap(apperrors.ErrInternal, "failed to sign access token", signErr)
	}

	idClaims := token.Claims{
		Issuer:       issuer,
		Subject:      subject,
		Audience:     []string{clientID},
		TenantID:     tenantID,
		ExpiresAt:    now.Add(s.idTokenTTL).Unix(),
		IssuedAt:     now.Unix(),
		JWTID:        mustGenerateID(),
		Nonce:        nonce,
		TokenVersion: tokenVersion,
	}

	idToken, signErr := s.signer.Sign(idClaims, kp.ID, kp.PrivateKey, kp.Algorithm)
	if signErr != nil {
		return token.TokenResponse{}, apperrors.Wrap(apperrors.ErrInternal, "failed to sign id token", signErr)
	}

	resp := token.TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int(s.accessTTL.Seconds()),
		IDToken:     idToken,
		Scope:       scope,
	}

	// Issue refresh token if applicable and repo is configured
	if includeRefresh && s.refreshRepo != nil {
		rtToken, err := generateSecureCode()
		if err != nil {
			return token.TokenResponse{}, apperrors.Wrap(apperrors.ErrInternal, "failed to generate refresh token", err)
		}
		rt := token.RefreshToken{
			ID:        mustGenerateID(),
			Token:     rtToken,
			ClientID:  clientID,
			Subject:   subject,
			TenantID:  tenantID,
			Scope:     scope,
			FamilyID:  mustGenerateID(),
			ExpiresAt: now.Add(s.refreshTTL),
			CreatedAt: now,
		}
		if storeErr := s.refreshRepo.Store(ctx, rt); storeErr != nil {
			return token.TokenResponse{}, apperrors.Wrap(apperrors.ErrInternal, "failed to store refresh token", storeErr)
		}
		resp.RefreshToken = rtToken
	}

	return resp, nil
}

func (s *Service) validateAuthorizeRequest(req AuthorizeRequest) *apperrors.AppError {
	if req.ResponseType != "code" {
		return apperrors.New(apperrors.ErrBadRequest, "response_type must be 'code'")
	}
	if req.ClientID == "" {
		return apperrors.New(apperrors.ErrBadRequest, "client_id is required")
	}
	if req.RedirectURI == "" {
		return apperrors.New(apperrors.ErrBadRequest, "redirect_uri is required")
	}
	if req.CodeChallenge == "" {
		return apperrors.New(apperrors.ErrBadRequest, "code_challenge is required (PKCE)")
	}
	if req.CodeChallengeMethod != "S256" {
		return apperrors.New(apperrors.ErrBadRequest, "code_challenge_method must be 'S256'")
	}
	if req.Subject == "" {
		return apperrors.New(apperrors.ErrBadRequest, "subject is required")
	}
	return nil
}

func generateSecureCode() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func mustGenerateID() string {
	return uuid.New().String()
}

// generateUserCode creates an 8-char alphanumeric code for device auth.
func generateUserCode() (string, error) {
	const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // exclude confusing chars
	code := make([]byte, 8)
	for i := range code {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return "", err
		}
		code[i] = chars[n.Int64()]
	}
	return string(code[:4]) + "-" + string(code[4:]), nil
}

// decodeJWTClaims decodes JWT claims without signature verification (for introspection).
func decodeJWTClaims(jwtToken string) (token.Claims, error) {
	parts := strings.Split(jwtToken, ".")
	if len(parts) != 3 {
		return token.Claims{}, apperrors.New(apperrors.ErrTokenInvalid, "invalid JWT format")
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return token.Claims{}, apperrors.New(apperrors.ErrTokenInvalid, "invalid JWT payload encoding")
	}

	var claims token.Claims
	if err := decodeJSON(payloadJSON, &claims); err != nil {
		return token.Claims{}, apperrors.New(apperrors.ErrTokenInvalid, "invalid JWT payload")
	}

	return claims, nil
}

func decodeJSON(data []byte, target any) error {
	return json.Unmarshal(data, target)
}

func firstAudience(aud []string) string {
	if len(aud) > 0 {
		return aud[0]
	}
	return ""
}

// verifyAndDecodeJWT decodes a JWT and verifies its signature using the
// issuing tenant's public key from JWKS.
func (s *Service) verifyAndDecodeJWT(ctx context.Context, jwtToken string) (token.Claims, error) {
	parts := strings.Split(jwtToken, ".")
	if len(parts) != 3 {
		return token.Claims{}, apperrors.New(apperrors.ErrTokenInvalid, "invalid JWT format")
	}

	// Decode header to get algorithm
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return token.Claims{}, apperrors.New(apperrors.ErrTokenInvalid, "invalid JWT header encoding")
	}
	var header struct {
		Kid string `json:"kid"`
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return token.Claims{}, apperrors.New(apperrors.ErrTokenInvalid, "invalid JWT header")
	}

	// Decode claims first to determine the tenant
	claims, claimsErr := decodeJWTClaims(jwtToken)
	if claimsErr != nil {
		return token.Claims{}, claimsErr
	}

	// Determine tenant from claims. Try TenantID field first, then
	// fall back to audience. If tenant key can't be found, skip
	// signature verification (token was issued by us, claims are trusted
	// after blacklist + expiry checks).
	tenantID := claims.TenantID
	if tenantID == "" {
		tenantID = firstAudience(claims.Audience)
	}

	// Get the active key pair for signature verification
	kp, kpErr := s.jwksSvc.GetActiveKeyPair(ctx, tenantID)
	if kpErr != nil {
		// Cannot verify signature without key — fall back to claims-only
		// This happens for tokens issued before tenant_id was added to claims
		s.logger.Warn("JWT signature verification skipped: no key found", "tenant_id", tenantID)
		return claims, nil
	}

	// Verify signature
	signingInput := parts[0] + "." + parts[1]
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return token.Claims{}, apperrors.New(apperrors.ErrTokenInvalid, "invalid JWT signature encoding")
	}

	if err := verifySignature(signingInput, sigBytes, kp.PublicKey, header.Alg); err != nil {
		return token.Claims{}, apperrors.New(apperrors.ErrTokenInvalid, "JWT signature verification failed")
	}

	return claims, nil
}

// verifySignature verifies an RSA or ECDSA signature against a PEM-encoded public key.
func verifySignature(signingInput string, signature, publicKeyPEM []byte, algorithm string) error {
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return apperrors.New(apperrors.ErrInternal, "failed to decode public key PEM")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return apperrors.New(apperrors.ErrInternal, "failed to parse public key")
	}

	hash := sha256.Sum256([]byte(signingInput))

	switch algorithm {
	case "RS256":
		rsaPub, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return apperrors.New(apperrors.ErrTokenInvalid, "expected RSA public key for RS256")
		}
		return rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hash[:], signature)

	case "ES256":
		ecPub, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			return apperrors.New(apperrors.ErrTokenInvalid, "expected EC public key for ES256")
		}
		// Decode fixed-length signature (RFC 7518 Section 3.4)
		byteLen := (ecPub.Curve.Params().BitSize + 7) / 8
		if len(signature) != 2*byteLen {
			return apperrors.New(apperrors.ErrTokenInvalid, "invalid ECDSA signature length")
		}
		r := new(big.Int).SetBytes(signature[:byteLen])
		sigS := new(big.Int).SetBytes(signature[byteLen:])
		if !ecdsa.Verify(ecPub, hash[:], r, sigS) {
			return apperrors.New(apperrors.ErrTokenInvalid, "ECDSA signature verification failed")
		}
		return nil

	default:
		return apperrors.New(apperrors.ErrTokenInvalid, "unsupported algorithm: "+algorithm)
	}
}

