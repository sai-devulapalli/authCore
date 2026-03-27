package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"math/big"
	"strings"
	"time"

	"github.com/authcore/internal/application/jwks"
	"github.com/authcore/internal/domain/tenant"
	"github.com/authcore/internal/domain/token"
	apperrors "github.com/authcore/pkg/sdk/errors"
)

// Service provides OAuth 2.0 token operations for all grant types.
type Service struct {
	codeRepo      token.CodeRepository
	refreshRepo   token.RefreshTokenRepository
	deviceRepo    token.DeviceCodeRepository
	blacklist     token.TokenBlacklist
	userValidator token.UserValidator
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

	// For client_credentials, the subject is the client itself
	resp, err := s.issueTokens(ctx, req.ClientID, req.ClientID, tenantID, scope, "", false)
	if err != nil {
		return token.TokenResponse{}, err
	}

	// Client credentials does not issue refresh tokens or id tokens
	resp.RefreshToken = ""
	resp.IDToken = ""

	s.logger.Info("tokens issued", "grant", "client_credentials", "client_id", req.ClientID)
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

	// Try to decode as JWT
	claims, err := decodeJWTClaims(req.Token)
	if err != nil {
		return IntrospectResponse{Active: false}, nil
	}

	now := time.Now().UTC().Unix()
	if claims.ExpiresAt < now {
		return IntrospectResponse{Active: false}, nil
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

	accessClaims := token.Claims{
		Issuer:    "https://authcore",
		Subject:   subject,
		Audience:  []string{clientID},
		ExpiresAt: now.Add(s.accessTTL).Unix(),
		IssuedAt:  now.Unix(),
		JWTID:     mustGenerateID(),
	}

	accessToken, signErr := s.signer.Sign(accessClaims, kp.ID, kp.PrivateKey, kp.Algorithm)
	if signErr != nil {
		return token.TokenResponse{}, apperrors.Wrap(apperrors.ErrInternal, "failed to sign access token", signErr)
	}

	idClaims := token.Claims{
		Issuer:    "https://authcore",
		Subject:   subject,
		Audience:  []string{clientID},
		ExpiresAt: now.Add(s.idTokenTTL).Unix(),
		IssuedAt:  now.Unix(),
		JWTID:     mustGenerateID(),
		Nonce:     nonce,
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
	b := make([]byte, 16)
	rand.Read(b) //nolint:errcheck
	return base64.RawURLEncoding.EncodeToString(b)
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
