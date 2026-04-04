package social

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/authplex/internal/adapter/http/oauth"
	"github.com/authplex/internal/application/auth"
	"github.com/authplex/internal/domain/identity"
	apperrors "github.com/authplex/pkg/sdk/errors"
)

// Service provides social login operations.
type Service struct {
	providerRepo identity.ProviderRepository
	identityRepo identity.ExternalIdentityRepository
	stateRepo    identity.StateRepository
	oauthClient  identity.OAuthClient
	authSvc      *auth.Service
	logger       *slog.Logger
	callbackURL  string
}

// NewService creates a new social login service.
func NewService(
	providerRepo identity.ProviderRepository,
	identityRepo identity.ExternalIdentityRepository,
	stateRepo identity.StateRepository,
	oauthClient identity.OAuthClient,
	authSvc *auth.Service,
	callbackURL string,
	logger *slog.Logger,
) *Service {
	return &Service{
		providerRepo: providerRepo,
		identityRepo: identityRepo,
		stateRepo:    stateRepo,
		oauthClient:  oauthClient,
		authSvc:      authSvc,
		callbackURL:  callbackURL,
		logger:       logger,
	}
}

// AuthorizeRedirect builds the redirect URL for the external provider.
func (s *Service) AuthorizeRedirect(ctx context.Context, req SocialAuthorizeRequest) (string, *apperrors.AppError) {
	provider, err := s.providerRepo.GetByType(ctx, req.TenantID, identity.ProviderType(req.Provider))
	if err != nil {
		return "", apperrors.Wrap(apperrors.ErrNotFound, "provider not found", err)
	}
	if !provider.Enabled {
		return "", apperrors.New(apperrors.ErrBadRequest, "provider is disabled")
	}

	// Resolve auth URL (from provider config or known defaults)
	authURL := oauth.ResolveAuthURL(provider)
	if authURL == "" && provider.DiscoveryURL != "" {
		// Fetch from OIDC discovery
		config, err := s.oauthClient.FetchOIDCDiscovery(ctx, provider.DiscoveryURL)
		if err != nil {
			return "", apperrors.Wrap(apperrors.ErrInternal, "failed to fetch OIDC discovery", err)
		}
		authURL = config.AuthorizationEndpoint
	}
	if authURL == "" {
		return "", apperrors.New(apperrors.ErrInternal, "no authorization URL configured for provider")
	}

	// Generate CSRF state
	stateToken, genErr := generateSecureToken()
	if genErr != nil {
		return "", apperrors.Wrap(apperrors.ErrInternal, "failed to generate state", genErr)
	}

	// Store state for callback validation
	oauthState := identity.OAuthState{
		State:               stateToken,
		TenantID:            req.TenantID,
		ProviderID:          provider.ID,
		OriginalClientID:    req.ClientID,
		OriginalRedirectURI: req.RedirectURI,
		OriginalScope:       req.Scope,
		OriginalState:       req.State,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		Nonce:               req.Nonce,
		Subject:             req.Subject,
		ExpiresAt:           time.Now().UTC().Add(10 * time.Minute),
	}
	if storeErr := s.stateRepo.Store(ctx, oauthState); storeErr != nil {
		return "", apperrors.Wrap(apperrors.ErrInternal, "failed to store state", storeErr)
	}

	// Build provider authorization URL
	scopes := oauth.ResolveScopes(provider)
	redirectURL, _ := url.Parse(authURL)
	q := redirectURL.Query()
	q.Set("client_id", provider.ClientID)
	q.Set("redirect_uri", s.callbackURL)
	q.Set("response_type", "code")
	q.Set("scope", strings.Join(scopes, " "))
	q.Set("state", stateToken)
	redirectURL.RawQuery = q.Encode()

	s.logger.Info("social login redirect", "provider", req.Provider, "tenant_id", req.TenantID)
	return redirectURL.String(), nil
}

// HandleCallback processes the callback from the external provider.
func (s *Service) HandleCallback(ctx context.Context, req CallbackRequest) (auth.AuthorizeResponse, *apperrors.AppError) {
	if req.Error != "" {
		return auth.AuthorizeResponse{}, apperrors.New(apperrors.ErrAccessDenied, "provider error: "+req.Error)
	}

	// Validate CSRF state
	oauthState, stateErr := s.stateRepo.Consume(ctx, req.State)
	if stateErr != nil {
		return auth.AuthorizeResponse{}, apperrors.Wrap(apperrors.ErrBadRequest, "invalid or expired state", stateErr)
	}

	// Get provider
	provider, err := s.providerRepo.GetByID(ctx, oauthState.ProviderID, oauthState.TenantID)
	if err != nil {
		return auth.AuthorizeResponse{}, apperrors.Wrap(apperrors.ErrInternal, "provider not found", err)
	}

	// Resolve token URL
	tokenURL := oauth.ResolveTokenURL(provider)
	if tokenURL == "" && provider.DiscoveryURL != "" {
		config, err := s.oauthClient.FetchOIDCDiscovery(ctx, provider.DiscoveryURL)
		if err != nil {
			return auth.AuthorizeResponse{}, apperrors.Wrap(apperrors.ErrInternal, "failed to fetch OIDC discovery", err)
		}
		tokenURL = config.TokenEndpoint
	}

	// Exchange code for tokens (with provider-specific config for Apple JWT etc.)
	tokenResp, exchangeErr := s.oauthClient.ExchangeCodeWithConfig(ctx, tokenURL, req.Code, s.callbackURL,
		provider.ClientID, string(provider.ClientSecret), provider.ExtraConfig)
	if exchangeErr != nil {
		return auth.AuthorizeResponse{}, apperrors.Wrap(apperrors.ErrInternal, "token exchange with provider failed", exchangeErr)
	}

	// Get user info
	userInfoURL := oauth.ResolveUserInfoURL(provider)
	var userInfo identity.UserInfo

	if userInfoURL != "" && tokenResp.AccessToken != "" {
		info, err := s.oauthClient.FetchUserInfo(ctx, userInfoURL, tokenResp.AccessToken)
		if err != nil {
			s.logger.Warn("failed to fetch user info", "error", err)
		} else {
			userInfo = info
		}
	}

	// Decode id_token for OIDC providers when userinfo didn't yield a subject
	if userInfo.Subject == "" && tokenResp.IDToken != "" {
		if provider.DiscoveryURL != "" {
			config, err := s.oauthClient.FetchOIDCDiscovery(ctx, provider.DiscoveryURL)
			if err == nil && config.JWKSURI != "" {
				idInfo, decErr := s.oauthClient.DecodeIDToken(ctx, tokenResp.IDToken, config.JWKSURI)
				if decErr != nil {
					s.logger.Warn("failed to decode id_token", "error", decErr)
				} else {
					userInfo = idInfo
				}
			}
		}
	}

	if userInfo.Subject == "" {
		return auth.AuthorizeResponse{}, apperrors.New(apperrors.ErrInternal, "could not determine user identity from provider")
	}

	// Link or create external identity
	internalSubject, linkErr := s.linkIdentity(ctx, provider.ID, oauthState.TenantID, userInfo, oauthState.Subject)
	if linkErr != nil {
		return auth.AuthorizeResponse{}, linkErr
	}

	// Issue AuthPlex authorization code
	authReq := auth.AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            oauthState.OriginalClientID,
		RedirectURI:         oauthState.OriginalRedirectURI,
		Scope:               oauthState.OriginalScope,
		State:               oauthState.OriginalState,
		CodeChallenge:       oauthState.CodeChallenge,
		CodeChallengeMethod: oauthState.CodeChallengeMethod,
		Subject:             internalSubject,
		TenantID:            oauthState.TenantID,
		Nonce:               oauthState.Nonce,
	}

	resp, authErr := s.authSvc.Authorize(ctx, authReq)
	if authErr != nil {
		return auth.AuthorizeResponse{}, authErr
	}

	s.logger.Info("social login completed", "provider_id", provider.ID, "internal_subject", internalSubject)
	return resp, nil
}

// linkIdentity links an external identity to an internal subject.
func (s *Service) linkIdentity(ctx context.Context, providerID, tenantID string, userInfo identity.UserInfo, explicitSubject string) (string, *apperrors.AppError) {
	// Check for existing link
	existing, err := s.identityRepo.GetByExternalSubject(ctx, providerID, userInfo.Subject)
	if err == nil {
		// Update profile
		existing.Email = userInfo.Email
		existing.Name = userInfo.Name
		existing.ProfileData = userInfo.RawClaims
		existing.UpdatedAt = time.Now().UTC()
		s.identityRepo.Update(ctx, existing) //nolint:errcheck
		return existing.InternalSubject, nil
	}

	// Create new link
	internalSubject := explicitSubject
	if internalSubject == "" {
		generated, err := generateSecureToken()
		if err != nil {
			return "", apperrors.Wrap(apperrors.ErrInternal, "failed to generate subject", err)
		}
		internalSubject = generated
	}

	id, err := generateSecureToken()
	if err != nil {
		return "", apperrors.Wrap(apperrors.ErrInternal, "failed to generate identity ID", err)
	}

	ei, valErr := identity.NewExternalIdentity(id, providerID, userInfo.Subject, internalSubject, tenantID)
	if valErr != nil {
		return "", apperrors.Wrap(apperrors.ErrInternal, "failed to create external identity", valErr)
	}
	ei.Email = userInfo.Email
	ei.Name = userInfo.Name
	ei.ProfileData = userInfo.RawClaims

	if createErr := s.identityRepo.Create(ctx, ei); createErr != nil {
		return "", apperrors.Wrap(apperrors.ErrInternal, "failed to store external identity", createErr)
	}

	return internalSubject, nil
}

func generateSecureToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
