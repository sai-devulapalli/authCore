package saml

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	crewsaml "github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"

	"github.com/authcore/internal/application/auth"
	"github.com/authcore/internal/domain/identity"
	apperrors "github.com/authcore/pkg/sdk/errors"
)

// Service provides SAML 2.0 Service Provider operations.
type Service struct {
	providerRepo   identity.ProviderRepository
	externalIDRepo identity.ExternalIdentityRepository
	stateRepo      identity.StateRepository
	authSvc        *auth.Service
	issuer         string
	logger         *slog.Logger
}

// NewService creates a new SAML service.
func NewService(
	providerRepo identity.ProviderRepository,
	externalIDRepo identity.ExternalIdentityRepository,
	stateRepo identity.StateRepository,
	authSvc *auth.Service,
	issuer string,
	logger *slog.Logger,
) *Service {
	return &Service{
		providerRepo:   providerRepo,
		externalIDRepo: externalIDRepo,
		stateRepo:      stateRepo,
		authSvc:        authSvc,
		issuer:         issuer,
		logger:         logger,
	}
}

// GetServiceProvider creates a crewjam/saml.ServiceProvider for the given provider config.
func (s *Service) GetServiceProvider(provider identity.IdentityProvider) (*crewsaml.ServiceProvider, error) {
	metadataURL, err := url.Parse(s.issuer + "/saml/metadata?provider=" + provider.ID)
	if err != nil {
		return nil, fmt.Errorf("invalid metadata URL: %w", err)
	}

	acsURL, err := url.Parse(s.issuer + "/saml/acs")
	if err != nil {
		return nil, fmt.Errorf("invalid ACS URL: %w", err)
	}

	var idpMetadata *crewsaml.EntityDescriptor

	// Try metadata_url first, then idp_metadata_xml
	if metaURL, ok := provider.ExtraConfig["metadata_url"]; ok && metaURL != "" {
		fetched, fetchErr := fetchIDPMetadata(metaURL)
		if fetchErr != nil {
			return nil, fmt.Errorf("failed to fetch IdP metadata from %s: %w", metaURL, fetchErr)
		}
		idpMetadata = fetched
	} else if metaXML, ok := provider.ExtraConfig["idp_metadata_xml"]; ok && metaXML != "" {
		parsed, parseErr := samlsp.ParseMetadata([]byte(metaXML))
		if parseErr != nil {
			return nil, fmt.Errorf("failed to parse IdP metadata XML: %w", parseErr)
		}
		idpMetadata = parsed
	} else {
		return nil, fmt.Errorf("provider %s has no IdP metadata configured (set metadata_url or idp_metadata_xml in extra_config)", provider.ID)
	}

	sp := crewsaml.ServiceProvider{
		EntityID:    metadataURL.String(),
		MetadataURL: *metadataURL,
		AcsURL:      *acsURL,
		IDPMetadata: idpMetadata,
	}

	return &sp, nil
}

// GenerateMetadata returns the SP metadata XML for a provider.
func (s *Service) GenerateMetadata(ctx context.Context, tenantID, providerID string) ([]byte, error) {
	provider, err := s.providerRepo.GetByID(ctx, providerID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("provider not found: %w", err)
	}

	sp, spErr := s.GetServiceProvider(provider)
	if spErr != nil {
		return nil, spErr
	}

	metadata := sp.Metadata()
	xmlBytes, marshalErr := xml.MarshalIndent(metadata, "", "  ")
	if marshalErr != nil {
		return nil, fmt.Errorf("failed to marshal metadata: %w", marshalErr)
	}

	return append([]byte(xml.Header), xmlBytes...), nil
}

// InitiateSSO generates the SAML AuthnRequest URL.
func (s *Service) InitiateSSO(ctx context.Context, req SSORequest) (string, *apperrors.AppError) {
	provider, err := s.providerRepo.GetByID(ctx, req.ProviderID, req.TenantID)
	if err != nil {
		return "", apperrors.Wrap(apperrors.ErrNotFound, "SAML provider not found", err)
	}
	if !provider.Enabled {
		return "", apperrors.New(apperrors.ErrBadRequest, "SAML provider is disabled")
	}
	if provider.ProviderType != identity.ProviderSAML {
		return "", apperrors.New(apperrors.ErrBadRequest, "provider is not a SAML provider")
	}

	sp, spErr := s.GetServiceProvider(provider)
	if spErr != nil {
		return "", apperrors.Wrap(apperrors.ErrInternal, "failed to create SAML service provider", spErr)
	}

	// Generate relay state token
	stateToken, genErr := generateSecureToken()
	if genErr != nil {
		return "", apperrors.Wrap(apperrors.ErrInternal, "failed to generate state", genErr)
	}

	// Store state for ACS callback validation
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
		ExpiresAt:           time.Now().UTC().Add(10 * time.Minute),
	}
	if storeErr := s.stateRepo.Store(ctx, oauthState); storeErr != nil {
		return "", apperrors.Wrap(apperrors.ErrInternal, "failed to store state", storeErr)
	}

	// Generate AuthnRequest redirect URL
	authnRequestURL, requestErr := sp.MakeRedirectAuthenticationRequest(stateToken)
	if requestErr != nil {
		return "", apperrors.Wrap(apperrors.ErrInternal, "failed to create SAML AuthnRequest", requestErr)
	}

	s.logger.Info("SAML SSO redirect", "provider_id", provider.ID, "tenant_id", req.TenantID)
	return authnRequestURL.String(), nil
}

// HandleACS processes the SAML assertion response, links identity, and issues an auth code.
func (s *Service) HandleACS(ctx context.Context, httpReq *http.Request, relayState string) (auth.AuthorizeResponse, *apperrors.AppError) {
	// Retrieve state from relay state
	oauthState, stateErr := s.stateRepo.Consume(ctx, relayState)
	if stateErr != nil {
		return auth.AuthorizeResponse{}, apperrors.Wrap(apperrors.ErrBadRequest, "invalid or expired relay state", stateErr)
	}

	// Get provider
	provider, err := s.providerRepo.GetByID(ctx, oauthState.ProviderID, oauthState.TenantID)
	if err != nil {
		return auth.AuthorizeResponse{}, apperrors.Wrap(apperrors.ErrInternal, "SAML provider not found", err)
	}

	sp, spErr := s.GetServiceProvider(provider)
	if spErr != nil {
		return auth.AuthorizeResponse{}, apperrors.Wrap(apperrors.ErrInternal, "failed to create SAML service provider", spErr)
	}

	// Parse SAML response from the HTTP request — pass nil for possibleRequestIDs
	// to skip InResponseTo validation (acceptable for SP-initiated SSO without request tracking)
	assertion, parseErr := sp.ParseResponse(httpReq, nil)
	if parseErr != nil {
		return auth.AuthorizeResponse{}, apperrors.Wrap(apperrors.ErrAccessDenied, "SAML assertion validation failed", parseErr)
	}

	// Extract subject (NameID) from the assertion
	subject := ""
	if assertion.Subject != nil && assertion.Subject.NameID != nil {
		subject = assertion.Subject.NameID.Value
	}
	if subject == "" {
		return auth.AuthorizeResponse{}, apperrors.New(apperrors.ErrInternal, "SAML assertion missing NameID")
	}

	// Extract attributes (email, name) from the assertion
	email := ""
	name := ""
	for _, stmt := range assertion.AttributeStatements {
		for _, attr := range stmt.Attributes {
			val := firstAttributeValue(attr)
			switch attr.Name {
			case "email", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
				"urn:oid:0.9.2342.19200300.100.1.3":
				email = val
			case "name", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
				"displayName", "urn:oid:2.16.840.1.113730.3.1.241":
				name = val
			}
		}
	}

	// Build user info for identity linking
	userInfo := identity.UserInfo{
		Subject: subject,
		Email:   email,
		Name:    name,
	}

	// Link or create external identity (same pattern as social login)
	internalSubject, linkErr := s.linkIdentity(ctx, provider.ID, oauthState.TenantID, userInfo)
	if linkErr != nil {
		return auth.AuthorizeResponse{}, linkErr
	}

	// Issue AuthCore authorization code
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
	}

	resp, authErr := s.authSvc.Authorize(ctx, authReq)
	if authErr != nil {
		return auth.AuthorizeResponse{}, authErr
	}

	s.logger.Info("SAML SSO completed", "provider_id", provider.ID, "internal_subject", internalSubject)
	return resp, nil
}

// linkIdentity links an external SAML identity to an internal subject.
func (s *Service) linkIdentity(ctx context.Context, providerID, tenantID string, userInfo identity.UserInfo) (string, *apperrors.AppError) {
	// Check for existing link
	existing, err := s.externalIDRepo.GetByExternalSubject(ctx, providerID, userInfo.Subject)
	if err == nil {
		// Update profile
		existing.Email = userInfo.Email
		existing.Name = userInfo.Name
		existing.UpdatedAt = time.Now().UTC()
		s.externalIDRepo.Update(ctx, existing) //nolint:errcheck
		return existing.InternalSubject, nil
	}

	// Create new link
	internalSubject, genErr := generateSecureToken()
	if genErr != nil {
		return "", apperrors.Wrap(apperrors.ErrInternal, "failed to generate subject", genErr)
	}

	id, idErr := generateSecureToken()
	if idErr != nil {
		return "", apperrors.Wrap(apperrors.ErrInternal, "failed to generate identity ID", idErr)
	}

	ei, valErr := identity.NewExternalIdentity(id, providerID, userInfo.Subject, internalSubject, tenantID)
	if valErr != nil {
		return "", apperrors.Wrap(apperrors.ErrInternal, "failed to create external identity", valErr)
	}
	ei.Email = userInfo.Email
	ei.Name = userInfo.Name

	if createErr := s.externalIDRepo.Create(ctx, ei); createErr != nil {
		return "", apperrors.Wrap(apperrors.ErrInternal, "failed to store external identity", createErr)
	}

	return internalSubject, nil
}

// firstAttributeValue returns the first value from a SAML attribute, or empty string.
func firstAttributeValue(attr crewsaml.Attribute) string {
	if len(attr.Values) > 0 {
		return attr.Values[0].Value
	}
	return ""
}

// fetchIDPMetadata downloads and parses IdP metadata from a URL.
func fetchIDPMetadata(metadataURL string) (*crewsaml.EntityDescriptor, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(metadataURL) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from metadata URL", resp.StatusCode)
	}

	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return nil, fmt.Errorf("failed to read response body: %w", readErr)
	}

	metadata, parseErr := samlsp.ParseMetadata(body)
	if parseErr != nil {
		return nil, fmt.Errorf("failed to parse metadata XML: %w", parseErr)
	}

	return metadata, nil
}

func generateSecureToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
