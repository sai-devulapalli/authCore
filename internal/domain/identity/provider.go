package identity

import "time"

// ProviderType represents the type of external identity provider.
type ProviderType string

const (
	ProviderGoogle    ProviderType = "google"
	ProviderGitHub    ProviderType = "github"
	ProviderMicrosoft ProviderType = "microsoft"
	ProviderApple     ProviderType = "apple"
	ProviderOIDC      ProviderType = "oidc"
	ProviderOAuth2    ProviderType = "oauth2"
	ProviderSAML      ProviderType = "saml"
)

// IdentityProvider represents an external OAuth/OIDC identity provider.
type IdentityProvider struct {
	ID           string
	TenantID     string
	ProviderType ProviderType
	ClientID     string
	ClientSecret []byte
	Scopes       []string
	DiscoveryURL string
	AuthURL      string
	TokenURL     string
	UserInfoURL  string
	Enabled      bool
	ExtraConfig  map[string]string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// NewIdentityProvider creates a validated IdentityProvider.
func NewIdentityProvider(id, tenantID string, providerType ProviderType, clientID string, clientSecret []byte, scopes []string) (IdentityProvider, error) {
	if id == "" {
		return IdentityProvider{}, &ValidationError{Field: "id", Message: "must not be empty"}
	}
	if tenantID == "" {
		return IdentityProvider{}, &ValidationError{Field: "tenant_id", Message: "must not be empty"}
	}
	if !isValidProviderType(providerType) {
		return IdentityProvider{}, &ValidationError{Field: "provider_type", Message: "must be google, github, microsoft, apple, oidc, oauth2, or saml"}
	}
	if clientID == "" {
		return IdentityProvider{}, &ValidationError{Field: "client_id", Message: "must not be empty"}
	}

	now := time.Now().UTC()
	return IdentityProvider{
		ID:           id,
		TenantID:     tenantID,
		ProviderType: providerType,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       scopes,
		Enabled:      true,
		ExtraConfig:  make(map[string]string),
		CreatedAt:    now,
		UpdatedAt:    now,
	}, nil
}

func isValidProviderType(pt ProviderType) bool {
	switch pt {
	case ProviderGoogle, ProviderGitHub, ProviderMicrosoft, ProviderApple, ProviderOIDC, ProviderOAuth2, ProviderSAML:
		return true
	default:
		return false
	}
}
