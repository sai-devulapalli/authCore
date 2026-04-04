package provider

import "github.com/authplex/internal/domain/identity"

// CreateProviderRequest is the DTO for creating an identity provider.
type CreateProviderRequest struct {
	ProviderType string            `json:"provider_type"`
	ClientID     string            `json:"client_id"`
	ClientSecret string            `json:"client_secret"`
	Scopes       []string          `json:"scopes"`
	DiscoveryURL string            `json:"discovery_url,omitempty"`
	AuthURL      string            `json:"auth_url,omitempty"`
	TokenURL     string            `json:"token_url,omitempty"`
	UserInfoURL  string            `json:"userinfo_url,omitempty"`
	ExtraConfig  map[string]string `json:"extra_config,omitempty"`
	TenantID     string            `json:"-"`
}

// ProviderResponse is the DTO returned to the caller.
type ProviderResponse struct {
	ID           string            `json:"id"`
	ProviderType string            `json:"provider_type"`
	ClientID     string            `json:"client_id"`
	Scopes       []string          `json:"scopes"`
	DiscoveryURL string            `json:"discovery_url,omitempty"`
	AuthURL      string            `json:"auth_url,omitempty"`
	TokenURL     string            `json:"token_url,omitempty"`
	UserInfoURL  string            `json:"userinfo_url,omitempty"`
	Enabled      bool              `json:"enabled"`
	ExtraConfig  map[string]string `json:"extra_config,omitempty"`
}

func toResponse(p identity.IdentityProvider) ProviderResponse {
	return ProviderResponse{
		ID:           p.ID,
		ProviderType: string(p.ProviderType),
		ClientID:     p.ClientID,
		Scopes:       p.Scopes,
		DiscoveryURL: p.DiscoveryURL,
		AuthURL:      p.AuthURL,
		TokenURL:     p.TokenURL,
		UserInfoURL:  p.UserInfoURL,
		Enabled:      p.Enabled,
		ExtraConfig:  p.ExtraConfig,
	}
}
