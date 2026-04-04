package oauth

import "github.com/authplex/internal/domain/identity"

// ProviderDefaults contains default configuration for well-known providers.
type ProviderDefaults struct {
	DiscoveryURL  string
	AuthURL       string
	TokenURL      string
	UserInfoURL   string
	DefaultScopes []string
}

// KnownProviders contains configuration defaults for well-known identity providers.
var KnownProviders = map[identity.ProviderType]ProviderDefaults{
	identity.ProviderGoogle: {
		DiscoveryURL:  "https://accounts.google.com/.well-known/openid-configuration",
		DefaultScopes: []string{"openid", "email", "profile"},
	},
	identity.ProviderGitHub: {
		AuthURL:       "https://github.com/login/oauth/authorize",
		TokenURL:      "https://github.com/login/oauth/access_token",
		UserInfoURL:   "https://api.github.com/user",
		DefaultScopes: []string{"read:user", "user:email"},
	},
	identity.ProviderMicrosoft: {
		DiscoveryURL:  "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration",
		DefaultScopes: []string{"openid", "email", "profile"},
	},
	identity.ProviderApple: {
		AuthURL:       "https://appleid.apple.com/auth/authorize",
		TokenURL:      "https://appleid.apple.com/auth/token",
		DefaultScopes: []string{"openid", "email", "name"},
	},
}

// GetProviderDefaults returns the default configuration for a provider type.
// Returns empty defaults for unknown/generic providers.
func GetProviderDefaults(providerType identity.ProviderType) ProviderDefaults {
	if defaults, ok := KnownProviders[providerType]; ok {
		return defaults
	}
	return ProviderDefaults{}
}

// ResolveAuthURL returns the authorization URL for a provider, using discovery if needed.
func ResolveAuthURL(provider identity.IdentityProvider) string {
	if provider.AuthURL != "" {
		return provider.AuthURL
	}
	defaults := GetProviderDefaults(provider.ProviderType)
	return defaults.AuthURL
}

// ResolveTokenURL returns the token URL for a provider, using defaults if not set.
func ResolveTokenURL(provider identity.IdentityProvider) string {
	if provider.TokenURL != "" {
		return provider.TokenURL
	}
	defaults := GetProviderDefaults(provider.ProviderType)
	return defaults.TokenURL
}

// ResolveUserInfoURL returns the userinfo URL for a provider.
func ResolveUserInfoURL(provider identity.IdentityProvider) string {
	if provider.UserInfoURL != "" {
		return provider.UserInfoURL
	}
	defaults := GetProviderDefaults(provider.ProviderType)
	return defaults.UserInfoURL
}

// ResolveScopes returns the scopes for a provider, using defaults if none configured.
func ResolveScopes(provider identity.IdentityProvider) []string {
	if len(provider.Scopes) > 0 {
		return provider.Scopes
	}
	defaults := GetProviderDefaults(provider.ProviderType)
	return defaults.DefaultScopes
}
