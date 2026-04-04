package oauth

import (
	"testing"

	"github.com/authplex/internal/domain/identity"
	"github.com/stretchr/testify/assert"
)

func TestGetProviderDefaults_Google(t *testing.T) {
	d := GetProviderDefaults(identity.ProviderGoogle)
	assert.NotEmpty(t, d.DiscoveryURL)
	assert.Contains(t, d.DefaultScopes, "openid")
}

func TestGetProviderDefaults_GitHub(t *testing.T) {
	d := GetProviderDefaults(identity.ProviderGitHub)
	assert.NotEmpty(t, d.AuthURL)
	assert.NotEmpty(t, d.TokenURL)
	assert.NotEmpty(t, d.UserInfoURL)
}

func TestGetProviderDefaults_Unknown(t *testing.T) {
	d := GetProviderDefaults(identity.ProviderType("unknown"))
	assert.Empty(t, d.DiscoveryURL)
	assert.Empty(t, d.AuthURL)
}

func TestResolveAuthURL_CustomOverride(t *testing.T) {
	p := identity.IdentityProvider{AuthURL: "https://custom.com/auth"}
	assert.Equal(t, "https://custom.com/auth", ResolveAuthURL(p))
}

func TestResolveAuthURL_FromDefaults(t *testing.T) {
	p := identity.IdentityProvider{ProviderType: identity.ProviderGitHub}
	assert.Equal(t, "https://github.com/login/oauth/authorize", ResolveAuthURL(p))
}

func TestResolveTokenURL_CustomOverride(t *testing.T) {
	p := identity.IdentityProvider{TokenURL: "https://custom.com/token"}
	assert.Equal(t, "https://custom.com/token", ResolveTokenURL(p))
}

func TestResolveScopes_Custom(t *testing.T) {
	p := identity.IdentityProvider{Scopes: []string{"custom"}}
	assert.Equal(t, []string{"custom"}, ResolveScopes(p))
}

func TestResolveScopes_Default(t *testing.T) {
	p := identity.IdentityProvider{ProviderType: identity.ProviderGoogle}
	scopes := ResolveScopes(p)
	assert.Contains(t, scopes, "openid")
}

func TestResolveTokenURL_FromDefaults(t *testing.T) {
	p := identity.IdentityProvider{ProviderType: identity.ProviderGitHub}
	assert.Contains(t, ResolveTokenURL(p), "github.com")
}

func TestResolveUserInfoURL_Custom(t *testing.T) {
	p := identity.IdentityProvider{UserInfoURL: "https://custom.com/userinfo"}
	assert.Equal(t, "https://custom.com/userinfo", ResolveUserInfoURL(p))
}

func TestResolveUserInfoURL_FromDefaults(t *testing.T) {
	p := identity.IdentityProvider{ProviderType: identity.ProviderGitHub}
	assert.Contains(t, ResolveUserInfoURL(p), "github.com")
}
