package social

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/authplex/internal/application/auth"
	"github.com/authplex/internal/application/jwks"
	"github.com/authplex/internal/domain/identity"
	"github.com/authplex/internal/domain/jwk"
	"github.com/authplex/internal/domain/token"
	apperrors "github.com/authplex/pkg/sdk/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Mocks ---

type mockProviderRepo struct {
	getByTypeFunc func(ctx context.Context, tenantID string, pt identity.ProviderType) (identity.IdentityProvider, error)
	getByIDFunc   func(ctx context.Context, id, tenantID string) (identity.IdentityProvider, error)
}

func (m *mockProviderRepo) Create(_ context.Context, _ identity.IdentityProvider) error { return nil }
func (m *mockProviderRepo) GetByID(ctx context.Context, id, tenantID string) (identity.IdentityProvider, error) {
	if m.getByIDFunc != nil {
		return m.getByIDFunc(ctx, id, tenantID)
	}
	return identity.IdentityProvider{}, errors.New("not found")
}
func (m *mockProviderRepo) GetByType(ctx context.Context, tenantID string, pt identity.ProviderType) (identity.IdentityProvider, error) {
	if m.getByTypeFunc != nil {
		return m.getByTypeFunc(ctx, tenantID, pt)
	}
	return identity.IdentityProvider{}, errors.New("not found")
}
func (m *mockProviderRepo) List(_ context.Context, _ string) ([]identity.IdentityProvider, error) {
	return nil, nil
}
func (m *mockProviderRepo) Update(_ context.Context, _ identity.IdentityProvider) error { return nil }
func (m *mockProviderRepo) Delete(_ context.Context, _, _ string) error                 { return nil }

type mockIdentityRepo struct {
	getByExternalFunc func(ctx context.Context, providerID, extSub string) (identity.ExternalIdentity, error)
	createFunc        func(ctx context.Context, ei identity.ExternalIdentity) error
}

func (m *mockIdentityRepo) Create(ctx context.Context, ei identity.ExternalIdentity) error {
	if m.createFunc != nil {
		return m.createFunc(ctx, ei)
	}
	return nil
}
func (m *mockIdentityRepo) GetByExternalSubject(ctx context.Context, providerID, extSub string) (identity.ExternalIdentity, error) {
	if m.getByExternalFunc != nil {
		return m.getByExternalFunc(ctx, providerID, extSub)
	}
	return identity.ExternalIdentity{}, errors.New("not found")
}
func (m *mockIdentityRepo) GetByInternalSubject(_ context.Context, _, _ string) ([]identity.ExternalIdentity, error) {
	return nil, nil
}
func (m *mockIdentityRepo) Update(_ context.Context, _ identity.ExternalIdentity) error { return nil }

type mockStateRepo struct {
	storeFunc   func(ctx context.Context, s identity.OAuthState) error
	consumeFunc func(ctx context.Context, state string) (identity.OAuthState, error)
}

func (m *mockStateRepo) Store(ctx context.Context, s identity.OAuthState) error {
	if m.storeFunc != nil {
		return m.storeFunc(ctx, s)
	}
	return nil
}
func (m *mockStateRepo) Consume(ctx context.Context, state string) (identity.OAuthState, error) {
	if m.consumeFunc != nil {
		return m.consumeFunc(ctx, state)
	}
	return identity.OAuthState{}, errors.New("not found")
}

type mockOAuthClient struct {
	exchangeFunc  func(ctx context.Context, tokenURL, code, redirectURI, clientID, clientSecret string) (identity.OAuthTokenResponse, error)
	userInfoFunc  func(ctx context.Context, userInfoURL, accessToken string) (identity.UserInfo, error)
	discoveryFunc func(ctx context.Context, discoveryURL string) (identity.OIDCConfig, error)
}

func (m *mockOAuthClient) ExchangeCode(ctx context.Context, tokenURL, code, redirectURI, clientID, clientSecret string) (identity.OAuthTokenResponse, error) {
	if m.exchangeFunc != nil {
		return m.exchangeFunc(ctx, tokenURL, code, redirectURI, clientID, clientSecret)
	}
	return identity.OAuthTokenResponse{AccessToken: "at-123"}, nil
}
func (m *mockOAuthClient) FetchUserInfo(ctx context.Context, userInfoURL, accessToken string) (identity.UserInfo, error) {
	if m.userInfoFunc != nil {
		return m.userInfoFunc(ctx, userInfoURL, accessToken)
	}
	return identity.UserInfo{Subject: "ext-user-1", Email: "user@example.com"}, nil
}
func (m *mockOAuthClient) FetchOIDCDiscovery(ctx context.Context, discoveryURL string) (identity.OIDCConfig, error) {
	if m.discoveryFunc != nil {
		return m.discoveryFunc(ctx, discoveryURL)
	}
	return identity.OIDCConfig{
		AuthorizationEndpoint: "https://provider.com/auth",
		TokenEndpoint:         "https://provider.com/token",
		UserinfoEndpoint:      "https://provider.com/userinfo",
	}, nil
}
func (m *mockOAuthClient) ExchangeCodeWithConfig(ctx context.Context, tokenURL, code, redirectURI, clientID, clientSecret string, _ map[string]string) (identity.OAuthTokenResponse, error) {
	return m.ExchangeCode(ctx, tokenURL, code, redirectURI, clientID, clientSecret)
}
func (m *mockOAuthClient) DecodeIDToken(_ context.Context, _ string, _ string) (identity.UserInfo, error) {
	return identity.UserInfo{Subject: "id-token-user", Email: "idtoken@example.com"}, nil
}

type mockJWKRepo struct{}

func (m *mockJWKRepo) Store(_ context.Context, _ jwk.KeyPair) error { return nil }
func (m *mockJWKRepo) GetActive(_ context.Context, _ string) (jwk.KeyPair, error) {
	return jwk.KeyPair{ID: "kid", Algorithm: "RS256", PrivateKey: []byte("key")}, nil
}
func (m *mockJWKRepo) GetAllPublic(_ context.Context, _ string) ([]jwk.KeyPair, error) {
	return nil, nil
}
func (m *mockJWKRepo) Deactivate(_ context.Context, _ string) error { return nil }
func (m *mockJWKRepo) GetAllActiveTenantIDs(_ context.Context) ([]string, error) { return nil, nil }
func (m *mockJWKRepo) DeleteInactive(_ context.Context, _ time.Time) (int64, error) { return 0, nil }

type mockGen struct{}

func (m *mockGen) GenerateRSA() ([]byte, []byte, error) { return nil, nil, nil }
func (m *mockGen) GenerateEC() ([]byte, []byte, error)  { return nil, nil, nil }

type mockConv struct{}

func (m *mockConv) PEMToPublicJWK(_ []byte, _ string, _ string) (jwk.PublicJWK, error) {
	return jwk.PublicJWK{}, nil
}

type mockCodeRepo struct{}

func (m *mockCodeRepo) Store(_ context.Context, _ token.AuthorizationCode) error { return nil }
func (m *mockCodeRepo) Consume(_ context.Context, _ string) (token.AuthorizationCode, error) {
	return token.AuthorizationCode{}, errors.New("not found")
}

type mockSigner struct{}

func (m *mockSigner) Sign(_ token.Claims, _ string, _ []byte, _ string) (string, error) {
	return "mock-jwt", nil
}

func newTestAuthSvc() *auth.Service {
	jwksSvc := jwks.NewService(&mockJWKRepo{}, &mockGen{}, &mockConv{}, slog.Default())
	return auth.NewService(&mockCodeRepo{}, jwksSvc, &mockSigner{}, slog.Default())
}

// --- Tests ---

func TestAuthorizeRedirect_Success(t *testing.T) {
	providerRepo := &mockProviderRepo{
		getByTypeFunc: func(_ context.Context, _ string, _ identity.ProviderType) (identity.IdentityProvider, error) {
			return identity.IdentityProvider{
				ID:           "p1",
				ProviderType: identity.ProviderGitHub,
				ClientID:     "gh-client",
				AuthURL:      "https://github.com/login/oauth/authorize",
				Scopes:       []string{"read:user"},
				Enabled:      true,
			}, nil
		},
	}

	svc := NewService(providerRepo, &mockIdentityRepo{}, &mockStateRepo{}, &mockOAuthClient{},
		newTestAuthSvc(), "https://authplex.com/callback", slog.Default())

	url, appErr := svc.AuthorizeRedirect(context.Background(), SocialAuthorizeRequest{
		Provider: "github",
		TenantID: "t1",
		ClientID: "my-app",
		State:    "original-state",
	})

	require.Nil(t, appErr)
	assert.Contains(t, url, "https://github.com/login/oauth/authorize")
	assert.Contains(t, url, "client_id=gh-client")
	assert.Contains(t, url, "redirect_uri=")
}

func TestAuthorizeRedirect_ProviderNotFound(t *testing.T) {
	svc := NewService(&mockProviderRepo{}, &mockIdentityRepo{}, &mockStateRepo{}, &mockOAuthClient{},
		newTestAuthSvc(), "https://authplex.com/callback", slog.Default())

	_, appErr := svc.AuthorizeRedirect(context.Background(), SocialAuthorizeRequest{
		Provider: "google",
		TenantID: "t1",
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrNotFound, appErr.Code)
}

func TestAuthorizeRedirect_ProviderDisabled(t *testing.T) {
	providerRepo := &mockProviderRepo{
		getByTypeFunc: func(_ context.Context, _ string, _ identity.ProviderType) (identity.IdentityProvider, error) {
			return identity.IdentityProvider{Enabled: false}, nil
		},
	}
	svc := NewService(providerRepo, &mockIdentityRepo{}, &mockStateRepo{}, &mockOAuthClient{},
		newTestAuthSvc(), "https://authplex.com/callback", slog.Default())

	_, appErr := svc.AuthorizeRedirect(context.Background(), SocialAuthorizeRequest{
		Provider: "google", TenantID: "t1",
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrBadRequest, appErr.Code)
}

func TestHandleCallback_Success_NewIdentity(t *testing.T) {
	providerRepo := &mockProviderRepo{
		getByIDFunc: func(_ context.Context, _, _ string) (identity.IdentityProvider, error) {
			return identity.IdentityProvider{
				ID:           "p1",
				ClientID:     "gh-client",
				ClientSecret: []byte("secret"),
				TokenURL:     "https://github.com/token",
				UserInfoURL:  "https://api.github.com/user",
			}, nil
		},
	}

	stateRepo := &mockStateRepo{
		consumeFunc: func(_ context.Context, _ string) (identity.OAuthState, error) {
			return identity.OAuthState{
				ProviderID:          "p1",
				TenantID:            "t1",
				OriginalClientID:    "my-app",
				OriginalRedirectURI: "https://myapp.com/cb",
				OriginalScope:       "openid",
				CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
				CodeChallengeMethod: "S256",
				ExpiresAt:           time.Now().UTC().Add(10 * time.Minute),
			}, nil
		},
	}

	svc := NewService(providerRepo, &mockIdentityRepo{}, stateRepo, &mockOAuthClient{},
		newTestAuthSvc(), "https://authplex.com/callback", slog.Default())

	resp, appErr := svc.HandleCallback(context.Background(), CallbackRequest{
		Code:  "provider-code",
		State: "state-123",
	})

	require.Nil(t, appErr)
	assert.NotEmpty(t, resp.Code)
	assert.Equal(t, "https://myapp.com/cb", resp.RedirectURI)
}

func TestHandleCallback_ExistingIdentity(t *testing.T) {
	providerRepo := &mockProviderRepo{
		getByIDFunc: func(_ context.Context, _, _ string) (identity.IdentityProvider, error) {
			return identity.IdentityProvider{
				ID: "p1", ClientID: "cid", TokenURL: "https://p.com/token", UserInfoURL: "https://p.com/user",
			}, nil
		},
	}
	identityRepo := &mockIdentityRepo{
		getByExternalFunc: func(_ context.Context, _, _ string) (identity.ExternalIdentity, error) {
			return identity.ExternalIdentity{
				InternalSubject: "existing-user",
			}, nil
		},
	}
	stateRepo := &mockStateRepo{
		consumeFunc: func(_ context.Context, _ string) (identity.OAuthState, error) {
			return identity.OAuthState{
				ProviderID:          "p1",
				TenantID:            "t1",
				OriginalClientID:    "app",
				OriginalRedirectURI: "https://app.com/cb",
				CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
				CodeChallengeMethod: "S256",
				ExpiresAt:           time.Now().UTC().Add(10 * time.Minute),
			}, nil
		},
	}

	svc := NewService(providerRepo, identityRepo, stateRepo, &mockOAuthClient{},
		newTestAuthSvc(), "https://authplex.com/callback", slog.Default())

	resp, appErr := svc.HandleCallback(context.Background(), CallbackRequest{
		Code: "code", State: "state",
	})

	require.Nil(t, appErr)
	assert.NotEmpty(t, resp.Code)
}

func TestHandleCallback_ProviderError(t *testing.T) {
	svc := NewService(&mockProviderRepo{}, &mockIdentityRepo{}, &mockStateRepo{}, &mockOAuthClient{},
		newTestAuthSvc(), "https://authplex.com/callback", slog.Default())

	_, appErr := svc.HandleCallback(context.Background(), CallbackRequest{
		Error: "access_denied",
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrAccessDenied, appErr.Code)
}

func TestHandleCallback_InvalidState(t *testing.T) {
	svc := NewService(&mockProviderRepo{}, &mockIdentityRepo{}, &mockStateRepo{}, &mockOAuthClient{},
		newTestAuthSvc(), "https://authplex.com/callback", slog.Default())

	_, appErr := svc.HandleCallback(context.Background(), CallbackRequest{
		Code: "code", State: "invalid-state",
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrBadRequest, appErr.Code)
}
