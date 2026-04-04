package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"testing"
	"time"

	adaptcrypto "github.com/authplex/internal/adapter/crypto"
	"github.com/authplex/internal/adapter/cache"
	"github.com/authplex/internal/application/jwks"
	"github.com/authplex/internal/domain/client"
	"github.com/authplex/internal/domain/jwk"
	"github.com/authplex/internal/domain/token"
	"github.com/authplex/internal/domain/user"
	apperrors "github.com/authplex/pkg/sdk/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Mocks ---

type mockCodeRepo struct {
	storeFunc   func(ctx context.Context, code token.AuthorizationCode) error
	consumeFunc func(ctx context.Context, code string) (token.AuthorizationCode, error)
}

func (m *mockCodeRepo) Store(ctx context.Context, code token.AuthorizationCode) error {
	if m.storeFunc != nil {
		return m.storeFunc(ctx, code)
	}
	return nil
}

func (m *mockCodeRepo) Consume(ctx context.Context, code string) (token.AuthorizationCode, error) {
	if m.consumeFunc != nil {
		return m.consumeFunc(ctx, code)
	}
	return token.AuthorizationCode{}, errors.New("not found")
}

type mockJWKRepo struct{}

func (m *mockJWKRepo) Store(_ context.Context, _ jwk.KeyPair) error { return nil }
func (m *mockJWKRepo) GetActive(_ context.Context, _ string) (jwk.KeyPair, error) {
	return jwk.KeyPair{ID: "kid", Algorithm: "RS256", PrivateKey: []byte("key"), Active: true}, nil
}
func (m *mockJWKRepo) GetAllPublic(_ context.Context, _ string) ([]jwk.KeyPair, error) {
	return nil, nil
}
func (m *mockJWKRepo) Deactivate(_ context.Context, _ string) error { return nil }
func (m *mockJWKRepo) GetAllActiveTenantIDs(_ context.Context) ([]string, error) { return nil, nil }
func (m *mockJWKRepo) DeleteInactive(_ context.Context, _ time.Time) (int64, error) { return 0, nil }

type mockJWKRepoNoKey struct{}

func (m *mockJWKRepoNoKey) Store(_ context.Context, _ jwk.KeyPair) error { return nil }
func (m *mockJWKRepoNoKey) GetActive(_ context.Context, _ string) (jwk.KeyPair, error) {
	return jwk.KeyPair{}, errors.New("not found")
}
func (m *mockJWKRepoNoKey) GetAllPublic(_ context.Context, _ string) ([]jwk.KeyPair, error) {
	return nil, nil
}
func (m *mockJWKRepoNoKey) Deactivate(_ context.Context, _ string) error { return nil }
func (m *mockJWKRepoNoKey) GetAllActiveTenantIDs(_ context.Context) ([]string, error) { return nil, nil }
func (m *mockJWKRepoNoKey) DeleteInactive(_ context.Context, _ time.Time) (int64, error) { return 0, nil }

type mockGen struct{}

func (m *mockGen) GenerateRSA() ([]byte, []byte, error) { return nil, nil, nil }
func (m *mockGen) GenerateEC() ([]byte, []byte, error)  { return nil, nil, nil }

type mockConv struct{}

func (m *mockConv) PEMToPublicJWK(_ []byte, _ string, _ string) (jwk.PublicJWK, error) {
	return jwk.PublicJWK{}, nil
}

type mockSigner struct {
	signFunc func(claims token.Claims, kid string, key []byte, alg string) (string, error)
}

func (m *mockSigner) Sign(claims token.Claims, kid string, key []byte, alg string) (string, error) {
	if m.signFunc != nil {
		return m.signFunc(claims, kid, key, alg)
	}
	return "mock-jwt-token", nil
}

type mockRefreshRepo struct {
	tokens map[string]token.RefreshToken
}

func newMockRefreshRepo() *mockRefreshRepo {
	return &mockRefreshRepo{tokens: make(map[string]token.RefreshToken)}
}

func mockHashToken(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func (m *mockRefreshRepo) Store(_ context.Context, rt token.RefreshToken) error {
	hashed := mockHashToken(rt.Token)
	rt.Token = hashed
	m.tokens[hashed] = rt
	return nil
}

func (m *mockRefreshRepo) GetByToken(_ context.Context, tok string) (token.RefreshToken, error) {
	hashed := mockHashToken(tok)
	rt, ok := m.tokens[hashed]
	if !ok {
		return token.RefreshToken{}, errors.New("not found")
	}
	return rt, nil
}

func (m *mockRefreshRepo) RevokeByToken(_ context.Context, tok string) error {
	hashed := mockHashToken(tok)
	rt, ok := m.tokens[hashed]
	if !ok {
		return errors.New("not found")
	}
	now := time.Now()
	rt.RevokedAt = &now
	m.tokens[hashed] = rt
	return nil
}

func (m *mockRefreshRepo) RevokeFamily(_ context.Context, familyID string) error {
	now := time.Now()
	for k, rt := range m.tokens {
		if rt.FamilyID == familyID {
			rt.RevokedAt = &now
			m.tokens[k] = rt
		}
	}
	return nil
}
func (m *mockRefreshRepo) DeleteExpiredAndRevoked(_ context.Context, _ time.Time) (int64, error) { return 0, nil }

type mockDeviceRepo struct {
	devices map[string]token.DeviceCode
}

func newMockDeviceRepo() *mockDeviceRepo {
	return &mockDeviceRepo{devices: make(map[string]token.DeviceCode)}
}

func (m *mockDeviceRepo) Store(_ context.Context, dc token.DeviceCode) error {
	m.devices[dc.DeviceCode] = dc
	return nil
}

func (m *mockDeviceRepo) GetByDeviceCode(_ context.Context, code string) (token.DeviceCode, error) {
	dc, ok := m.devices[code]
	if !ok {
		return token.DeviceCode{}, errors.New("not found")
	}
	return dc, nil
}

func (m *mockDeviceRepo) GetByUserCode(_ context.Context, userCode string) (token.DeviceCode, error) {
	for _, dc := range m.devices {
		if dc.UserCode == userCode {
			return dc, nil
		}
	}
	return token.DeviceCode{}, errors.New("not found")
}

func (m *mockDeviceRepo) Authorize(_ context.Context, userCode, subject string) error {
	for k, dc := range m.devices {
		if dc.UserCode == userCode {
			dc.Subject = subject
			dc.Authorized = true
			m.devices[k] = dc
			return nil
		}
	}
	return errors.New("not found")
}

func (m *mockDeviceRepo) Deny(_ context.Context, userCode string) error {
	for k, dc := range m.devices {
		if dc.UserCode == userCode {
			dc.Denied = true
			m.devices[k] = dc
			return nil
		}
	}
	return errors.New("not found")
}

type mockUserValidator struct {
	validateFunc func(ctx context.Context, tenantID, username, password string) (string, error)
}

func (m *mockUserValidator) ValidateCredentials(ctx context.Context, tenantID, username, password string) (string, error) {
	if m.validateFunc != nil {
		return m.validateFunc(ctx, tenantID, username, password)
	}
	return "user-123", nil
}

type mockBlacklist struct {
	revoked map[string]bool
}

func newMockBlacklist() *mockBlacklist {
	return &mockBlacklist{revoked: make(map[string]bool)}
}

func (m *mockBlacklist) Revoke(_ context.Context, jti string, _ time.Time) error {
	m.revoked[jti] = true
	return nil
}

func (m *mockBlacklist) IsRevoked(_ context.Context, jti string) (bool, error) {
	return m.revoked[jti], nil
}

// testKeyPair holds a real RSA key pair for tests requiring signature verification.
type testKeyPair struct {
	privateKeyPEM []byte
	publicKeyPEM  []byte
}

func generateTestKeyPair(t *testing.T) testKeyPair {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	privBytes, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})

	pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	return testKeyPair{privateKeyPEM: privPEM, publicKeyPEM: pubPEM}
}

// mockJWKRepoReal returns a real RSA key pair for signature verification tests.
type mockJWKRepoReal struct {
	kp testKeyPair
}

func (m *mockJWKRepoReal) Store(_ context.Context, _ jwk.KeyPair) error { return nil }
func (m *mockJWKRepoReal) GetActive(_ context.Context, _ string) (jwk.KeyPair, error) {
	return jwk.KeyPair{ID: "real-kid", Algorithm: "RS256", PrivateKey: m.kp.privateKeyPEM, PublicKey: m.kp.publicKeyPEM, Active: true}, nil
}
func (m *mockJWKRepoReal) GetAllPublic(_ context.Context, _ string) ([]jwk.KeyPair, error) {
	return nil, nil
}
func (m *mockJWKRepoReal) Deactivate(_ context.Context, _ string) error              { return nil }
func (m *mockJWKRepoReal) GetAllActiveTenantIDs(_ context.Context) ([]string, error)  { return nil, nil }
func (m *mockJWKRepoReal) DeleteInactive(_ context.Context, _ time.Time) (int64, error) { return 0, nil }

// signTestJWT creates a properly signed JWT for testing.
func signTestJWT(t *testing.T, claims map[string]any, kp testKeyPair) string {
	t.Helper()
	signer := adaptcrypto.NewJWTSigner()
	claimsJSON, err := json.Marshal(claims)
	require.NoError(t, err)

	var tc token.Claims
	require.NoError(t, json.Unmarshal(claimsJSON, &tc))

	jwt, err := signer.Sign(tc, "real-kid", kp.privateKeyPEM, "RS256")
	require.NoError(t, err)
	return jwt
}

// --- Helpers ---

func validAuthorizeRequest() AuthorizeRequest {
	return AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            "client-1",
		RedirectURI:         "https://example.com/callback",
		Scope:               "openid",
		State:               "state-xyz",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		Subject:             "user-123",
		TenantID:            "tenant-1",
	}
}

func newTestService(codeRepo token.CodeRepository, jwkRepo jwk.Repository, signer token.Signer) *Service {
	jwksSvc := jwks.NewService(jwkRepo, &mockGen{}, &mockConv{}, slog.Default())
	return NewService(codeRepo, jwksSvc, signer, slog.Default())
}

// --- Authorize Tests ---

func TestAuthorize_Success(t *testing.T) {
	svc := newTestService(&mockCodeRepo{}, &mockJWKRepo{}, &mockSigner{})

	resp, appErr := svc.Authorize(context.Background(), validAuthorizeRequest())

	require.Nil(t, appErr)
	assert.NotEmpty(t, resp.Code)
	assert.Equal(t, "state-xyz", resp.State)
}

func TestAuthorize_InvalidResponseType(t *testing.T) {
	svc := newTestService(&mockCodeRepo{}, &mockJWKRepo{}, &mockSigner{})
	req := validAuthorizeRequest()
	req.ResponseType = "token"

	_, appErr := svc.Authorize(context.Background(), req)

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrBadRequest, appErr.Code)
}

func TestAuthorize_MissingClientID(t *testing.T) {
	svc := newTestService(&mockCodeRepo{}, &mockJWKRepo{}, &mockSigner{})
	req := validAuthorizeRequest()
	req.ClientID = ""

	_, appErr := svc.Authorize(context.Background(), req)
	require.NotNil(t, appErr)
}

func TestAuthorize_StoreError(t *testing.T) {
	codeRepo := &mockCodeRepo{
		storeFunc: func(_ context.Context, _ token.AuthorizationCode) error {
			return errors.New("store failed")
		},
	}
	svc := newTestService(codeRepo, &mockJWKRepo{}, &mockSigner{})

	_, appErr := svc.Authorize(context.Background(), validAuthorizeRequest())
	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrInternal, appErr.Code)
}

// --- Exchange: authorization_code ---

func validExchangeSetup() (*mockCodeRepo, string) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	codeRepo := &mockCodeRepo{
		consumeFunc: func(_ context.Context, _ string) (token.AuthorizationCode, error) {
			return token.AuthorizationCode{
				Code:                "code-123",
				ClientID:            "client-1",
				RedirectURI:         "https://example.com/callback",
				Subject:             "user-123",
				TenantID:            "tenant-1",
				Scope:               "openid",
				CodeChallenge:       challenge,
				CodeChallengeMethod: "S256",
				ExpiresAt:           time.Now().UTC().Add(10 * time.Minute),
			}, nil
		},
	}
	return codeRepo, verifier
}

func TestExchange_AuthCode_Success(t *testing.T) {
	codeRepo, verifier := validExchangeSetup()
	svc := newTestService(codeRepo, &mockJWKRepo{}, &mockSigner{})

	resp, appErr := svc.Exchange(context.Background(), TokenRequest{
		GrantType:    "authorization_code",
		Code:         "code-123",
		RedirectURI:  "https://example.com/callback",
		ClientID:     "client-1",
		CodeVerifier: verifier,
		TenantID:     "tenant-1",
	})

	require.Nil(t, appErr)
	assert.Equal(t, "mock-jwt-token", resp.AccessToken)
	assert.Equal(t, "Bearer", resp.TokenType)
}

func TestExchange_AuthCode_PKCEFailed(t *testing.T) {
	codeRepo, _ := validExchangeSetup()
	svc := newTestService(codeRepo, &mockJWKRepo{}, &mockSigner{})

	_, appErr := svc.Exchange(context.Background(), TokenRequest{
		GrantType:    "authorization_code",
		Code:         "code-123",
		RedirectURI:  "https://example.com/callback",
		ClientID:     "client-1",
		CodeVerifier: "wrong-verifier",
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrPKCEFailed, appErr.Code)
}

func TestExchange_AuthCode_ClientIDMismatch(t *testing.T) {
	codeRepo, verifier := validExchangeSetup()
	svc := newTestService(codeRepo, &mockJWKRepo{}, &mockSigner{})

	_, appErr := svc.Exchange(context.Background(), TokenRequest{
		GrantType:    "authorization_code",
		Code:         "code-123",
		RedirectURI:  "https://example.com/callback",
		ClientID:     "wrong-client",
		CodeVerifier: verifier,
	})

	require.NotNil(t, appErr)
	assert.Contains(t, appErr.Message, "client_id mismatch")
}

// --- Exchange: client_credentials ---

func TestExchange_ClientCredentials_Success(t *testing.T) {
	svc := newTestService(&mockCodeRepo{}, &mockJWKRepo{}, &mockSigner{})

	resp, appErr := svc.Exchange(context.Background(), TokenRequest{
		GrantType: "client_credentials",
		ClientID:  "server-app",
		TenantID:  "tenant-1",
		Scope:     "api:read",
	})

	require.Nil(t, appErr)
	assert.Equal(t, "mock-jwt-token", resp.AccessToken)
	assert.Empty(t, resp.RefreshToken, "client_credentials should not issue refresh token")
	assert.Empty(t, resp.IDToken, "client_credentials should not issue id_token")
}

func TestExchange_ClientCredentials_MissingClientID(t *testing.T) {
	svc := newTestService(&mockCodeRepo{}, &mockJWKRepo{}, &mockSigner{})

	_, appErr := svc.Exchange(context.Background(), TokenRequest{
		GrantType: "client_credentials",
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrBadRequest, appErr.Code)
}

// --- Exchange: refresh_token ---

func TestExchange_RefreshToken_Success(t *testing.T) {
	refreshRepo := newMockRefreshRepo()
	h := mockHashToken("rt-123")
	refreshRepo.tokens[h] = token.RefreshToken{
		Token:     h,
		ClientID:  "client-1",
		Subject:   "user-1",
		TenantID:  "tenant-1",
		Scope:     "openid",
		FamilyID:  "fam-1",
		ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
	}

	svc := newTestService(&mockCodeRepo{}, &mockJWKRepo{}, &mockSigner{})
	svc.WithRefreshRepo(refreshRepo)

	resp, appErr := svc.Exchange(context.Background(), TokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: "rt-123",
	})

	require.Nil(t, appErr)
	assert.Equal(t, "mock-jwt-token", resp.AccessToken)
	assert.NotEmpty(t, resp.RefreshToken)
	assert.NotEqual(t, "rt-123", resp.RefreshToken, "should issue new refresh token")
}

func TestExchange_RefreshToken_ReplayDetection(t *testing.T) {
	refreshRepo := newMockRefreshRepo()
	h := mockHashToken("rt-123")
	refreshRepo.tokens[h] = token.RefreshToken{
		Token:     h,
		FamilyID:  "fam-1",
		Rotated:   true, // already used
		ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
	}

	svc := newTestService(&mockCodeRepo{}, &mockJWKRepo{}, &mockSigner{})
	svc.WithRefreshRepo(refreshRepo)

	_, appErr := svc.Exchange(context.Background(), TokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: "rt-123",
	})

	require.NotNil(t, appErr)
	assert.Contains(t, appErr.Message, "reused")
}

func TestExchange_RefreshToken_Expired(t *testing.T) {
	refreshRepo := newMockRefreshRepo()
	h := mockHashToken("rt-123")
	refreshRepo.tokens[h] = token.RefreshToken{
		Token:     h,
		ExpiresAt: time.Now().UTC().Add(-1 * time.Hour),
	}

	svc := newTestService(&mockCodeRepo{}, &mockJWKRepo{}, &mockSigner{})
	svc.WithRefreshRepo(refreshRepo)

	_, appErr := svc.Exchange(context.Background(), TokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: "rt-123",
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrExpiredCode, appErr.Code)
}

func TestExchange_RefreshToken_NotConfigured(t *testing.T) {
	svc := newTestService(&mockCodeRepo{}, &mockJWKRepo{}, &mockSigner{})

	_, appErr := svc.Exchange(context.Background(), TokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: "rt-123",
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrUnsupportedGrant, appErr.Code)
}

// --- Exchange: device_code ---

func TestExchange_DeviceCode_Success(t *testing.T) {
	deviceRepo := newMockDeviceRepo()
	deviceRepo.devices["dev-123"] = token.DeviceCode{
		DeviceCode: "dev-123",
		ClientID:   "client-1",
		TenantID:   "tenant-1",
		Subject:    "user-1",
		Authorized: true,
		ExpiresAt:  time.Now().UTC().Add(10 * time.Minute),
	}

	svc := newTestService(&mockCodeRepo{}, &mockJWKRepo{}, &mockSigner{})
	svc.WithDeviceRepo(deviceRepo)

	resp, appErr := svc.Exchange(context.Background(), TokenRequest{
		GrantType:  "urn:ietf:params:oauth:grant-type:device_code",
		DeviceCode: "dev-123",
	})

	require.Nil(t, appErr)
	assert.Equal(t, "mock-jwt-token", resp.AccessToken)
}

func TestExchange_DeviceCode_Pending(t *testing.T) {
	deviceRepo := newMockDeviceRepo()
	deviceRepo.devices["dev-123"] = token.DeviceCode{
		DeviceCode: "dev-123",
		ExpiresAt:  time.Now().UTC().Add(10 * time.Minute),
	}

	svc := newTestService(&mockCodeRepo{}, &mockJWKRepo{}, &mockSigner{})
	svc.WithDeviceRepo(deviceRepo)

	_, appErr := svc.Exchange(context.Background(), TokenRequest{
		GrantType:  "urn:ietf:params:oauth:grant-type:device_code",
		DeviceCode: "dev-123",
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrAuthorizationPending, appErr.Code)
}

func TestExchange_DeviceCode_Denied(t *testing.T) {
	deviceRepo := newMockDeviceRepo()
	deviceRepo.devices["dev-123"] = token.DeviceCode{
		DeviceCode: "dev-123",
		Denied:     true,
		ExpiresAt:  time.Now().UTC().Add(10 * time.Minute),
	}

	svc := newTestService(&mockCodeRepo{}, &mockJWKRepo{}, &mockSigner{})
	svc.WithDeviceRepo(deviceRepo)

	_, appErr := svc.Exchange(context.Background(), TokenRequest{
		GrantType:  "urn:ietf:params:oauth:grant-type:device_code",
		DeviceCode: "dev-123",
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrAccessDenied, appErr.Code)
}

func TestExchange_DeviceCode_Expired(t *testing.T) {
	deviceRepo := newMockDeviceRepo()
	deviceRepo.devices["dev-123"] = token.DeviceCode{
		DeviceCode: "dev-123",
		ExpiresAt:  time.Now().UTC().Add(-1 * time.Minute),
	}

	svc := newTestService(&mockCodeRepo{}, &mockJWKRepo{}, &mockSigner{})
	svc.WithDeviceRepo(deviceRepo)

	_, appErr := svc.Exchange(context.Background(), TokenRequest{
		GrantType:  "urn:ietf:params:oauth:grant-type:device_code",
		DeviceCode: "dev-123",
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrExpiredCode, appErr.Code)
}

// --- Exchange: password ---

func TestExchange_Password_Success(t *testing.T) {
	svc := newTestService(&mockCodeRepo{}, &mockJWKRepo{}, &mockSigner{})
	svc.WithUserValidator(&mockUserValidator{})

	resp, appErr := svc.Exchange(context.Background(), TokenRequest{
		GrantType: "password",
		Username:  "user@example.com",
		Password:  "secret",
		ClientID:  "client-1",
		TenantID:  "tenant-1",
	})

	require.Nil(t, appErr)
	assert.Equal(t, "mock-jwt-token", resp.AccessToken)
}

func TestExchange_Password_InvalidCredentials(t *testing.T) {
	svc := newTestService(&mockCodeRepo{}, &mockJWKRepo{}, &mockSigner{})
	svc.WithUserValidator(&mockUserValidator{
		validateFunc: func(_ context.Context, _, _, _ string) (string, error) {
			return "", errors.New("bad credentials")
		},
	})

	_, appErr := svc.Exchange(context.Background(), TokenRequest{
		GrantType: "password",
		Username:  "user@example.com",
		Password:  "wrong",
		ClientID:  "client-1",
		TenantID:  "tenant-1",
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrUnauthorized, appErr.Code)
}

func TestExchange_Password_MissingFields(t *testing.T) {
	svc := newTestService(&mockCodeRepo{}, &mockJWKRepo{}, &mockSigner{})
	svc.WithUserValidator(&mockUserValidator{})

	_, appErr := svc.Exchange(context.Background(), TokenRequest{
		GrantType: "password",
		ClientID:  "client-1",
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrBadRequest, appErr.Code)
}

// --- Exchange: unsupported ---

func TestExchange_UnsupportedGrant(t *testing.T) {
	svc := newTestService(&mockCodeRepo{}, &mockJWKRepo{}, &mockSigner{})

	_, appErr := svc.Exchange(context.Background(), TokenRequest{
		GrantType: "implicit",
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrUnsupportedGrant, appErr.Code)
}

// --- Device Auth ---

func TestInitiateDeviceAuth_Success(t *testing.T) {
	deviceRepo := newMockDeviceRepo()
	svc := newTestService(&mockCodeRepo{}, &mockJWKRepo{}, &mockSigner{})
	svc.WithDeviceRepo(deviceRepo)

	resp, appErr := svc.InitiateDeviceAuth(context.Background(), DeviceAuthRequest{
		ClientID: "client-1",
		Scope:    "openid",
		TenantID: "tenant-1",
	})

	require.Nil(t, appErr)
	assert.NotEmpty(t, resp.DeviceCode)
	assert.NotEmpty(t, resp.UserCode)
	assert.Contains(t, resp.UserCode, "-")
	assert.Equal(t, 5, resp.Interval)
	assert.Greater(t, resp.ExpiresIn, 0)
}

func TestAuthorizeDevice_Success(t *testing.T) {
	deviceRepo := newMockDeviceRepo()
	deviceRepo.devices["dev-123"] = token.DeviceCode{
		DeviceCode: "dev-123",
		UserCode:   "ABCD-1234",
	}

	svc := newTestService(&mockCodeRepo{}, &mockJWKRepo{}, &mockSigner{})
	svc.WithDeviceRepo(deviceRepo)

	appErr := svc.AuthorizeDevice(context.Background(), AuthorizeDeviceRequest{
		UserCode: "ABCD-1234",
		Subject:  "user-1",
	})

	assert.Nil(t, appErr)
}

// --- Revoke ---

func TestRevoke_RefreshToken(t *testing.T) {
	refreshRepo := newMockRefreshRepo()
	h := mockHashToken("rt-123")
	refreshRepo.tokens[h] = token.RefreshToken{Token: h}

	svc := newTestService(&mockCodeRepo{}, &mockJWKRepo{}, &mockSigner{})
	svc.WithRefreshRepo(refreshRepo)

	appErr := svc.Revoke(context.Background(), RevokeRequest{
		Token:         "rt-123",
		TokenTypeHint: "refresh_token",
	})

	assert.Nil(t, appErr)
}

func TestRevoke_AccessToken(t *testing.T) {
	bl := newMockBlacklist()
	svc := newTestService(&mockCodeRepo{}, &mockJWKRepo{}, &mockSigner{})
	svc.WithBlacklist(bl)

	appErr := svc.Revoke(context.Background(), RevokeRequest{
		Token: "some-jti",
	})

	assert.Nil(t, appErr)
	assert.True(t, bl.revoked["some-jti"])
}

// --- Introspect ---

func TestIntrospect_Revoked(t *testing.T) {
	bl := newMockBlacklist()
	bl.revoked["some-token"] = true
	svc := newTestService(&mockCodeRepo{}, &mockJWKRepo{}, &mockSigner{})
	svc.WithBlacklist(bl)

	resp, appErr := svc.Introspect(context.Background(), IntrospectRequest{Token: "some-token"})

	require.Nil(t, appErr)
	assert.False(t, resp.Active)
}

func TestIntrospect_InvalidJWT(t *testing.T) {
	svc := newTestService(&mockCodeRepo{}, &mockJWKRepo{}, &mockSigner{})

	resp, appErr := svc.Introspect(context.Background(), IntrospectRequest{Token: "not-a-jwt"})

	require.Nil(t, appErr)
	assert.False(t, resp.Active)
}

func TestIntrospect_ValidJWT(t *testing.T) {
	kp := generateTestKeyPair(t)
	jwkRepo := &mockJWKRepoReal{kp: kp}
	svc := newTestService(&mockCodeRepo{}, jwkRepo, &mockSigner{})

	// Create a properly signed JWT
	jwt := signTestJWT(t, map[string]any{
		"iss": "https://authplex",
		"sub": "user-1",
		"aud": []string{"client-1"},
		"exp": 9999999999,
		"iat": 1000000000,
		"jti": "jti-1",
	}, kp)

	resp, appErr := svc.Introspect(context.Background(), IntrospectRequest{Token: jwt})

	require.Nil(t, appErr)
	assert.True(t, resp.Active)
	assert.Equal(t, "user-1", resp.Subject)
	assert.Equal(t, "client-1", resp.ClientID)
	assert.Equal(t, "https://authplex", resp.Issuer)
}

func TestIntrospect_InvalidSignature(t *testing.T) {
	kp := generateTestKeyPair(t)
	jwkRepo := &mockJWKRepoReal{kp: kp}
	svc := newTestService(&mockCodeRepo{}, jwkRepo, &mockSigner{})

	// Construct a JWT with a fake signature (should fail verification)
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT","kid":"real-kid"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"https://authplex","sub":"user-1","aud":["client-1"],"exp":9999999999,"iat":1000000000,"jti":"jti-1"}`))
	fakeJWT := header + "." + payload + ".fakesig"

	resp, appErr := svc.Introspect(context.Background(), IntrospectRequest{Token: fakeJWT})

	require.Nil(t, appErr)
	assert.False(t, resp.Active, "JWT with invalid signature should not be active")
}

func TestIntrospect_ExpiredJWT(t *testing.T) {
	kp := generateTestKeyPair(t)
	jwkRepo := &mockJWKRepoReal{kp: kp}
	svc := newTestService(&mockCodeRepo{}, jwkRepo, &mockSigner{})

	// Create a properly signed JWT that is expired
	jwt := signTestJWT(t, map[string]any{
		"iss": "https://authplex",
		"sub": "user-1",
		"aud": []string{"client-1"},
		"exp": 1000000000,
		"iat": 999999000,
	}, kp)

	resp, appErr := svc.Introspect(context.Background(), IntrospectRequest{Token: jwt})

	require.Nil(t, appErr)
	assert.False(t, resp.Active)
}

func TestExchange_AuthCode_MissingCode(t *testing.T) {
	svc := newTestService(&mockCodeRepo{}, &mockJWKRepo{}, &mockSigner{})

	_, appErr := svc.Exchange(context.Background(), TokenRequest{
		GrantType: "authorization_code",
	})

	require.NotNil(t, appErr)
	assert.Contains(t, appErr.Message, "code is required")
}

func TestExchange_AuthCode_MissingClientID(t *testing.T) {
	svc := newTestService(&mockCodeRepo{}, &mockJWKRepo{}, &mockSigner{})

	_, appErr := svc.Exchange(context.Background(), TokenRequest{
		GrantType:    "authorization_code",
		Code:         "code-123",
		CodeVerifier: "verifier",
	})

	require.NotNil(t, appErr)
	assert.Contains(t, appErr.Message, "client_id is required")
}

func TestExchange_RefreshToken_Revoked(t *testing.T) {
	now := time.Now()
	refreshRepo := newMockRefreshRepo()
	h := mockHashToken("rt-123")
	refreshRepo.tokens[h] = token.RefreshToken{
		Token:     h,
		RevokedAt: &now,
		ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
	}

	svc := newTestService(&mockCodeRepo{}, &mockJWKRepo{}, &mockSigner{})
	svc.WithRefreshRepo(refreshRepo)

	_, appErr := svc.Exchange(context.Background(), TokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: "rt-123",
	})

	require.NotNil(t, appErr)
	assert.Contains(t, appErr.Message, "revoked")
}

func TestExchange_RefreshToken_Missing(t *testing.T) {
	svc := newTestService(&mockCodeRepo{}, &mockJWKRepo{}, &mockSigner{})
	svc.WithRefreshRepo(newMockRefreshRepo())

	_, appErr := svc.Exchange(context.Background(), TokenRequest{
		GrantType: "refresh_token",
	})

	require.NotNil(t, appErr)
	assert.Contains(t, appErr.Message, "refresh_token is required")
}

func TestExchange_DeviceCode_Missing(t *testing.T) {
	svc := newTestService(&mockCodeRepo{}, &mockJWKRepo{}, &mockSigner{})
	svc.WithDeviceRepo(newMockDeviceRepo())

	_, appErr := svc.Exchange(context.Background(), TokenRequest{
		GrantType: "urn:ietf:params:oauth:grant-type:device_code",
	})

	require.NotNil(t, appErr)
	assert.Contains(t, appErr.Message, "device_code is required")
}

func TestAuthorize_MissingSubject(t *testing.T) {
	svc := newTestService(&mockCodeRepo{}, &mockJWKRepo{}, &mockSigner{})
	req := validAuthorizeRequest()
	req.Subject = ""

	_, appErr := svc.Authorize(context.Background(), req)
	require.NotNil(t, appErr)
	assert.Contains(t, appErr.Message, "subject")
}

func TestAuthorize_MissingRedirectURI(t *testing.T) {
	svc := newTestService(&mockCodeRepo{}, &mockJWKRepo{}, &mockSigner{})
	req := validAuthorizeRequest()
	req.RedirectURI = ""

	_, appErr := svc.Authorize(context.Background(), req)
	require.NotNil(t, appErr)
}

func TestAuthorize_MissingCodeChallenge(t *testing.T) {
	svc := newTestService(&mockCodeRepo{}, &mockJWKRepo{}, &mockSigner{})
	req := validAuthorizeRequest()
	req.CodeChallenge = ""

	_, appErr := svc.Authorize(context.Background(), req)
	require.NotNil(t, appErr)
}

func TestAuthorize_InvalidChallengeMethod(t *testing.T) {
	svc := newTestService(&mockCodeRepo{}, &mockJWKRepo{}, &mockSigner{})
	req := validAuthorizeRequest()
	req.CodeChallengeMethod = "plain"

	_, appErr := svc.Authorize(context.Background(), req)
	require.NotNil(t, appErr)
}

func TestExchange_AuthCode_RedirectURIMismatch(t *testing.T) {
	codeRepo, verifier := validExchangeSetup()
	svc := newTestService(codeRepo, &mockJWKRepo{}, &mockSigner{})

	_, appErr := svc.Exchange(context.Background(), TokenRequest{
		GrantType:    "authorization_code",
		Code:         "code-123",
		RedirectURI:  "https://evil.com/cb",
		ClientID:     "client-1",
		CodeVerifier: verifier,
	})

	require.NotNil(t, appErr)
	assert.Contains(t, appErr.Message, "redirect_uri")
}

func TestExchange_AuthCode_NoSigningKey(t *testing.T) {
	codeRepo, verifier := validExchangeSetup()
	svc := newTestService(codeRepo, &mockJWKRepoNoKey{}, &mockSigner{})

	_, appErr := svc.Exchange(context.Background(), TokenRequest{
		GrantType:    "authorization_code",
		Code:         "code-123",
		RedirectURI:  "https://example.com/callback",
		ClientID:     "client-1",
		CodeVerifier: verifier,
		TenantID:     "tenant-1",
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrInternal, appErr.Code)
}

func TestInitiateDeviceAuth_MissingClientID(t *testing.T) {
	svc := newTestService(&mockCodeRepo{}, &mockJWKRepo{}, &mockSigner{})
	svc.WithDeviceRepo(newMockDeviceRepo())

	_, appErr := svc.InitiateDeviceAuth(context.Background(), DeviceAuthRequest{})
	require.NotNil(t, appErr)
}

func TestAuthorizeDevice_MissingUserCode(t *testing.T) {
	svc := newTestService(&mockCodeRepo{}, &mockJWKRepo{}, &mockSigner{})
	svc.WithDeviceRepo(newMockDeviceRepo())

	appErr := svc.AuthorizeDevice(context.Background(), AuthorizeDeviceRequest{})
	require.NotNil(t, appErr)
}

func TestAuthorizeDevice_MissingSubject(t *testing.T) {
	svc := newTestService(&mockCodeRepo{}, &mockJWKRepo{}, &mockSigner{})
	svc.WithDeviceRepo(newMockDeviceRepo())

	appErr := svc.AuthorizeDevice(context.Background(), AuthorizeDeviceRequest{UserCode: "ABCD-1234"})
	require.NotNil(t, appErr)
}

// --- WithXxx fluent method tests ---

func TestAuthSvc_WithUserRepo(t *testing.T) {
	svc := newTestService(&mockCodeRepo{}, &mockJWKRepo{}, &mockSigner{})
	result := svc.WithUserRepo(nil)
	assert.NotNil(t, result)
}

func TestAuthSvc_WithTenantRepo(t *testing.T) {
	svc := newTestService(&mockCodeRepo{}, &mockJWKRepo{}, &mockSigner{})
	result := svc.WithTenantRepo(nil)
	assert.NotNil(t, result)
}

func TestAuthSvc_WithRBAC(t *testing.T) {
	svc := newTestService(&mockCodeRepo{}, &mockJWKRepo{}, &mockSigner{})
	result := svc.WithRBAC(nil)
	assert.NotNil(t, result)
}

func TestAuthSvc_WithAudit(t *testing.T) {
	svc := newTestService(&mockCodeRepo{}, &mockJWKRepo{}, &mockSigner{})
	result := svc.WithAudit(nil)
	assert.NotNil(t, result)
}

func TestAuthSvc_WithClientRepo(t *testing.T) {
	svc := newTestService(&mockCodeRepo{}, &mockJWKRepo{}, &mockSigner{})
	result := svc.WithClientRepo(nil)
	assert.NotNil(t, result)
}

func TestIntrospect_WithTokenVersion_UserRevoked(t *testing.T) {
	kp := generateTestKeyPair(t)
	jwkRepo := &mockJWKRepoReal{kp: kp}
	userRepo := cache.NewInMemoryUserRepository()
	svc := newTestService(&mockCodeRepo{}, jwkRepo, &mockSigner{})
	svc.WithUserRepo(userRepo)

	// Create user with higher token version
	u, _ := user.NewUser("user-1", "t1", "a@b.com", "Test")
	u.TokenVersion = 5
	userRepo.Create(context.Background(), u) //nolint:errcheck

	// Sign a JWT with lower token version
	jwt := signTestJWT(t, map[string]any{
		"iss": "https://authplex",
		"sub": "user-1",
		"aud": []string{"t1"},
		"exp": 9999999999,
		"iat": 1000000000,
		"jti": "jti-1",
		"tv":  2,
	}, kp)

	resp, appErr := svc.Introspect(context.Background(), IntrospectRequest{Token: jwt})
	require.Nil(t, appErr)
	assert.False(t, resp.Active) // Token version is outdated
}

func TestIntrospect_WithTokenVersion_Active(t *testing.T) {
	kp := generateTestKeyPair(t)
	jwkRepo := &mockJWKRepoReal{kp: kp}
	userRepo := cache.NewInMemoryUserRepository()
	tenantRepo := cache.NewInMemoryTenantRepository()
	svc := newTestService(&mockCodeRepo{}, jwkRepo, &mockSigner{})
	svc.WithUserRepo(userRepo)
	svc.WithTenantRepo(tenantRepo)

	u, _ := user.NewUser("user-1", "t1", "a@b.com", "Test")
	u.TokenVersion = 1
	userRepo.Create(context.Background(), u) //nolint:errcheck

	jwt := signTestJWT(t, map[string]any{
		"iss": "https://authplex",
		"sub": "user-1",
		"aud": []string{"t1"},
		"exp": 9999999999,
		"iat": 1000000000,
		"jti": "jti-2",
		"tv":  1,
	}, kp)

	resp, appErr := svc.Introspect(context.Background(), IntrospectRequest{Token: jwt})
	require.Nil(t, appErr)
	assert.True(t, resp.Active)
}

func TestExchangeClientCredentials_WithEndpoints(t *testing.T) {
	kp := generateTestKeyPair(t)
	jwkRepo := &mockJWKRepoReal{kp: kp}
	clientRepo := cache.NewInMemoryClientRepository()
	ctx := context.Background()

	// Create a client with AllowedEndpoints
	c, _ := client.NewClient("client-1", "t1", "API Client", client.Confidential,
		nil, nil, []client.GrantType{client.GrantClientCredentials})
	c.AllowedEndpoints = []string{"/api/v1/resource"}
	clientRepo.Create(ctx, c) //nolint:errcheck

	svc := newTestService(&mockCodeRepo{}, jwkRepo, adaptcrypto.NewJWTSigner())
	svc.WithClientRepo(clientRepo)

	resp, appErr := svc.Exchange(ctx, TokenRequest{
		GrantType: "client_credentials",
		ClientID:  "client-1",
		TenantID:  "t1",
		Scope:     "api:read",
	})

	require.Nil(t, appErr)
	assert.NotEmpty(t, resp.AccessToken)
}
