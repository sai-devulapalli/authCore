package mfa

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/authplex/internal/application/auth"
	"github.com/authplex/internal/application/jwks"
	domainmfa "github.com/authplex/internal/domain/mfa"
	"github.com/authplex/internal/domain/jwk"
	"github.com/authplex/internal/domain/token"
	apperrors "github.com/authplex/pkg/sdk/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Mocks ---

type mockTOTPRepo struct {
	enrollments map[string]domainmfa.TOTPEnrollment
}

func newMockTOTPRepo() *mockTOTPRepo {
	return &mockTOTPRepo{enrollments: make(map[string]domainmfa.TOTPEnrollment)}
}

func (m *mockTOTPRepo) Store(_ context.Context, e domainmfa.TOTPEnrollment) error {
	m.enrollments[e.ID] = e
	return nil
}
func (m *mockTOTPRepo) GetBySubject(_ context.Context, tenantID, subject string) (domainmfa.TOTPEnrollment, error) {
	for _, e := range m.enrollments {
		if e.TenantID == tenantID && e.Subject == subject {
			return e, nil
		}
	}
	return domainmfa.TOTPEnrollment{}, errors.New("not found")
}
func (m *mockTOTPRepo) Confirm(_ context.Context, id string) error {
	e, ok := m.enrollments[id]
	if !ok {
		return errors.New("not found")
	}
	e.Confirmed = true
	m.enrollments[id] = e
	return nil
}
func (m *mockTOTPRepo) Delete(_ context.Context, id string) error {
	delete(m.enrollments, id)
	return nil
}

type mockChallengeRepo struct {
	challenges map[string]domainmfa.MFAChallenge
}

func newMockChallengeRepo() *mockChallengeRepo {
	return &mockChallengeRepo{challenges: make(map[string]domainmfa.MFAChallenge)}
}

func (m *mockChallengeRepo) Store(_ context.Context, c domainmfa.MFAChallenge) error {
	m.challenges[c.ID] = c
	return nil
}
func (m *mockChallengeRepo) GetByID(_ context.Context, id string) (domainmfa.MFAChallenge, error) {
	c, ok := m.challenges[id]
	if !ok {
		return domainmfa.MFAChallenge{}, errors.New("not found")
	}
	return c, nil
}
func (m *mockChallengeRepo) MarkVerified(_ context.Context, id string) error {
	c := m.challenges[id]
	c.Verified = true
	m.challenges[id] = c
	return nil
}
func (m *mockChallengeRepo) Delete(_ context.Context, id string) error {
	delete(m.challenges, id)
	return nil
}

type mockJWKRepo struct{}
func (m *mockJWKRepo) Store(_ context.Context, _ jwk.KeyPair) error { return nil }
func (m *mockJWKRepo) GetActive(_ context.Context, _ string) (jwk.KeyPair, error) {
	return jwk.KeyPair{ID: "kid", Algorithm: "RS256", PrivateKey: []byte("key")}, nil
}
func (m *mockJWKRepo) GetAllPublic(_ context.Context, _ string) ([]jwk.KeyPair, error) { return nil, nil }
func (m *mockJWKRepo) Deactivate(_ context.Context, _ string) error { return nil }
func (m *mockJWKRepo) GetAllActiveTenantIDs(_ context.Context) ([]string, error) { return nil, nil }
func (m *mockJWKRepo) DeleteInactive(_ context.Context, _ time.Time) (int64, error) { return 0, nil }

type mockGen struct{}
func (m *mockGen) GenerateRSA() ([]byte, []byte, error) { return nil, nil, nil }
func (m *mockGen) GenerateEC() ([]byte, []byte, error) { return nil, nil, nil }

type mockConv struct{}
func (m *mockConv) PEMToPublicJWK(_ []byte, _ string, _ string) (jwk.PublicJWK, error) { return jwk.PublicJWK{}, nil }

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

func TestEnrollTOTP_Success(t *testing.T) {
	svc := NewService(newMockTOTPRepo(), newMockChallengeRepo(), newTestAuthSvc(), slog.Default())

	resp, appErr := svc.EnrollTOTP(context.Background(), EnrollRequest{
		Subject: "user-1", TenantID: "t1",
	})

	require.Nil(t, appErr)
	assert.NotEmpty(t, resp.Secret)
	assert.Contains(t, resp.OTPAuthURI, "otpauth://totp/")
	assert.Contains(t, resp.OTPAuthURI, "user-1")
}

func TestEnrollTOTP_AlreadyEnrolled(t *testing.T) {
	totpRepo := newMockTOTPRepo()
	totpRepo.enrollments["e1"] = domainmfa.TOTPEnrollment{
		ID: "e1", Subject: "user-1", TenantID: "t1", Confirmed: true,
	}
	svc := NewService(totpRepo, newMockChallengeRepo(), newTestAuthSvc(), slog.Default())

	_, appErr := svc.EnrollTOTP(context.Background(), EnrollRequest{
		Subject: "user-1", TenantID: "t1",
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrConflict, appErr.Code)
}

func TestEnrollTOTP_MissingSubject(t *testing.T) {
	svc := NewService(newMockTOTPRepo(), newMockChallengeRepo(), newTestAuthSvc(), slog.Default())

	_, appErr := svc.EnrollTOTP(context.Background(), EnrollRequest{TenantID: "t1"})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrBadRequest, appErr.Code)
}

func TestConfirmTOTP_Success(t *testing.T) {
	totpRepo := newMockTOTPRepo()
	secret := []byte("12345678901234567890")
	totpRepo.enrollments["e1"] = domainmfa.TOTPEnrollment{
		ID: "e1", Subject: "user-1", TenantID: "t1", Secret: secret, Confirmed: false,
	}

	svc := NewService(totpRepo, newMockChallengeRepo(), newTestAuthSvc(), slog.Default())

	code := domainmfa.GenerateTOTP(secret, time.Now().UTC())
	appErr := svc.ConfirmTOTP(context.Background(), VerifyRequest{
		Subject: "user-1", TenantID: "t1", Code: code,
	})

	assert.Nil(t, appErr)
	assert.True(t, totpRepo.enrollments["e1"].Confirmed)
}

func TestConfirmTOTP_WrongCode(t *testing.T) {
	totpRepo := newMockTOTPRepo()
	totpRepo.enrollments["e1"] = domainmfa.TOTPEnrollment{
		ID: "e1", Subject: "user-1", TenantID: "t1", Secret: []byte("secret"), Confirmed: false,
	}

	svc := NewService(totpRepo, newMockChallengeRepo(), newTestAuthSvc(), slog.Default())

	appErr := svc.ConfirmTOTP(context.Background(), VerifyRequest{
		Subject: "user-1", TenantID: "t1", Code: "000000",
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrBadRequest, appErr.Code)
}

func TestConfirmTOTP_NotEnrolled(t *testing.T) {
	svc := NewService(newMockTOTPRepo(), newMockChallengeRepo(), newTestAuthSvc(), slog.Default())

	appErr := svc.ConfirmTOTP(context.Background(), VerifyRequest{
		Subject: "user-1", TenantID: "t1", Code: "123456",
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrNotFound, appErr.Code)
}

func TestConfirmTOTP_AlreadyConfirmed(t *testing.T) {
	totpRepo := newMockTOTPRepo()
	totpRepo.enrollments["e1"] = domainmfa.TOTPEnrollment{
		ID: "e1", Subject: "user-1", TenantID: "t1", Secret: []byte("s"), Confirmed: true,
	}

	svc := NewService(totpRepo, newMockChallengeRepo(), newTestAuthSvc(), slog.Default())

	appErr := svc.ConfirmTOTP(context.Background(), VerifyRequest{
		Subject: "user-1", TenantID: "t1", Code: "123456",
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrConflict, appErr.Code)
}

func TestVerifyMFA_Success(t *testing.T) {
	totpRepo := newMockTOTPRepo()
	secret := []byte("12345678901234567890")
	totpRepo.enrollments["e1"] = domainmfa.TOTPEnrollment{
		ID: "e1", Subject: "user-1", TenantID: "t1", Secret: secret, Confirmed: true,
	}

	challengeRepo := newMockChallengeRepo()
	challengeRepo.challenges["ch1"] = domainmfa.MFAChallenge{
		ID:                  "ch1",
		Subject:             "user-1",
		TenantID:            "t1",
		ExpiresAt:           time.Now().UTC().Add(5 * time.Minute),
		OriginalClientID:    "client-1",
		OriginalRedirectURI: "https://example.com/cb",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
	}

	svc := NewService(totpRepo, challengeRepo, newTestAuthSvc(), slog.Default())

	code := domainmfa.GenerateTOTP(secret, time.Now().UTC())
	resp, appErr := svc.VerifyMFA(context.Background(), MFAVerifyRequest{
		ChallengeID: "ch1", Method: "totp", Code: code,
	})

	require.Nil(t, appErr)
	assert.NotEmpty(t, resp.Code)
}

func TestVerifyMFA_ChallengeNotFound(t *testing.T) {
	svc := NewService(newMockTOTPRepo(), newMockChallengeRepo(), newTestAuthSvc(), slog.Default())

	_, appErr := svc.VerifyMFA(context.Background(), MFAVerifyRequest{
		ChallengeID: "nonexistent", Code: "123456",
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrNotFound, appErr.Code)
}

func TestVerifyMFA_ChallengeExpired(t *testing.T) {
	challengeRepo := newMockChallengeRepo()
	challengeRepo.challenges["ch1"] = domainmfa.MFAChallenge{
		ID:        "ch1",
		ExpiresAt: time.Now().UTC().Add(-1 * time.Minute),
	}

	svc := NewService(newMockTOTPRepo(), challengeRepo, newTestAuthSvc(), slog.Default())

	_, appErr := svc.VerifyMFA(context.Background(), MFAVerifyRequest{
		ChallengeID: "ch1", Code: "123456",
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrExpiredCode, appErr.Code)
}

func TestVerifyMFA_WrongCode(t *testing.T) {
	totpRepo := newMockTOTPRepo()
	totpRepo.enrollments["e1"] = domainmfa.TOTPEnrollment{
		ID: "e1", Subject: "user-1", TenantID: "t1", Secret: []byte("secret"), Confirmed: true,
	}

	challengeRepo := newMockChallengeRepo()
	challengeRepo.challenges["ch1"] = domainmfa.MFAChallenge{
		ID: "ch1", Subject: "user-1", TenantID: "t1",
		ExpiresAt: time.Now().UTC().Add(5 * time.Minute),
	}

	svc := NewService(totpRepo, challengeRepo, newTestAuthSvc(), slog.Default())

	_, appErr := svc.VerifyMFA(context.Background(), MFAVerifyRequest{
		ChallengeID: "ch1", Code: "000000",
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrBadRequest, appErr.Code)
}

func TestCreateChallenge(t *testing.T) {
	svc := NewService(newMockTOTPRepo(), newMockChallengeRepo(), newTestAuthSvc(), slog.Default())

	resp, appErr := svc.CreateChallenge(context.Background(), CreateChallengeRequest{
		Subject:  "user-1",
		TenantID: "t1",
		Methods:  []string{"totp"},
	})

	require.Nil(t, appErr)
	assert.NotEmpty(t, resp.ChallengeID)
	assert.True(t, resp.MFARequired)
	assert.Contains(t, resp.Methods, "totp")
	assert.Greater(t, resp.ExpiresIn, 0)
}

func TestHasEnrolledMFA_True(t *testing.T) {
	totpRepo := newMockTOTPRepo()
	totpRepo.enrollments["e1"] = domainmfa.TOTPEnrollment{
		ID: "e1", Subject: "user-1", TenantID: "t1", Confirmed: true,
	}

	svc := NewService(totpRepo, newMockChallengeRepo(), newTestAuthSvc(), slog.Default())

	assert.True(t, svc.HasEnrolledMFA(context.Background(), "t1", "user-1"))
}

func TestHasEnrolledMFA_False(t *testing.T) {
	svc := NewService(newMockTOTPRepo(), newMockChallengeRepo(), newTestAuthSvc(), slog.Default())

	assert.False(t, svc.HasEnrolledMFA(context.Background(), "t1", "nonexistent"))
}

// --- WebAuthn Tests ---

type mockWebAuthnRepo struct {
	creds map[string]domainmfa.WebAuthnCredential
}

func newMockWebAuthnRepo() *mockWebAuthnRepo {
	return &mockWebAuthnRepo{creds: make(map[string]domainmfa.WebAuthnCredential)}
}

func (m *mockWebAuthnRepo) Store(_ context.Context, c domainmfa.WebAuthnCredential) error {
	m.creds[c.ID] = c
	return nil
}

func (m *mockWebAuthnRepo) GetBySubject(_ context.Context, tenantID, subject string) ([]domainmfa.WebAuthnCredential, error) {
	var result []domainmfa.WebAuthnCredential
	for _, c := range m.creds {
		if c.TenantID == tenantID && c.Subject == subject {
			result = append(result, c)
		}
	}
	if len(result) == 0 {
		return nil, errors.New("not found")
	}
	return result, nil
}

func (m *mockWebAuthnRepo) GetByCredentialID(_ context.Context, credID []byte) (domainmfa.WebAuthnCredential, error) {
	for _, c := range m.creds {
		if string(c.CredentialID) == string(credID) {
			return c, nil
		}
	}
	return domainmfa.WebAuthnCredential{}, errors.New("not found")
}

func (m *mockWebAuthnRepo) UpdateSignCount(_ context.Context, id string, count uint32) error {
	c, ok := m.creds[id]
	if !ok {
		return errors.New("not found")
	}
	c.SignCount = count
	m.creds[id] = c
	return nil
}

func (m *mockWebAuthnRepo) Delete(_ context.Context, id string) error {
	delete(m.creds, id)
	return nil
}

func TestWithWebAuthn(t *testing.T) {
	svc := NewService(newMockTOTPRepo(), newMockChallengeRepo(), newTestAuthSvc(), slog.Default())
	repo := newMockWebAuthnRepo()

	result := svc.WithWebAuthn(repo, "example.com", "Example", []string{"https://example.com"})

	assert.Same(t, svc, result) // returns same pointer
	assert.NotNil(t, svc.webauthnRepo)
	assert.Equal(t, "example.com", svc.webauthnRPID)
	assert.Equal(t, "Example", svc.webauthnRPName)
	assert.Equal(t, []string{"https://example.com"}, svc.webauthnRPOrigins)
}

func TestHasEnrolledMFA_WithWebAuthn(t *testing.T) {
	waRepo := newMockWebAuthnRepo()
	waRepo.creds["c1"] = domainmfa.WebAuthnCredential{
		ID: "c1", Subject: "user-1", TenantID: "t1", CredentialID: []byte("cred-1"),
	}

	svc := NewService(newMockTOTPRepo(), newMockChallengeRepo(), newTestAuthSvc(), slog.Default()).
		WithWebAuthn(waRepo, "example.com", "Test", []string{"https://example.com"})

	assert.True(t, svc.HasEnrolledMFA(context.Background(), "t1", "user-1"))
	assert.False(t, svc.HasEnrolledMFA(context.Background(), "t1", "nonexistent"))
}

func TestBeginWebAuthnRegistration_NotConfigured(t *testing.T) {
	svc := NewService(newMockTOTPRepo(), newMockChallengeRepo(), newTestAuthSvc(), slog.Default())

	_, appErr := svc.BeginWebAuthnRegistration(context.Background(), WebAuthnRegisterRequest{
		Subject: "user-1", TenantID: "t1",
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrBadRequest, appErr.Code)
	assert.Contains(t, appErr.Error(), "not configured")
}

func TestBeginWebAuthnRegistration_MissingSubject(t *testing.T) {
	svc := NewService(newMockTOTPRepo(), newMockChallengeRepo(), newTestAuthSvc(), slog.Default()).
		WithWebAuthn(newMockWebAuthnRepo(), "localhost", "Test", []string{"http://localhost"})

	_, appErr := svc.BeginWebAuthnRegistration(context.Background(), WebAuthnRegisterRequest{
		TenantID: "t1",
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrBadRequest, appErr.Code)
}

func TestBeginWebAuthnRegistration_Success(t *testing.T) {
	svc := NewService(newMockTOTPRepo(), newMockChallengeRepo(), newTestAuthSvc(), slog.Default()).
		WithWebAuthn(newMockWebAuthnRepo(), "localhost", "Test", []string{"http://localhost:8080"})

	resp, appErr := svc.BeginWebAuthnRegistration(context.Background(), WebAuthnRegisterRequest{
		Subject: "user-1", TenantID: "t1", DisplayName: "Test User",
	})

	require.Nil(t, appErr)
	assert.NotEmpty(t, resp)
	// Verify it contains session_id and options
	var parsed map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(resp, &parsed))
	assert.Contains(t, string(parsed["session_id"]), "")
	assert.NotEmpty(t, parsed["options"])
}

func TestFinishWebAuthnRegistration_NotConfigured(t *testing.T) {
	svc := NewService(newMockTOTPRepo(), newMockChallengeRepo(), newTestAuthSvc(), slog.Default())

	appErr := svc.FinishWebAuthnRegistration(context.Background(), WebAuthnRegisterFinishRequest{
		Subject: "user-1", TenantID: "t1",
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrBadRequest, appErr.Code)
}

func TestFinishWebAuthnRegistration_MissingSubject(t *testing.T) {
	svc := NewService(newMockTOTPRepo(), newMockChallengeRepo(), newTestAuthSvc(), slog.Default()).
		WithWebAuthn(newMockWebAuthnRepo(), "localhost", "Test", []string{"http://localhost"})

	appErr := svc.FinishWebAuthnRegistration(context.Background(), WebAuthnRegisterFinishRequest{
		TenantID: "t1",
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrBadRequest, appErr.Code)
}

func TestFinishWebAuthnRegistration_InvalidResponse(t *testing.T) {
	svc := NewService(newMockTOTPRepo(), newMockChallengeRepo(), newTestAuthSvc(), slog.Default()).
		WithWebAuthn(newMockWebAuthnRepo(), "localhost", "Test", []string{"http://localhost"})

	appErr := svc.FinishWebAuthnRegistration(context.Background(), WebAuthnRegisterFinishRequest{
		Subject: "user-1", TenantID: "t1", Response: []byte("not json"),
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrBadRequest, appErr.Code)
}

func TestFinishWebAuthnRegistration_SessionNotFound(t *testing.T) {
	svc := NewService(newMockTOTPRepo(), newMockChallengeRepo(), newTestAuthSvc(), slog.Default()).
		WithWebAuthn(newMockWebAuthnRepo(), "localhost", "Test", []string{"http://localhost"})

	appErr := svc.FinishWebAuthnRegistration(context.Background(), WebAuthnRegisterFinishRequest{
		Subject: "user-1", TenantID: "t1",
		Response: []byte(`{"session_id":"nonexistent","response":{}}`),
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrNotFound, appErr.Code)
}

func TestBeginWebAuthnLogin_NotConfigured(t *testing.T) {
	svc := NewService(newMockTOTPRepo(), newMockChallengeRepo(), newTestAuthSvc(), slog.Default())

	_, appErr := svc.BeginWebAuthnLogin(context.Background(), WebAuthnLoginRequest{
		Subject: "user-1", TenantID: "t1",
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrBadRequest, appErr.Code)
}

func TestBeginWebAuthnLogin_MissingSubject(t *testing.T) {
	svc := NewService(newMockTOTPRepo(), newMockChallengeRepo(), newTestAuthSvc(), slog.Default()).
		WithWebAuthn(newMockWebAuthnRepo(), "localhost", "Test", []string{"http://localhost"})

	_, appErr := svc.BeginWebAuthnLogin(context.Background(), WebAuthnLoginRequest{
		TenantID: "t1",
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrBadRequest, appErr.Code)
}

func TestBeginWebAuthnLogin_NoCredentials(t *testing.T) {
	svc := NewService(newMockTOTPRepo(), newMockChallengeRepo(), newTestAuthSvc(), slog.Default()).
		WithWebAuthn(newMockWebAuthnRepo(), "localhost", "Test", []string{"http://localhost:8080"})

	_, appErr := svc.BeginWebAuthnLogin(context.Background(), WebAuthnLoginRequest{
		Subject: "user-1", TenantID: "t1",
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrNotFound, appErr.Code)
	assert.Contains(t, appErr.Error(), "no WebAuthn credentials")
}

func TestVerifyMFA_WebAuthn_NotConfigured(t *testing.T) {
	challengeRepo := newMockChallengeRepo()
	challengeRepo.challenges["ch1"] = domainmfa.MFAChallenge{
		ID: "ch1", Subject: "user-1", TenantID: "t1",
		ExpiresAt: time.Now().UTC().Add(5 * time.Minute),
	}

	svc := NewService(newMockTOTPRepo(), challengeRepo, newTestAuthSvc(), slog.Default())

	_, appErr := svc.VerifyMFA(context.Background(), MFAVerifyRequest{
		ChallengeID: "ch1", Method: "webauthn", Code: "{}",
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrBadRequest, appErr.Code)
}

func TestNewWebAuthn(t *testing.T) {
	svc := NewService(newMockTOTPRepo(), newMockChallengeRepo(), newTestAuthSvc(), slog.Default()).
		WithWebAuthn(newMockWebAuthnRepo(), "localhost", "Test", []string{"http://localhost:8080"})

	w, appErr := svc.newWebAuthn()
	require.Nil(t, appErr)
	assert.NotNil(t, w)
}

func TestBuildWebAuthnUser_NoCredentials(t *testing.T) {
	svc := NewService(newMockTOTPRepo(), newMockChallengeRepo(), newTestAuthSvc(), slog.Default()).
		WithWebAuthn(newMockWebAuthnRepo(), "localhost", "Test", []string{"http://localhost"})

	user, appErr := svc.buildWebAuthnUser(context.Background(), "t1", "user-1", "Test User")
	require.Nil(t, appErr)
	assert.Equal(t, []byte("user-1"), user.WebAuthnID())
	assert.Equal(t, "user-1", user.WebAuthnName())
	assert.Equal(t, "Test User", user.WebAuthnDisplayName())
	assert.Empty(t, user.WebAuthnCredentials())
}

func TestFinishWebAuthnRegistration_ExpiredSession(t *testing.T) {
	challengeRepo := newMockChallengeRepo()
	// Store an expired challenge
	challengeRepo.challenges["session-1"] = domainmfa.MFAChallenge{
		ID:        "session-1",
		Subject:   "user-1",
		TenantID:  "t1",
		Methods:   []string{"webauthn"},
		ExpiresAt: time.Now().UTC().Add(-5 * time.Minute), // expired
		Nonce:     `{"session":{},"subject":"user-1","tenant_id":"t1"}`,
	}

	svc := NewService(newMockTOTPRepo(), challengeRepo, newTestAuthSvc(), slog.Default()).
		WithWebAuthn(newMockWebAuthnRepo(), "localhost", "Test", []string{"http://localhost:8080"})

	appErr := svc.FinishWebAuthnRegistration(context.Background(), WebAuthnRegisterFinishRequest{
		Subject:  "user-1",
		TenantID: "t1",
		Response: []byte(`{"session_id":"session-1","response":{}}`),
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrExpiredCode, appErr.Code)
}

func TestFinishWebAuthnRegistration_MissingSessionID(t *testing.T) {
	svc := NewService(newMockTOTPRepo(), newMockChallengeRepo(), newTestAuthSvc(), slog.Default()).
		WithWebAuthn(newMockWebAuthnRepo(), "localhost", "Test", []string{"http://localhost:8080"})

	appErr := svc.FinishWebAuthnRegistration(context.Background(), WebAuthnRegisterFinishRequest{
		Subject:  "user-1",
		TenantID: "t1",
		Response: []byte(`{"session_id":"","response":{}}`),
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrBadRequest, appErr.Code)
}

func TestFinishWebAuthnLogin_NotConfigured(t *testing.T) {
	svc := NewService(newMockTOTPRepo(), newMockChallengeRepo(), newTestAuthSvc(), slog.Default())

	appErr := svc.FinishWebAuthnLogin(context.Background(), WebAuthnLoginFinishRequest{
		ChallengeID: "s1",
		Response:  []byte("{}"),
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrBadRequest, appErr.Code)
}

func TestFinishWebAuthnLogin_SessionNotFound(t *testing.T) {
	svc := NewService(newMockTOTPRepo(), newMockChallengeRepo(), newTestAuthSvc(), slog.Default()).
		WithWebAuthn(newMockWebAuthnRepo(), "localhost", "Test", []string{"http://localhost:8080"})

	appErr := svc.FinishWebAuthnLogin(context.Background(), WebAuthnLoginFinishRequest{
		ChallengeID: "nonexistent",
		Response:  []byte("{}"),
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrNotFound, appErr.Code)
}

func TestFinishWebAuthnLogin_ExpiredSession(t *testing.T) {
	challengeRepo := newMockChallengeRepo()
	challengeRepo.challenges["s1"] = domainmfa.MFAChallenge{
		ID:        "s1",
		Subject:   "user-1",
		TenantID:  "t1",
		ExpiresAt: time.Now().UTC().Add(-5 * time.Minute),
		Nonce:     `{"session":{},"subject":"user-1","tenant_id":"t1"}`,
	}

	svc := NewService(newMockTOTPRepo(), challengeRepo, newTestAuthSvc(), slog.Default()).
		WithWebAuthn(newMockWebAuthnRepo(), "localhost", "Test", []string{"http://localhost:8080"})

	appErr := svc.FinishWebAuthnLogin(context.Background(), WebAuthnLoginFinishRequest{
		ChallengeID: "s1",
		Response:  []byte("{}"),
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrExpiredCode, appErr.Code)
}

func TestVerifyMFAWebAuthn_NotConfigured(t *testing.T) {
	svc := NewService(newMockTOTPRepo(), newMockChallengeRepo(), newTestAuthSvc(), slog.Default())

	challenge := domainmfa.MFAChallenge{
		ID: "ch1", Subject: "user-1", TenantID: "t1",
		ExpiresAt: time.Now().UTC().Add(5 * time.Minute),
	}

	appErr := svc.VerifyMFAWebAuthn(context.Background(), challenge, []byte("{}"))

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrBadRequest, appErr.Code)
}

func TestVerifyMFAWebAuthn_NoCredentials(t *testing.T) {
	svc := NewService(newMockTOTPRepo(), newMockChallengeRepo(), newTestAuthSvc(), slog.Default()).
		WithWebAuthn(newMockWebAuthnRepo(), "localhost", "Test", []string{"http://localhost:8080"})

	challenge := domainmfa.MFAChallenge{
		ID: "ch1", Subject: "user-1", TenantID: "t1",
		ExpiresAt: time.Now().UTC().Add(5 * time.Minute),
	}

	appErr := svc.VerifyMFAWebAuthn(context.Background(), challenge, []byte("{}"))

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrBadRequest, appErr.Code)
	assert.Contains(t, appErr.Error(), "no WebAuthn credentials")
}

func TestBeginWebAuthnLogin_WithCredentials(t *testing.T) {
	waRepo := newMockWebAuthnRepo()
	waRepo.creds["c1"] = domainmfa.WebAuthnCredential{
		ID: "c1", Subject: "user-1", TenantID: "t1",
		CredentialID: []byte("cred-id-1"), PublicKey: []byte("pub-key"),
		SignCount: 0,
	}

	svc := NewService(newMockTOTPRepo(), newMockChallengeRepo(), newTestAuthSvc(), slog.Default()).
		WithWebAuthn(waRepo, "localhost", "Test", []string{"http://localhost:8080"})

	resp, appErr := svc.BeginWebAuthnLogin(context.Background(), WebAuthnLoginRequest{
		Subject: "user-1", TenantID: "t1",
	})

	require.Nil(t, appErr)
	// Response is JSON with challenge_id and options
	var parsed map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(resp, &parsed))
	assert.NotEmpty(t, parsed["challenge_id"])
	assert.NotEmpty(t, parsed["options"])
}

func TestFinishWebAuthnLogin_MissingChallengeID(t *testing.T) {
	svc := NewService(newMockTOTPRepo(), newMockChallengeRepo(), newTestAuthSvc(), slog.Default()).
		WithWebAuthn(newMockWebAuthnRepo(), "localhost", "Test", []string{"http://localhost:8080"})

	appErr := svc.FinishWebAuthnLogin(context.Background(), WebAuthnLoginFinishRequest{
		ChallengeID: "",
		Response:    []byte("{}"),
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrBadRequest, appErr.Code)
}

func TestBuildWebAuthnUser_WithCredentials(t *testing.T) {
	waRepo := newMockWebAuthnRepo()
	waRepo.creds["c1"] = domainmfa.WebAuthnCredential{
		ID: "c1", Subject: "user-1", TenantID: "t1",
		CredentialID: []byte("cred-id"), PublicKey: []byte("pub-key"),
		SignCount: 5,
	}

	svc := NewService(newMockTOTPRepo(), newMockChallengeRepo(), newTestAuthSvc(), slog.Default()).
		WithWebAuthn(waRepo, "localhost", "Test", []string{"http://localhost"})

	user, appErr := svc.buildWebAuthnUser(context.Background(), "t1", "user-1", "")
	require.Nil(t, appErr)
	assert.Len(t, user.WebAuthnCredentials(), 1)
	assert.Equal(t, "user-1", user.WebAuthnDisplayName()) // falls back to subject
}

func TestMFASvc_WithAudit(t *testing.T) {
	svc := NewService(newMockTOTPRepo(), newMockChallengeRepo(), newTestAuthSvc(), slog.Default())
	result := svc.WithAudit(nil)
	assert.NotNil(t, result)
}
