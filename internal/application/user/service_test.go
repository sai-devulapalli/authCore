package user

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	domainotp "github.com/authcore/internal/domain/otp"
	domainuser "github.com/authcore/internal/domain/user"
	apperrors "github.com/authcore/pkg/sdk/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Mocks ---

type mockUserRepo struct {
	users map[string]domainuser.User
}

func newMockUserRepo() *mockUserRepo {
	return &mockUserRepo{users: make(map[string]domainuser.User)}
}

func (m *mockUserRepo) Create(_ context.Context, u domainuser.User) error {
	for _, existing := range m.users {
		if existing.TenantID == u.TenantID && existing.Email == u.Email {
			return apperrors.New(apperrors.ErrConflict, "email already registered")
		}
	}
	m.users[u.ID] = u
	return nil
}

func (m *mockUserRepo) GetByID(_ context.Context, id, tenantID string) (domainuser.User, error) {
	u, ok := m.users[id]
	if !ok || u.TenantID != tenantID {
		return domainuser.User{}, errors.New("not found")
	}
	return u, nil
}

func (m *mockUserRepo) GetByEmail(_ context.Context, email, tenantID string) (domainuser.User, error) {
	for _, u := range m.users {
		if u.TenantID == tenantID && u.Email == email {
			return u, nil
		}
	}
	return domainuser.User{}, errors.New("not found")
}

func (m *mockUserRepo) GetByPhone(_ context.Context, phone, tenantID string) (domainuser.User, error) {
	for _, u := range m.users {
		if u.TenantID == tenantID && u.Phone == phone && u.Phone != "" {
			return u, nil
		}
	}
	return domainuser.User{}, errors.New("not found")
}

func (m *mockUserRepo) Update(_ context.Context, u domainuser.User) error {
	m.users[u.ID] = u
	return nil
}

func (m *mockUserRepo) HardDelete(_ context.Context, _, _ string) error { return nil }

func (m *mockUserRepo) Delete(_ context.Context, id, _ string) error {
	delete(m.users, id)
	return nil
}

func (m *mockUserRepo) IncrementTokenVersion(_ context.Context, id, _ string) error {
	u, ok := m.users[id]
	if !ok {
		return errors.New("not found")
	}
	u.TokenVersion++
	m.users[id] = u
	return nil
}

type mockSessionRepo struct {
	sessions map[string]domainuser.Session
}

func newMockSessionRepo() *mockSessionRepo {
	return &mockSessionRepo{sessions: make(map[string]domainuser.Session)}
}

func (m *mockSessionRepo) Create(_ context.Context, s domainuser.Session) error {
	m.sessions[s.ID] = s
	return nil
}

func (m *mockSessionRepo) GetByID(_ context.Context, id string) (domainuser.Session, error) {
	s, ok := m.sessions[id]
	if !ok {
		return domainuser.Session{}, errors.New("not found")
	}
	return s, nil
}

func (m *mockSessionRepo) Delete(_ context.Context, id string) error {
	delete(m.sessions, id)
	return nil
}

func (m *mockSessionRepo) DeleteByUserID(_ context.Context, userID string) error {
	for id, s := range m.sessions {
		if s.UserID == userID {
			delete(m.sessions, id)
		}
	}
	return nil
}

type mockHasher struct{}

func (m *mockHasher) Hash(_ string) ([]byte, error)      { return []byte("hashed"), nil }
func (m *mockHasher) Verify(_ string, _ []byte) error { return nil }

type mockHasherFail struct{}

func (m *mockHasherFail) Hash(_ string) ([]byte, error)      { return nil, errors.New("hash failed") }
func (m *mockHasherFail) Verify(_ string, _ []byte) error { return errors.New("mismatch") }

// --- Tests ---

func TestRegister_Success(t *testing.T) {
	svc := NewService(newMockUserRepo(), newMockSessionRepo(), &mockHasher{}, slog.Default())

	resp, appErr := svc.Register(context.Background(), RegisterRequest{
		Email: "user@example.com", Password: "secret123", Name: "Test", TenantID: "t1",
	})

	require.Nil(t, appErr)
	assert.NotEmpty(t, resp.UserID)
	assert.Equal(t, "user@example.com", resp.Email)
}

func TestRegister_WithVerification(t *testing.T) {
	otpRepo := newMockOTPRepo()
	emailSender := &mockEmailSender{}
	svc := NewService(newMockUserRepo(), newMockSessionRepo(), &mockHasher{}, slog.Default()).
		WithOTP(otpRepo, emailSender, &mockSMSSender{})

	resp, appErr := svc.Register(context.Background(), RegisterRequest{
		Email: "user@example.com", Password: "secret123", Name: "Test", TenantID: "t1",
	})

	require.Nil(t, appErr)
	assert.True(t, resp.VerificationSent)
	assert.True(t, emailSender.sent)
}

func TestRegister_WithoutVerification(t *testing.T) {
	svc := NewService(newMockUserRepo(), newMockSessionRepo(), &mockHasher{}, slog.Default())

	resp, appErr := svc.Register(context.Background(), RegisterRequest{
		Email: "user@example.com", Password: "secret123", Name: "Test", TenantID: "t1",
	})

	require.Nil(t, appErr)
	assert.False(t, resp.VerificationSent)
}

func TestRegister_DuplicateEmail(t *testing.T) {
	repo := newMockUserRepo()
	svc := NewService(repo, newMockSessionRepo(), &mockHasher{}, slog.Default())

	svc.Register(context.Background(), RegisterRequest{
		Email: "user@example.com", Password: "pass", Name: "User1", TenantID: "t1",
	})

	_, appErr := svc.Register(context.Background(), RegisterRequest{
		Email: "user@example.com", Password: "pass", Name: "User2", TenantID: "t1",
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrConflict, appErr.Code)
}

func TestRegister_EmptyPassword(t *testing.T) {
	svc := NewService(newMockUserRepo(), newMockSessionRepo(), &mockHasher{}, slog.Default())

	_, appErr := svc.Register(context.Background(), RegisterRequest{
		Email: "a@b.com", Password: "", Name: "Name", TenantID: "t1",
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrBadRequest, appErr.Code)
}

func TestRegister_InvalidEmail(t *testing.T) {
	svc := NewService(newMockUserRepo(), newMockSessionRepo(), &mockHasher{}, slog.Default())

	_, appErr := svc.Register(context.Background(), RegisterRequest{
		Email: "notanemail", Password: "pass", Name: "Name", TenantID: "t1",
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrBadRequest, appErr.Code)
}

func TestRegister_HashError(t *testing.T) {
	svc := NewService(newMockUserRepo(), newMockSessionRepo(), &mockHasherFail{}, slog.Default())

	_, appErr := svc.Register(context.Background(), RegisterRequest{
		Email: "a@b.com", Password: "pass", Name: "Name", TenantID: "t1",
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrInternal, appErr.Code)
}

func TestLogin_Success(t *testing.T) {
	repo := newMockUserRepo()
	svc := NewService(repo, newMockSessionRepo(), &mockHasher{}, slog.Default())

	svc.Register(context.Background(), RegisterRequest{
		Email: "user@example.com", Password: "secret", Name: "User", TenantID: "t1",
	})

	resp, appErr := svc.Login(context.Background(), LoginRequest{
		Email: "user@example.com", Password: "secret", TenantID: "t1",
	})

	require.Nil(t, appErr)
	assert.NotEmpty(t, resp.SessionToken)
	assert.Greater(t, resp.ExpiresIn, 0)
}

func TestLogin_WrongPassword(t *testing.T) {
	repo := newMockUserRepo()
	svc := NewService(repo, newMockSessionRepo(), &mockHasherFail{}, slog.Default())

	// Pre-create a user with mock hasher that passes Hash but fails Verify
	u, _ := domainuser.NewUser("u1", "t1", "user@example.com", "User")
	u.PasswordHash = []byte("hash")
	repo.users["u1"] = u

	_, appErr := svc.Login(context.Background(), LoginRequest{
		Email: "user@example.com", Password: "wrong", TenantID: "t1",
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrUnauthorized, appErr.Code)
}

func TestLogin_UserNotFound(t *testing.T) {
	svc := NewService(newMockUserRepo(), newMockSessionRepo(), &mockHasher{}, slog.Default())

	_, appErr := svc.Login(context.Background(), LoginRequest{
		Email: "nonexistent@example.com", Password: "pass", TenantID: "t1",
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrUnauthorized, appErr.Code)
	assert.Equal(t, "invalid credentials", appErr.Message) // no user enumeration
}

func TestLogin_DisabledUser(t *testing.T) {
	repo := newMockUserRepo()
	u, _ := domainuser.NewUser("u1", "t1", "user@example.com", "User")
	u.PasswordHash = []byte("hash")
	u.Enabled = false
	repo.users["u1"] = u

	svc := NewService(repo, newMockSessionRepo(), &mockHasher{}, slog.Default())

	_, appErr := svc.Login(context.Background(), LoginRequest{
		Email: "user@example.com", Password: "pass", TenantID: "t1",
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrUnauthorized, appErr.Code)
}

func TestLogin_MissingFields(t *testing.T) {
	svc := NewService(newMockUserRepo(), newMockSessionRepo(), &mockHasher{}, slog.Default())

	_, appErr := svc.Login(context.Background(), LoginRequest{TenantID: "t1"})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrBadRequest, appErr.Code)
}

func TestLogout_Success(t *testing.T) {
	sessionRepo := newMockSessionRepo()
	s, _ := domainuser.NewSession("sess-1", "u1", "t1", time.Hour)
	sessionRepo.sessions["sess-1"] = s

	svc := NewService(newMockUserRepo(), sessionRepo, &mockHasher{}, slog.Default())

	appErr := svc.Logout(context.Background(), LogoutRequest{SessionToken: "sess-1"})
	assert.Nil(t, appErr)

	_, err := sessionRepo.GetByID(context.Background(), "sess-1")
	assert.Error(t, err)
}

func TestLogout_EmptyToken(t *testing.T) {
	svc := NewService(newMockUserRepo(), newMockSessionRepo(), &mockHasher{}, slog.Default())
	appErr := svc.Logout(context.Background(), LogoutRequest{})
	assert.Nil(t, appErr) // idempotent
}

func TestResolveSession_Valid(t *testing.T) {
	sessionRepo := newMockSessionRepo()
	s, _ := domainuser.NewSession("sess-1", "u1", "t1", time.Hour)
	sessionRepo.sessions["sess-1"] = s

	svc := NewService(newMockUserRepo(), sessionRepo, &mockHasher{}, slog.Default())

	session, appErr := svc.ResolveSession(context.Background(), "sess-1")
	require.Nil(t, appErr)
	assert.Equal(t, "u1", session.UserID)
}

func TestResolveSession_NotFound(t *testing.T) {
	svc := NewService(newMockUserRepo(), newMockSessionRepo(), &mockHasher{}, slog.Default())

	_, appErr := svc.ResolveSession(context.Background(), "nonexistent")
	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrUnauthorized, appErr.Code)
}

func TestResolveSession_Expired(t *testing.T) {
	sessionRepo := newMockSessionRepo()
	s := domainuser.Session{ID: "sess-1", UserID: "u1", ExpiresAt: time.Now().UTC().Add(-1 * time.Minute)}
	sessionRepo.sessions["sess-1"] = s

	svc := NewService(newMockUserRepo(), sessionRepo, &mockHasher{}, slog.Default())

	_, appErr := svc.ResolveSession(context.Background(), "sess-1")
	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrUnauthorized, appErr.Code)
}

func TestGetUserInfo_Success(t *testing.T) {
	repo := newMockUserRepo()
	u, _ := domainuser.NewUser("u1", "t1", "user@example.com", "Test User")
	u.EmailVerified = true
	repo.users["u1"] = u

	svc := NewService(repo, newMockSessionRepo(), &mockHasher{}, slog.Default())

	info, appErr := svc.GetUserInfo(context.Background(), "u1", "t1")
	require.Nil(t, appErr)
	assert.Equal(t, "u1", info.Subject)
	assert.Equal(t, "user@example.com", info.Email)
	assert.True(t, info.EmailVerified)
	assert.Equal(t, "Test User", info.Name)
}

func TestGetUserInfo_NotFound(t *testing.T) {
	svc := NewService(newMockUserRepo(), newMockSessionRepo(), &mockHasher{}, slog.Default())

	_, appErr := svc.GetUserInfo(context.Background(), "nonexistent", "t1")
	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrNotFound, appErr.Code)
}

func TestValidateCredentials_Success(t *testing.T) {
	repo := newMockUserRepo()
	u, _ := domainuser.NewUser("u1", "t1", "user@example.com", "User")
	u.PasswordHash = []byte("hash")
	repo.users["u1"] = u

	svc := NewService(repo, newMockSessionRepo(), &mockHasher{}, slog.Default())

	subject, err := svc.ValidateCredentials(context.Background(), "t1", "user@example.com", "pass")
	require.NoError(t, err)
	assert.Equal(t, "u1", subject)
}

func TestValidateCredentials_WrongPassword(t *testing.T) {
	repo := newMockUserRepo()
	u, _ := domainuser.NewUser("u1", "t1", "user@example.com", "User")
	u.PasswordHash = []byte("hash")
	repo.users["u1"] = u

	svc := NewService(repo, newMockSessionRepo(), &mockHasherFail{}, slog.Default())

	_, err := svc.ValidateCredentials(context.Background(), "t1", "user@example.com", "wrong")
	require.Error(t, err)
}

func TestValidateCredentials_UserNotFound(t *testing.T) {
	svc := NewService(newMockUserRepo(), newMockSessionRepo(), &mockHasher{}, slog.Default())

	_, err := svc.ValidateCredentials(context.Background(), "t1", "nonexistent@example.com", "pass")
	require.Error(t, err)
}

// --- OTP Mocks ---

type mockOTPRepo struct {
	otps map[string]domainotp.OTP
}

func newMockOTPRepo() *mockOTPRepo {
	return &mockOTPRepo{otps: make(map[string]domainotp.OTP)}
}

func (m *mockOTPRepo) Store(_ context.Context, o domainotp.OTP) error {
	m.otps[o.TenantID+":"+o.Identifier] = o
	return nil
}
func (m *mockOTPRepo) Get(_ context.Context, id, tenantID string) (domainotp.OTP, error) {
	o, ok := m.otps[tenantID+":"+id]
	if !ok {
		return domainotp.OTP{}, errors.New("not found")
	}
	return o, nil
}
func (m *mockOTPRepo) IncrementAttempts(_ context.Context, id, tenantID string) error {
	k := tenantID + ":" + id
	o := m.otps[k]
	o.Attempts++
	m.otps[k] = o
	return nil
}
func (m *mockOTPRepo) Delete(_ context.Context, id, tenantID string) error {
	delete(m.otps, tenantID+":"+id)
	return nil
}

type mockEmailSender struct{ sent bool }

func (m *mockEmailSender) SendOTP(_ context.Context, _, _ string) error {
	m.sent = true
	return nil
}

type mockSMSSender struct{ sent bool }

func (m *mockSMSSender) SendOTP(_ context.Context, _, _ string) error {
	m.sent = true
	return nil
}

func newOTPService() (*Service, *mockOTPRepo, *mockEmailSender) {
	repo := newMockUserRepo()
	u, _ := domainuser.NewUser("u1", "t1", "user@example.com", "User")
	u.PasswordHash = []byte("hash")
	repo.users["u1"] = u

	otpRepo := newMockOTPRepo()
	emailSender := &mockEmailSender{}
	smsSender := &mockSMSSender{}

	svc := NewService(repo, newMockSessionRepo(), &mockHasher{}, slog.Default()).
		WithOTP(otpRepo, emailSender, smsSender)

	return svc, otpRepo, emailSender
}

// --- OTP Tests ---

func TestRequestOTP_Email_Success(t *testing.T) {
	svc, _, emailSender := newOTPService()

	resp, appErr := svc.RequestOTP(context.Background(), RequestOTPRequest{
		Email: "user@example.com", Purpose: "login", TenantID: "t1",
	})

	require.Nil(t, appErr)
	assert.Equal(t, "OTP sent", resp.Message)
	assert.Greater(t, resp.ExpiresIn, 0)
	assert.True(t, emailSender.sent)
}

func TestRequestOTP_MissingIdentifier(t *testing.T) {
	svc, _, _ := newOTPService()

	_, appErr := svc.RequestOTP(context.Background(), RequestOTPRequest{
		Purpose: "login", TenantID: "t1",
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrBadRequest, appErr.Code)
}

func TestRequestOTP_InvalidPurpose(t *testing.T) {
	svc, _, _ := newOTPService()

	_, appErr := svc.RequestOTP(context.Background(), RequestOTPRequest{
		Email: "user@example.com", Purpose: "invalid", TenantID: "t1",
	})

	require.NotNil(t, appErr)
}

func TestRequestOTP_UserNotFound(t *testing.T) {
	svc, _, _ := newOTPService()

	_, appErr := svc.RequestOTP(context.Background(), RequestOTPRequest{
		Email: "nonexistent@example.com", Purpose: "login", TenantID: "t1",
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrNotFound, appErr.Code)
}

func TestRequestOTP_NotConfigured(t *testing.T) {
	svc := NewService(newMockUserRepo(), newMockSessionRepo(), &mockHasher{}, slog.Default())

	_, appErr := svc.RequestOTP(context.Background(), RequestOTPRequest{
		Email: "user@example.com", Purpose: "login", TenantID: "t1",
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrInternal, appErr.Code)
}

func TestVerifyOTP_Success(t *testing.T) {
	svc, otpRepo, _ := newOTPService()

	// Store an OTP
	otpRepo.otps["t1:user@example.com"] = domainotp.OTP{
		Identifier: "user@example.com",
		Code:       "123456",
		TenantID:   "t1",
		ExpiresAt:  time.Now().UTC().Add(5 * time.Minute),
	}

	resp, appErr := svc.VerifyOTP(context.Background(), VerifyOTPRequest{
		Email: "user@example.com", Code: "123456", TenantID: "t1",
	})

	require.Nil(t, appErr)
	assert.NotEmpty(t, resp.SessionToken)
}

func TestVerifyOTP_WrongCode(t *testing.T) {
	svc, otpRepo, _ := newOTPService()

	otpRepo.otps["t1:user@example.com"] = domainotp.OTP{
		Identifier: "user@example.com",
		Code:       "123456",
		TenantID:   "t1",
		ExpiresAt:  time.Now().UTC().Add(5 * time.Minute),
	}

	_, appErr := svc.VerifyOTP(context.Background(), VerifyOTPRequest{
		Email: "user@example.com", Code: "000000", TenantID: "t1",
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrBadRequest, appErr.Code)
}

func TestVerifyOTP_Expired(t *testing.T) {
	svc, otpRepo, _ := newOTPService()

	otpRepo.otps["t1:user@example.com"] = domainotp.OTP{
		Identifier: "user@example.com",
		Code:       "123456",
		TenantID:   "t1",
		ExpiresAt:  time.Now().UTC().Add(-1 * time.Minute),
	}

	_, appErr := svc.VerifyOTP(context.Background(), VerifyOTPRequest{
		Email: "user@example.com", Code: "123456", TenantID: "t1",
	})

	require.NotNil(t, appErr)
}

func TestVerifyOTP_MaxAttempts(t *testing.T) {
	svc, otpRepo, _ := newOTPService()

	otpRepo.otps["t1:user@example.com"] = domainotp.OTP{
		Identifier: "user@example.com",
		Code:       "123456",
		TenantID:   "t1",
		ExpiresAt:  time.Now().UTC().Add(5 * time.Minute),
		Attempts:   5,
	}

	_, appErr := svc.VerifyOTP(context.Background(), VerifyOTPRequest{
		Email: "user@example.com", Code: "123456", TenantID: "t1",
	})

	require.NotNil(t, appErr)
	assert.Contains(t, appErr.Message, "too many")
}

func TestResetPassword_Success(t *testing.T) {
	svc, otpRepo, _ := newOTPService()

	otpRepo.otps["t1:user@example.com"] = domainotp.OTP{
		Identifier: "user@example.com",
		Code:       "123456",
		TenantID:   "t1",
		ExpiresAt:  time.Now().UTC().Add(5 * time.Minute),
	}

	appErr := svc.ResetPassword(context.Background(), ResetPasswordRequest{
		Email: "user@example.com", Code: "123456", NewPassword: "newpass", TenantID: "t1",
	})

	assert.Nil(t, appErr)
}

func TestResetPassword_WrongCode(t *testing.T) {
	svc, otpRepo, _ := newOTPService()

	otpRepo.otps["t1:user@example.com"] = domainotp.OTP{
		Identifier: "user@example.com",
		Code:       "123456",
		TenantID:   "t1",
		ExpiresAt:  time.Now().UTC().Add(5 * time.Minute),
	}

	appErr := svc.ResetPassword(context.Background(), ResetPasswordRequest{
		Email: "user@example.com", Code: "000000", NewPassword: "newpass", TenantID: "t1",
	})

	require.NotNil(t, appErr)
}

func TestResetPassword_MissingPassword(t *testing.T) {
	svc, _, _ := newOTPService()

	appErr := svc.ResetPassword(context.Background(), ResetPasswordRequest{
		Email: "user@example.com", Code: "123456", TenantID: "t1",
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrBadRequest, appErr.Code)
}
