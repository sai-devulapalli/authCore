package handler

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	usersvc "github.com/authplex/internal/application/user"
	domainotp "github.com/authplex/internal/domain/otp"
	domainuser "github.com/authplex/internal/domain/user"
	"github.com/stretchr/testify/assert"
)

// --- Mocks ---

type mockUserHandlerRepo struct {
	users map[string]domainuser.User
}

func newMockUserHandlerRepo() *mockUserHandlerRepo {
	return &mockUserHandlerRepo{users: make(map[string]domainuser.User)}
}

func (m *mockUserHandlerRepo) Create(_ context.Context, u domainuser.User) error {
	m.users[u.ID] = u
	return nil
}
func (m *mockUserHandlerRepo) GetByID(_ context.Context, id, _ string) (domainuser.User, error) {
	u, ok := m.users[id]
	if !ok {
		return domainuser.User{}, errors.New("not found")
	}
	return u, nil
}
func (m *mockUserHandlerRepo) GetByEmail(_ context.Context, email, tenantID string) (domainuser.User, error) {
	for _, u := range m.users {
		if u.Email == email && u.TenantID == tenantID {
			return u, nil
		}
	}
	return domainuser.User{}, errors.New("not found")
}
func (m *mockUserHandlerRepo) GetByPhone(_ context.Context, phone, tenantID string) (domainuser.User, error) {
	for _, u := range m.users {
		if u.Phone == phone && u.TenantID == tenantID {
			return u, nil
		}
	}
	return domainuser.User{}, errors.New("not found")
}
func (m *mockUserHandlerRepo) Update(_ context.Context, u domainuser.User) error {
	m.users[u.ID] = u
	return nil
}
func (m *mockUserHandlerRepo) HardDelete(_ context.Context, _, _ string) error { return nil }

func (m *mockUserHandlerRepo) Delete(_ context.Context, id, _ string) error {
	delete(m.users, id)
	return nil
}

func (m *mockUserHandlerRepo) IncrementTokenVersion(_ context.Context, _, _ string) error {
	return nil
}

func (m *mockUserHandlerRepo) ListByTenant(_ context.Context, _ string, _, _ int) ([]domainuser.User, int, error) {
	var users []domainuser.User
	for _, u := range m.users {
		users = append(users, u)
	}
	return users, len(users), nil
}

type mockUserSessionRepo struct {
	sessions map[string]domainuser.Session
}

func newMockUserSessionRepo() *mockUserSessionRepo {
	return &mockUserSessionRepo{sessions: make(map[string]domainuser.Session)}
}

func (m *mockUserSessionRepo) Create(_ context.Context, s domainuser.Session) error {
	m.sessions[s.ID] = s
	return nil
}
func (m *mockUserSessionRepo) GetByID(_ context.Context, id string) (domainuser.Session, error) {
	s, ok := m.sessions[id]
	if !ok {
		return domainuser.Session{}, errors.New("not found")
	}
	return s, nil
}
func (m *mockUserSessionRepo) Delete(_ context.Context, id string) error {
	delete(m.sessions, id)
	return nil
}
func (m *mockUserSessionRepo) DeleteByUserID(_ context.Context, userID string) error {
	for id, s := range m.sessions {
		if s.UserID == userID {
			delete(m.sessions, id)
		}
	}
	return nil
}

type mockUserHasher struct{}

func (m *mockUserHasher) Hash(_ string) ([]byte, error)      { return []byte("hash"), nil }
func (m *mockUserHasher) Verify(_ string, _ []byte) error { return nil }

func newUserHandler() *UserHandler {
	svc := usersvc.NewService(newMockUserHandlerRepo(), newMockUserSessionRepo(), &mockUserHasher{}, slog.Default())
	return NewUserHandler(svc)
}

// --- Tests ---

func TestUserHandler_Register(t *testing.T) {
	h := newUserHandler()

	body := `{"email":"user@example.com","password":"secret123","name":"Test User"}`
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "t1")
	w := httptest.NewRecorder()

	h.HandleRegister(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Contains(t, w.Body.String(), "user_id")
}

func TestUserHandler_Register_MethodNotAllowed(t *testing.T) {
	h := newUserHandler()

	req := httptest.NewRequest(http.MethodGet, "/register", nil)
	w := httptest.NewRecorder()

	h.HandleRegister(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_Login(t *testing.T) {
	h := newUserHandler()

	// Register first
	body := `{"email":"user@example.com","password":"secret","name":"User"}`
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "t1")
	w := httptest.NewRecorder()
	h.HandleRegister(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)

	// Login
	body = `{"email":"user@example.com","password":"secret"}`
	req = httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "t1")
	w = httptest.NewRecorder()
	h.HandleLogin(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "session_token")
}

func TestUserHandler_Login_BadCredentials(t *testing.T) {
	h := newUserHandler()

	body := `{"email":"nonexistent@example.com","password":"wrong"}`
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.HandleLogin(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_Login_MethodNotAllowed(t *testing.T) {
	h := newUserHandler()

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	w := httptest.NewRecorder()

	h.HandleLogin(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_Logout(t *testing.T) {
	h := newUserHandler()

	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.Header.Set("X-Session-Token", "some-session")
	w := httptest.NewRecorder()

	h.HandleLogout(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "logged_out")
}

func TestUserHandler_Logout_MethodNotAllowed(t *testing.T) {
	h := newUserHandler()

	req := httptest.NewRequest(http.MethodGet, "/logout", nil)
	w := httptest.NewRecorder()

	h.HandleLogout(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_UserInfo_NoSession(t *testing.T) {
	h := newUserHandler()

	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	w := httptest.NewRecorder()

	h.HandleUserInfo(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_UserInfo_WithSession(t *testing.T) {
	userRepo := newMockUserHandlerRepo()
	sessionRepo := newMockUserSessionRepo()

	u, _ := domainuser.NewUser("u1", "t1", "user@example.com", "Test User")
	u.PasswordHash = []byte("hash")
	u.EmailVerified = true
	userRepo.users["u1"] = u

	s, _ := domainuser.NewSession("sess-1", "u1", "t1", time.Hour)
	sessionRepo.sessions["sess-1"] = s

	svc := usersvc.NewService(userRepo, sessionRepo, &mockUserHasher{}, slog.Default())
	h := NewUserHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer sess-1")
	w := httptest.NewRecorder()

	h.HandleUserInfo(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "user@example.com")
	assert.Contains(t, w.Body.String(), "Test User")
}

func TestUserHandler_UserInfo_MethodNotAllowed(t *testing.T) {
	h := newUserHandler()

	req := httptest.NewRequest(http.MethodPost, "/userinfo", nil)
	w := httptest.NewRecorder()

	h.HandleUserInfo(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- OTP Handler Tests ---

func newOTPUserHandler() *UserHandler {
	repo := newMockUserHandlerRepo()
	u, _ := domainuser.NewUser("u1", "t1", "user@example.com", "User")
	u.PasswordHash = []byte("hash")
	repo.users["u1"] = u

	svc := usersvc.NewService(repo, newMockUserSessionRepo(), &mockUserHasher{}, slog.Default())

	// We can't easily wire OTP here without more mocks — test method guards instead
	return NewUserHandler(svc)
}

func TestUserHandler_RequestOTP_MethodNotAllowed(t *testing.T) {
	h := newOTPUserHandler()
	req := httptest.NewRequest(http.MethodGet, "/otp/request", nil)
	w := httptest.NewRecorder()
	h.HandleRequestOTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_RequestOTP_NotConfigured(t *testing.T) {
	h := newOTPUserHandler()
	body := `{"email":"user@example.com","purpose":"login"}`
	req := httptest.NewRequest(http.MethodPost, "/otp/request", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "t1")
	w := httptest.NewRecorder()
	h.HandleRequestOTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestUserHandler_VerifyOTP_MethodNotAllowed(t *testing.T) {
	h := newOTPUserHandler()
	req := httptest.NewRequest(http.MethodGet, "/otp/verify", nil)
	w := httptest.NewRecorder()
	h.HandleVerifyOTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_ResetPassword_MethodNotAllowed(t *testing.T) {
	h := newOTPUserHandler()
	req := httptest.NewRequest(http.MethodGet, "/password/reset", nil)
	w := httptest.NewRecorder()
	h.HandleResetPassword(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_ResetPassword_NotConfigured(t *testing.T) {
	h := newOTPUserHandler()
	body := `{"email":"user@example.com","code":"123456","new_password":"newpass"}`
	req := httptest.NewRequest(http.MethodPost, "/password/reset", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "t1")
	w := httptest.NewRecorder()
	h.HandleResetPassword(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// --- OTP with real service ---

type mockOTPRepo struct{ otps map[string]string }

func (m *mockOTPRepo) Store(_ context.Context, o domainotp.OTP) error {
	m.otps[o.TenantID+":"+o.Identifier] = o.Code
	return nil
}
func (m *mockOTPRepo) Get(_ context.Context, id, tid string) (domainotp.OTP, error) {
	code, ok := m.otps[tid+":"+id]
	if !ok {
		return domainotp.OTP{}, errors.New("not found")
	}
	return domainotp.OTP{Code: code, ExpiresAt: time.Now().UTC().Add(5 * time.Minute)}, nil
}
func (m *mockOTPRepo) IncrementAttempts(_ context.Context, _, _ string) error { return nil }
func (m *mockOTPRepo) Delete(_ context.Context, id, tid string) error {
	delete(m.otps, tid+":"+id)
	return nil
}

type mockOTPEmailSender struct{}

func (m *mockOTPEmailSender) SendOTP(_ context.Context, _, _ string) error { return nil }

type mockOTPSMSSender struct{}

func (m *mockOTPSMSSender) SendOTP(_ context.Context, _, _ string) error { return nil }

func newOTPConfiguredHandler() *UserHandler {
	repo := newMockUserHandlerRepo()
	u, _ := domainuser.NewUser("u1", "t1", "user@example.com", "User")
	u.PasswordHash = []byte("hash")
	repo.users["u1"] = u

	otpRepo := &mockOTPRepo{otps: make(map[string]string)}
	svc := usersvc.NewService(repo, newMockUserSessionRepo(), &mockUserHasher{}, slog.Default()).
		WithOTP(otpRepo, &mockOTPEmailSender{}, &mockOTPSMSSender{})

	return NewUserHandler(svc)
}

func TestUserHandler_RequestOTP_Configured(t *testing.T) {
	h := newOTPConfiguredHandler()
	body := `{"email":"user@example.com","purpose":"login"}`
	req := httptest.NewRequest(http.MethodPost, "/otp/request", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "t1")
	w := httptest.NewRecorder()
	h.HandleRequestOTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "OTP sent")
}

func TestUserHandler_VerifyOTP_NotConfigured(t *testing.T) {
	h := newOTPUserHandler()
	body := `{"email":"user@example.com","code":"123456"}`
	req := httptest.NewRequest(http.MethodPost, "/otp/verify", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "t1")
	w := httptest.NewRecorder()
	h.HandleVerifyOTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestExtractSessionToken_Bearer(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer my-session-token")

	assert.Equal(t, "my-session-token", extractSessionToken(req))
}

func TestExtractSessionToken_Header(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Session-Token", "my-session-token")

	assert.Equal(t, "my-session-token", extractSessionToken(req))
}

func TestExtractSessionToken_Empty(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	assert.Empty(t, extractSessionToken(req))
}

func TestUserHandler_HandleListUsers_Success(t *testing.T) {
	userRepo := newMockUserHandlerRepo()
	u, _ := domainuser.NewUser("u1", "t1", "user@example.com", "Test User")
	u.PasswordHash = []byte("hash")
	userRepo.users["u1"] = u

	svc := usersvc.NewService(userRepo, newMockUserSessionRepo(), &mockUserHasher{}, slog.Default())
	h := NewUserHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/tenants/t1/users", nil)
	w := httptest.NewRecorder()

	h.HandleListUsers(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "users")
	assert.Contains(t, w.Body.String(), "count")
}

func TestUserHandler_HandleListUsers_MissingTenant(t *testing.T) {
	h := newUserHandler()

	req := httptest.NewRequest(http.MethodGet, "/users", nil)
	w := httptest.NewRecorder()

	h.HandleListUsers(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_HandleListUsers_MethodNotAllowed(t *testing.T) {
	h := newUserHandler()

	req := httptest.NewRequest(http.MethodPost, "/tenants/t1/users", nil)
	w := httptest.NewRecorder()

	h.HandleListUsers(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}
