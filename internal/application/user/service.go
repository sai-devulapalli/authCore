package user

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"log/slog"
	"strings"
	"time"

	auditsvc "github.com/authplex/internal/application/audit"
	domainaudit "github.com/authplex/internal/domain/audit"
	domainotp "github.com/authplex/internal/domain/otp"
	domainuser "github.com/authplex/internal/domain/user"
	apperrors "github.com/authplex/pkg/sdk/errors"
)

// Service provides user management and authentication operations.
type Service struct {
	userRepo    domainuser.Repository
	sessionRepo domainuser.SessionRepository
	hasher      domainuser.PasswordHasher
	otpRepo     domainotp.Repository
	emailSender domainotp.EmailSender
	smsSender   domainotp.SMSSender
	auditSvc    *auditsvc.Service
	logger      *slog.Logger
	sessionTTL  time.Duration
	otpTTL      time.Duration
}

// WithAudit configures audit event logging.
func (s *Service) WithAudit(a *auditsvc.Service) *Service {
	s.auditSvc = a
	return s
}

// NewService creates a new user service.
func NewService(
	userRepo domainuser.Repository,
	sessionRepo domainuser.SessionRepository,
	hasher domainuser.PasswordHasher,
	logger *slog.Logger,
) *Service {
	return &Service{
		userRepo:    userRepo,
		sessionRepo: sessionRepo,
		hasher:      hasher,
		logger:      logger,
		sessionTTL:  24 * time.Hour,
		otpTTL:      5 * time.Minute,
	}
}

// WithOTP configures OTP support.
func (s *Service) WithOTP(repo domainotp.Repository, email domainotp.EmailSender, sms domainotp.SMSSender) *Service {
	s.otpRepo = repo
	s.emailSender = email
	s.smsSender = sms
	return s
}

// Register creates a new user.
func (s *Service) Register(ctx context.Context, req RegisterRequest) (RegisterResponse, *apperrors.AppError) {
	if req.Password == "" {
		return RegisterResponse{}, apperrors.New(apperrors.ErrBadRequest, "password is required")
	}

	id, err := generateID()
	if err != nil {
		return RegisterResponse{}, apperrors.Wrap(apperrors.ErrInternal, "failed to generate user ID", err)
	}

	u, valErr := domainuser.NewUser(id, req.TenantID, req.Email, req.Name)
	if valErr != nil {
		return RegisterResponse{}, apperrors.Wrap(apperrors.ErrBadRequest, "invalid user", valErr)
	}

	if req.Phone != "" {
		u.Phone = strings.TrimSpace(req.Phone)
	}

	hash, hashErr := s.hasher.Hash(req.Password)
	if hashErr != nil {
		return RegisterResponse{}, apperrors.Wrap(apperrors.ErrInternal, "failed to hash password", hashErr)
	}
	u.PasswordHash = hash

	if createErr := s.userRepo.Create(ctx, u); createErr != nil {
		return RegisterResponse{}, apperrors.Wrap(apperrors.ErrConflict, "registration failed", createErr)
	}

	s.logger.Info("user registered", "user_id", u.ID, "tenant_id", u.TenantID)
	if s.auditSvc != nil {
		s.auditSvc.Log(ctx, req.TenantID, u.ID, "user", domainaudit.EventRegister, "user", u.ID, nil, nil)
	}

	// Auto-send verification OTP if email sender is configured
	if s.otpRepo != nil && s.emailSender != nil {
		s.RequestOTP(ctx, RequestOTPRequest{ //nolint:errcheck
			Email:    u.Email,
			Purpose:  "verify",
			TenantID: req.TenantID,
		})
	}

	return RegisterResponse{
		UserID:             u.ID,
		Email:              u.Email,
		VerificationSent:   s.emailSender != nil,
	}, nil
}

// Login verifies credentials and creates a session.
func (s *Service) Login(ctx context.Context, req LoginRequest) (LoginResponse, *apperrors.AppError) {
	if req.Email == "" || req.Password == "" {
		return LoginResponse{}, apperrors.New(apperrors.ErrBadRequest, "email and password are required")
	}

	u, err := s.userRepo.GetByEmail(ctx, req.Email, req.TenantID)
	if err != nil {
		// Don't reveal whether user exists (prevents enumeration)
		return LoginResponse{}, apperrors.New(apperrors.ErrUnauthorized, "invalid credentials")
	}

	if !u.IsActive() {
		return LoginResponse{}, apperrors.New(apperrors.ErrUnauthorized, "invalid credentials")
	}

	if verifyErr := s.hasher.Verify(req.Password, u.PasswordHash); verifyErr != nil {
		if s.auditSvc != nil {
			s.auditSvc.Log(ctx, req.TenantID, u.ID, "user", domainaudit.EventLoginFailure, "user", u.ID, nil, nil)
		}
		return LoginResponse{}, apperrors.New(apperrors.ErrUnauthorized, "invalid credentials")
	}

	sessionID, err := generateID()
	if err != nil {
		return LoginResponse{}, apperrors.Wrap(apperrors.ErrInternal, "failed to generate session", err)
	}

	session, valErr := domainuser.NewSession(sessionID, u.ID, u.TenantID, s.sessionTTL)
	if valErr != nil {
		return LoginResponse{}, apperrors.Wrap(apperrors.ErrInternal, "failed to create session", valErr)
	}

	if storeErr := s.sessionRepo.Create(ctx, session); storeErr != nil {
		return LoginResponse{}, apperrors.Wrap(apperrors.ErrInternal, "failed to store session", storeErr)
	}

	s.logger.Info("user logged in", "user_id", u.ID, "tenant_id", u.TenantID)
	if s.auditSvc != nil {
		s.auditSvc.Log(ctx, req.TenantID, u.ID, "user", domainaudit.EventLoginSuccess, "user", u.ID, nil, nil)
	}

	return LoginResponse{
		SessionToken: sessionID,
		ExpiresIn:    int(s.sessionTTL.Seconds()),
	}, nil
}

// Logout invalidates a session.
func (s *Service) Logout(ctx context.Context, req LogoutRequest) *apperrors.AppError {
	if req.SessionToken == "" {
		return nil // idempotent
	}
	s.sessionRepo.Delete(ctx, req.SessionToken) //nolint:errcheck
	s.logger.Info("user logged out")
	if s.auditSvc != nil {
		s.auditSvc.Log(ctx, "", "", "user", domainaudit.EventSessionRevoked, "session", req.SessionToken, nil, nil)
	}
	return nil
}

// ResolveSession validates a session token and returns the session.
func (s *Service) ResolveSession(ctx context.Context, sessionToken string) (domainuser.Session, *apperrors.AppError) {
	session, err := s.sessionRepo.GetByID(ctx, sessionToken)
	if err != nil {
		return domainuser.Session{}, apperrors.New(apperrors.ErrUnauthorized, "invalid session")
	}
	if session.IsExpired() {
		s.sessionRepo.Delete(ctx, sessionToken) //nolint:errcheck
		return domainuser.Session{}, apperrors.New(apperrors.ErrUnauthorized, "session expired")
	}
	return session, nil
}

// GetUserInfo returns OIDC UserInfo claims for a user.
func (s *Service) GetUserInfo(ctx context.Context, userID, tenantID string) (UserInfoResponse, *apperrors.AppError) {
	u, err := s.userRepo.GetByID(ctx, userID, tenantID)
	if err != nil {
		return UserInfoResponse{}, apperrors.Wrap(apperrors.ErrNotFound, "user not found", err)
	}

	return UserInfoResponse{
		Subject:       u.ID,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		Phone:         u.Phone,
		PhoneVerified: u.PhoneVerified,
		Name:          u.Name,
	}, nil
}

// RequestOTP generates and sends a one-time password.
func (s *Service) RequestOTP(ctx context.Context, req RequestOTPRequest) (RequestOTPResponse, *apperrors.AppError) {
	if s.otpRepo == nil {
		return RequestOTPResponse{}, apperrors.New(apperrors.ErrInternal, "OTP not configured")
	}
	if req.Email == "" && req.Phone == "" {
		return RequestOTPResponse{}, apperrors.New(apperrors.ErrBadRequest, "email or phone is required")
	}
	if !domainotp.IsValidPurpose(req.Purpose) {
		return RequestOTPResponse{}, apperrors.New(apperrors.ErrBadRequest, "purpose must be login, verify, or reset")
	}

	// Determine channel and identifier
	var identifier string
	var channel domainotp.Channel

	if req.Email != "" {
		identifier = strings.ToLower(strings.TrimSpace(req.Email))
		channel = domainotp.ChannelEmail
		// Verify user exists (except for verify purpose — user might not exist yet for phone verify)
		if req.Purpose != "verify" {
			if _, err := s.userRepo.GetByEmail(ctx, identifier, req.TenantID); err != nil {
				return RequestOTPResponse{}, apperrors.New(apperrors.ErrNotFound, "user not found")
			}
		}
	} else {
		identifier = strings.TrimSpace(req.Phone)
		channel = domainotp.ChannelSMS
		if req.Purpose != "verify" {
			if _, err := s.userRepo.GetByPhone(ctx, identifier, req.TenantID); err != nil {
				return RequestOTPResponse{}, apperrors.New(apperrors.ErrNotFound, "user not found")
			}
		}
	}

	code, genErr := domainotp.GenerateCode()
	if genErr != nil {
		return RequestOTPResponse{}, apperrors.Wrap(apperrors.ErrInternal, "failed to generate OTP", genErr)
	}

	o := domainotp.OTP{
		Identifier: identifier,
		Code:       code,
		Channel:    channel,
		Purpose:    domainotp.Purpose(req.Purpose),
		TenantID:   req.TenantID,
		ExpiresAt:  time.Now().UTC().Add(s.otpTTL),
	}

	if storeErr := s.otpRepo.Store(ctx, o); storeErr != nil {
		return RequestOTPResponse{}, apperrors.Wrap(apperrors.ErrInternal, "failed to store OTP", storeErr)
	}

	// Send via appropriate channel
	if channel == domainotp.ChannelEmail && s.emailSender != nil {
		if sendErr := s.emailSender.SendOTP(ctx, identifier, code); sendErr != nil {
			return RequestOTPResponse{}, apperrors.Wrap(apperrors.ErrInternal, "failed to send email OTP", sendErr)
		}
	} else if channel == domainotp.ChannelSMS && s.smsSender != nil {
		if sendErr := s.smsSender.SendOTP(ctx, identifier, code); sendErr != nil {
			return RequestOTPResponse{}, apperrors.Wrap(apperrors.ErrInternal, "failed to send SMS OTP", sendErr)
		}
	}

	s.logger.Info("OTP sent", "channel", channel, "identifier", identifier, "purpose", req.Purpose)
	if s.auditSvc != nil {
		s.auditSvc.Log(ctx, req.TenantID, identifier, "user", domainaudit.EventOTPRequested, "otp", identifier, nil, nil)
	}

	return RequestOTPResponse{
		Message:   "OTP sent",
		ExpiresIn: int(s.otpTTL.Seconds()),
	}, nil
}

// VerifyOTP verifies a one-time password and creates a session.
func (s *Service) VerifyOTP(ctx context.Context, req VerifyOTPRequest) (LoginResponse, *apperrors.AppError) {
	if s.otpRepo == nil {
		return LoginResponse{}, apperrors.New(apperrors.ErrInternal, "OTP not configured")
	}
	if req.Code == "" {
		return LoginResponse{}, apperrors.New(apperrors.ErrBadRequest, "code is required")
	}

	identifier := strings.ToLower(strings.TrimSpace(req.Email))
	if identifier == "" {
		identifier = strings.TrimSpace(req.Phone)
	}
	if identifier == "" {
		return LoginResponse{}, apperrors.New(apperrors.ErrBadRequest, "email or phone is required")
	}

	// Get stored OTP
	stored, getErr := s.otpRepo.Get(ctx, identifier, req.TenantID)
	if getErr != nil {
		return LoginResponse{}, apperrors.New(apperrors.ErrBadRequest, "invalid or expired OTP")
	}

	if stored.IsExpired() {
		s.otpRepo.Delete(ctx, identifier, req.TenantID) //nolint:errcheck
		return LoginResponse{}, apperrors.New(apperrors.ErrBadRequest, "OTP has expired")
	}

	if stored.MaxAttemptsExceeded() {
		s.otpRepo.Delete(ctx, identifier, req.TenantID) //nolint:errcheck
		return LoginResponse{}, apperrors.New(apperrors.ErrBadRequest, "too many failed attempts")
	}

	if stored.Code != req.Code {
		s.otpRepo.IncrementAttempts(ctx, identifier, req.TenantID) //nolint:errcheck
		return LoginResponse{}, apperrors.New(apperrors.ErrBadRequest, "invalid OTP code")
	}

	// OTP verified — delete it
	s.otpRepo.Delete(ctx, identifier, req.TenantID) //nolint:errcheck

	// Find user and mark channel as verified
	var u domainuser.User
	var err error
	if req.Email != "" {
		u, err = s.userRepo.GetByEmail(ctx, identifier, req.TenantID)
	} else {
		u, err = s.userRepo.GetByPhone(ctx, identifier, req.TenantID)
	}
	if err != nil {
		return LoginResponse{}, apperrors.New(apperrors.ErrNotFound, "user not found")
	}

	// Mark as verified
	if req.Email != "" && !u.EmailVerified {
		u.EmailVerified = true
		s.userRepo.Update(ctx, u) //nolint:errcheck
	}
	if req.Phone != "" && !u.PhoneVerified {
		u.PhoneVerified = true
		s.userRepo.Update(ctx, u) //nolint:errcheck
	}

	// Create session
	sessionID, err := generateID()
	if err != nil {
		return LoginResponse{}, apperrors.Wrap(apperrors.ErrInternal, "failed to generate session", err)
	}

	session, valErr := domainuser.NewSession(sessionID, u.ID, u.TenantID, s.sessionTTL)
	if valErr != nil {
		return LoginResponse{}, apperrors.Wrap(apperrors.ErrInternal, "failed to create session", valErr)
	}

	if storeErr := s.sessionRepo.Create(ctx, session); storeErr != nil {
		return LoginResponse{}, apperrors.Wrap(apperrors.ErrInternal, "failed to store session", storeErr)
	}

	s.logger.Info("OTP verified, session created", "user_id", u.ID)
	if s.auditSvc != nil {
		s.auditSvc.Log(ctx, req.TenantID, u.ID, "user", domainaudit.EventOTPVerified, "user", u.ID, nil, nil)
	}

	return LoginResponse{
		SessionToken: sessionID,
		ExpiresIn:    int(s.sessionTTL.Seconds()),
	}, nil
}

// ResetPassword resets a user's password after OTP verification.
func (s *Service) ResetPassword(ctx context.Context, req ResetPasswordRequest) *apperrors.AppError {
	if s.otpRepo == nil {
		return apperrors.New(apperrors.ErrInternal, "OTP not configured")
	}
	if req.NewPassword == "" {
		return apperrors.New(apperrors.ErrBadRequest, "new_password is required")
	}
	if req.Code == "" {
		return apperrors.New(apperrors.ErrBadRequest, "code is required")
	}

	identifier := strings.ToLower(strings.TrimSpace(req.Email))
	if identifier == "" {
		identifier = strings.TrimSpace(req.Phone)
	}
	if identifier == "" {
		return apperrors.New(apperrors.ErrBadRequest, "email or phone is required")
	}

	// Verify OTP
	stored, getErr := s.otpRepo.Get(ctx, identifier, req.TenantID)
	if getErr != nil {
		return apperrors.New(apperrors.ErrBadRequest, "invalid or expired OTP")
	}
	if stored.IsExpired() || stored.Code != req.Code {
		return apperrors.New(apperrors.ErrBadRequest, "invalid or expired OTP")
	}

	s.otpRepo.Delete(ctx, identifier, req.TenantID) //nolint:errcheck

	// Find user
	var u domainuser.User
	var err error
	if req.Email != "" {
		u, err = s.userRepo.GetByEmail(ctx, identifier, req.TenantID)
	} else {
		u, err = s.userRepo.GetByPhone(ctx, identifier, req.TenantID)
	}
	if err != nil {
		return apperrors.New(apperrors.ErrNotFound, "user not found")
	}

	// Hash new password
	hash, hashErr := s.hasher.Hash(req.NewPassword)
	if hashErr != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to hash password", hashErr)
	}

	u.PasswordHash = hash
	u.UpdatedAt = time.Now().UTC()
	if updateErr := s.userRepo.Update(ctx, u); updateErr != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to update password", updateErr)
	}

	s.logger.Info("password reset", "user_id", u.ID)
	if s.auditSvc != nil {
		s.auditSvc.Log(ctx, req.TenantID, u.ID, "user", domainaudit.EventPasswordReset, "user", u.ID, nil, nil)
	}
	return nil
}

// ListUsers returns a paginated list of users for a tenant.
func (s *Service) ListUsers(ctx context.Context, tenantID string, offset, limit int) ([]UserSummary, int, *apperrors.AppError) {
	if tenantID == "" {
		return nil, 0, apperrors.New(apperrors.ErrBadRequest, "tenant_id is required")
	}
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}

	users, total, err := s.userRepo.ListByTenant(ctx, tenantID, offset, limit)
	if err != nil {
		return nil, 0, apperrors.Wrap(apperrors.ErrInternal, "failed to list users", err)
	}

	summaries := make([]UserSummary, len(users))
	for i, u := range users {
		summaries[i] = UserSummary{
			ID:            u.ID,
			Email:         u.Email,
			Name:          u.Name,
			Phone:         u.Phone,
			EmailVerified: u.EmailVerified,
			Enabled:       u.Enabled,
			CreatedAt:     u.CreatedAt,
		}
	}
	return summaries, total, nil
}

// ValidateCredentials implements token.UserValidator for the password grant.
func (s *Service) ValidateCredentials(ctx context.Context, tenantID, username, password string) (string, error) {
	u, err := s.userRepo.GetByEmail(ctx, username, tenantID)
	if err != nil {
		return "", apperrors.New(apperrors.ErrUnauthorized, "invalid credentials")
	}
	if !u.IsActive() {
		return "", apperrors.New(apperrors.ErrUnauthorized, "invalid credentials")
	}
	if verifyErr := s.hasher.Verify(password, u.PasswordHash); verifyErr != nil {
		return "", apperrors.New(apperrors.ErrUnauthorized, "invalid credentials")
	}
	return u.ID, nil
}

func generateID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
