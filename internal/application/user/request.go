package user

import "time"

// RegisterRequest is the DTO for user registration.
type RegisterRequest struct {
	Email    string `json:"email"`
	Phone    string `json:"phone,omitempty"`
	Password string `json:"password"`
	Name     string `json:"name"`
	TenantID string `json:"-"`
}

// RegisterResponse is returned after registration.
type RegisterResponse struct {
	UserID           string `json:"user_id"`
	Email            string `json:"email"`
	VerificationSent bool   `json:"verification_sent"`
}

// LoginRequest is the DTO for user login.
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	TenantID string `json:"-"`
}

// LoginResponse is returned after login.
type LoginResponse struct {
	SessionToken string `json:"session_token"`
	ExpiresIn    int    `json:"expires_in"`
}

// LogoutRequest is the DTO for logout.
type LogoutRequest struct {
	SessionToken string `json:"-"`
}

// UserInfoResponse is the OIDC UserInfo response (RFC 5765).
type UserInfoResponse struct {
	Subject       string `json:"sub"`
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified"`
	Phone         string `json:"phone_number,omitempty"`
	PhoneVerified bool   `json:"phone_number_verified,omitempty"`
	Name          string `json:"name,omitempty"`
}

// RequestOTPRequest is the DTO for requesting an OTP.
type RequestOTPRequest struct {
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	Purpose  string `json:"purpose"` // "login", "verify", "reset"
	TenantID string `json:"-"`
}

// RequestOTPResponse is returned after sending an OTP.
type RequestOTPResponse struct {
	Message   string `json:"message"`
	ExpiresIn int    `json:"expires_in"`
}

// VerifyOTPRequest is the DTO for verifying an OTP.
type VerifyOTPRequest struct {
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	Code     string `json:"code"`
	TenantID string `json:"-"`
}

// ResetPasswordRequest is the DTO for resetting a password via OTP.
type ResetPasswordRequest struct {
	Email       string `json:"email"`
	Phone       string `json:"phone"`
	Code        string `json:"code"`
	NewPassword string `json:"new_password"`
	TenantID    string `json:"-"`
}

// UserSummary is a safe representation of a user for listing (no password hash).
type UserSummary struct {
	ID            string    `json:"id"`
	Email         string    `json:"email"`
	Name          string    `json:"name"`
	Phone         string    `json:"phone,omitempty"`
	EmailVerified bool      `json:"email_verified"`
	Enabled       bool      `json:"enabled"`
	CreatedAt     time.Time `json:"created_at"`
}
