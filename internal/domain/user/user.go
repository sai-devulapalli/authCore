package user

import (
	"strings"
	"time"
)

// User represents a registered user in a tenant.
type User struct {
	ID            string
	TenantID      string
	Email         string
	Phone         string
	PasswordHash  []byte
	Name          string
	EmailVerified bool
	PhoneVerified bool
	Enabled       bool
	TokenVersion  int
	ConsentGranted   bool       // whether user has granted data processing consent
	ConsentTimestamp *time.Time // when consent was last granted/revoked
	CreatedAt        time.Time
	UpdatedAt        time.Time
	DeletedAt        *time.Time
}

// NewUser creates a validated User.
func NewUser(id, tenantID, email, name string) (User, error) {
	if id == "" {
		return User{}, &ValidationError{Field: "id", Message: "must not be empty"}
	}
	if tenantID == "" {
		return User{}, &ValidationError{Field: "tenant_id", Message: "must not be empty"}
	}
	if email == "" {
		return User{}, &ValidationError{Field: "email", Message: "must not be empty"}
	}
	if !isValidEmail(email) {
		return User{}, &ValidationError{Field: "email", Message: "invalid format"}
	}
	if name == "" {
		return User{}, &ValidationError{Field: "name", Message: "must not be empty"}
	}

	now := time.Now().UTC()
	return User{
		ID:            id,
		TenantID:      tenantID,
		Email:         strings.ToLower(strings.TrimSpace(email)),
		Name:          name,
		EmailVerified: false,
		Enabled:       true,
		CreatedAt:     now,
		UpdatedAt:     now,
	}, nil
}

// IsDeleted returns true if the user has been soft-deleted.
func (u User) IsDeleted() bool {
	return u.DeletedAt != nil
}

// IsActive returns true if the user is enabled and not deleted.
func (u User) IsActive() bool {
	return u.Enabled && !u.IsDeleted()
}

// isValidEmail performs a basic email format check.
func isValidEmail(email string) bool {
	at := strings.Index(email, "@")
	dot := strings.LastIndex(email, ".")
	return at > 0 && dot > at+1 && dot < len(email)-1
}
