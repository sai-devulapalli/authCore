package tenant

import "time"

// Algorithm represents a JWT signing algorithm.
type Algorithm string

const (
	RS256 Algorithm = "RS256"
	ES256 Algorithm = "ES256"
)

// SigningConfig holds the tenant's JWT signing configuration.
type SigningConfig struct {
	Algorithm   Algorithm
	ActiveKeyID string
}

// MFAPolicy defines the MFA configuration for a tenant.
type MFAPolicy struct {
	Required string   `json:"required"` // "none", "optional", "required"
	Methods  []string `json:"methods"`  // e.g., ["totp"]
}

// IsMFARequired returns true if MFA is required for this tenant.
func (p MFAPolicy) IsMFARequired() bool {
	return p.Required == "required"
}

// TenantSettings holds per-tenant configuration.
type TenantSettings struct {
	SessionTTL               int      `json:"session_ttl"`                // seconds, default 86400 (24h)
	AccessTokenTTL           int      `json:"access_token_ttl"`           // seconds, default 3600 (1h)
	RefreshTokenTTL          int      `json:"refresh_token_ttl"`          // seconds, default 2592000 (30d)
	PasswordMinLength        int      `json:"password_min_length"`        // default 8
	PasswordRequireUppercase bool     `json:"password_require_uppercase"`
	PasswordRequireNumber    bool     `json:"password_require_number"`
	PasswordRequireSpecial   bool     `json:"password_require_special"`
	AllowedOrigins           []string `json:"allowed_origins"`            // CORS per tenant
	MaxLoginAttempts         int      `json:"max_login_attempts"`         // 0 = unlimited
	LockoutDuration          int      `json:"lockout_duration"`           // seconds
	AgentRateLimit           int      `json:"agent_rate_limit"`           // requests per minute for M2M clients, 0 = use global

	// SMTP per-tenant override (empty = use global config)
	SMTPHost     string `json:"smtp_host"`
	SMTPPort     int    `json:"smtp_port"`
	SMTPUsername string `json:"smtp_username"`
	SMTPPassword string `json:"smtp_password"`
	SMTPFrom     string `json:"smtp_from"`
}

// DefaultSettings returns the default tenant settings.
func DefaultSettings() TenantSettings {
	return TenantSettings{
		SessionTTL:        86400,
		AccessTokenTTL:    3600,
		RefreshTokenTTL:   2592000,
		PasswordMinLength: 8,
		MaxLoginAttempts:  0,
	}
}

// Tenant represents an isolated identity provider tenant.
type Tenant struct {
	ID            string
	Domain        string
	Issuer        string
	SigningConfig SigningConfig
	MFA           MFAPolicy
	Settings      TenantSettings
	TokenVersion  int
	CreatedAt     time.Time
	UpdatedAt     time.Time
	DeletedAt     *time.Time
}

// IsDeleted returns true if the tenant has been soft-deleted.
func (t Tenant) IsDeleted() bool {
	return t.DeletedAt != nil
}

// NewTenant creates a new Tenant with the given parameters.
// Validates required fields and returns an error if invalid.
func NewTenant(id, domain, issuer string, alg Algorithm) (Tenant, error) {
	if id == "" {
		return Tenant{}, &ValidationError{Field: "id", Message: "must not be empty"}
	}
	if domain == "" {
		return Tenant{}, &ValidationError{Field: "domain", Message: "must not be empty"}
	}
	if issuer == "" {
		return Tenant{}, &ValidationError{Field: "issuer", Message: "must not be empty"}
	}
	switch alg {
	case RS256, ES256:
		// valid
	default:
		return Tenant{}, &ValidationError{Field: "algorithm", Message: "must be RS256 or ES256"}
	}

	now := time.Now().UTC()
	return Tenant{
		ID:     id,
		Domain: domain,
		Issuer: issuer,
		SigningConfig: SigningConfig{
			Algorithm: alg,
		},
		Settings:     DefaultSettings(),
		TokenVersion: 1,
		CreatedAt:    now,
		UpdatedAt:    now,
	}, nil
}
