package tenant

import "github.com/authplex/internal/domain/tenant"

// CreateTenantRequest is the DTO for creating a new tenant.
type CreateTenantRequest struct {
	ID        string           `json:"id"`
	Domain    string           `json:"domain"`
	Issuer    string           `json:"issuer"`
	Algorithm tenant.Algorithm `json:"algorithm"`
}

// UpdateTenantRequest is the DTO for updating an existing tenant.
type UpdateTenantRequest struct {
	Domain   string                 `json:"domain,omitempty"`
	Issuer   string                 `json:"issuer,omitempty"`
	MFA      *tenant.MFAPolicy      `json:"mfa,omitempty"`
	Settings *tenant.TenantSettings `json:"settings,omitempty"`
}
