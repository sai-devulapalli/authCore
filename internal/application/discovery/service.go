package discovery

import (
	"log/slog"

	"github.com/authplex/internal/domain/oidc"
)

// Service provides OIDC discovery document generation.
type Service struct {
	issuer string
	logger *slog.Logger
}

// NewService creates a new Discovery service.
func NewService(issuer string, logger *slog.Logger) *Service {
	return &Service{
		issuer: issuer,
		logger: logger,
	}
}

// GetDiscoveryDocument returns the OIDC discovery document for the given issuer.
// If tenantIssuer is non-empty, it overrides the default issuer (multi-tenant support).
func (s *Service) GetDiscoveryDocument(tenantIssuer string) oidc.DiscoveryDocument {
	issuer := s.issuer
	if tenantIssuer != "" {
		issuer = tenantIssuer
	}
	s.logger.Debug("generating discovery document", "issuer", issuer)
	return oidc.NewDiscoveryDocument(issuer)
}
