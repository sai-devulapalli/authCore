package provider

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"log/slog"

	auditsvc "github.com/authplex/internal/application/audit"
	domainaudit "github.com/authplex/internal/domain/audit"
	"github.com/authplex/internal/domain/identity"
	apperrors "github.com/authplex/pkg/sdk/errors"
)

// Service provides identity provider management operations.
type Service struct {
	repo     identity.ProviderRepository
	auditSvc *auditsvc.Service
	logger   *slog.Logger
}

// WithAudit configures audit event logging.
func (s *Service) WithAudit(a *auditsvc.Service) *Service {
	s.auditSvc = a
	return s
}

// NewService creates a new provider management service.
func NewService(repo identity.ProviderRepository, logger *slog.Logger) *Service {
	return &Service{repo: repo, logger: logger}
}

// Create registers a new identity provider for a tenant.
func (s *Service) Create(ctx context.Context, req CreateProviderRequest) (ProviderResponse, *apperrors.AppError) {
	id, err := generateID()
	if err != nil {
		return ProviderResponse{}, apperrors.Wrap(apperrors.ErrInternal, "failed to generate provider ID", err)
	}

	p, valErr := identity.NewIdentityProvider(id, req.TenantID,
		identity.ProviderType(req.ProviderType), req.ClientID, []byte(req.ClientSecret), req.Scopes)
	if valErr != nil {
		return ProviderResponse{}, apperrors.Wrap(apperrors.ErrBadRequest, "invalid provider", valErr)
	}

	p.DiscoveryURL = req.DiscoveryURL
	p.AuthURL = req.AuthURL
	p.TokenURL = req.TokenURL
	p.UserInfoURL = req.UserInfoURL
	if req.ExtraConfig != nil {
		p.ExtraConfig = req.ExtraConfig
	}

	if err := s.repo.Create(ctx, p); err != nil {
		return ProviderResponse{}, apperrors.Wrap(apperrors.ErrInternal, "failed to create provider", err)
	}

	s.logger.Info("identity provider created", "provider_id", p.ID, "type", p.ProviderType, "tenant_id", p.TenantID)
	if s.auditSvc != nil {
		s.auditSvc.Log(ctx, req.TenantID, "system", "system", domainaudit.EventProviderCreated, "provider", p.ID, nil, nil)
	}
	return toResponse(p), nil
}

// Get returns a provider by ID.
func (s *Service) Get(ctx context.Context, id, tenantID string) (ProviderResponse, *apperrors.AppError) {
	p, err := s.repo.GetByID(ctx, id, tenantID)
	if err != nil {
		return ProviderResponse{}, apperrors.Wrap(apperrors.ErrNotFound, "provider not found", err)
	}
	return toResponse(p), nil
}

// List returns all providers for a tenant.
func (s *Service) List(ctx context.Context, tenantID string) ([]ProviderResponse, *apperrors.AppError) {
	providers, err := s.repo.List(ctx, tenantID)
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrInternal, "failed to list providers", err)
	}
	responses := make([]ProviderResponse, len(providers))
	for i, p := range providers {
		responses[i] = toResponse(p)
	}
	return responses, nil
}

// Delete removes a provider.
func (s *Service) Delete(ctx context.Context, id, tenantID string) *apperrors.AppError {
	if err := s.repo.Delete(ctx, id, tenantID); err != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to delete provider", err)
	}
	s.logger.Info("identity provider deleted", "provider_id", id)
	if s.auditSvc != nil {
		s.auditSvc.Log(ctx, tenantID, "system", "system", domainaudit.EventProviderDeleted, "provider", id, nil, nil)
	}
	return nil
}

func generateID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
