package cleanup

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"log/slog"
	"time"

	"github.com/authplex/internal/application/jwks"
	"github.com/authplex/internal/domain/jwk"
	"github.com/authplex/internal/domain/tenant"
	"github.com/authplex/internal/domain/token"
)

// Service runs periodic cleanup and rotation tasks.
type Service struct {
	refreshRepo token.RefreshTokenRepository
	jwkRepo     jwk.Repository
	jwksSvc     *jwks.Service
	tenantRepo  tenant.Repository
	logger      *slog.Logger
	interval    time.Duration
	retention   time.Duration
	keyMaxAge   time.Duration
}

// NewService creates a new cleanup service.
func NewService(
	refreshRepo token.RefreshTokenRepository,
	jwkRepo jwk.Repository,
	jwksSvc *jwks.Service,
	tenantRepo tenant.Repository,
	logger *slog.Logger,
	keyRotationDays int,
) *Service {
	if keyRotationDays <= 0 {
		keyRotationDays = 90
	}
	return &Service{
		refreshRepo: refreshRepo,
		jwkRepo:     jwkRepo,
		jwksSvc:     jwksSvc,
		tenantRepo:  tenantRepo,
		logger:      logger,
		interval:    24 * time.Hour,
		retention:   7 * 24 * time.Hour,
		keyMaxAge:   time.Duration(keyRotationDays) * 24 * time.Hour,
	}
}

// Start begins periodic cleanup in the background. Blocks until ctx is cancelled.
func (s *Service) Start(ctx context.Context) {
	s.logger.Info("cleanup service started", "interval", s.interval, "key_max_age_days", int(s.keyMaxAge.Hours()/24))

	// Run once at startup
	s.RunOnce(ctx)

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.logger.Info("cleanup service stopped")
			return
		case <-ticker.C:
			s.RunOnce(ctx)
		}
	}
}

// RunOnce performs a single cleanup pass.
func (s *Service) RunOnce(ctx context.Context) {
	s.cleanupRefreshTokens(ctx)
	s.rotateKeys(ctx)
	s.cleanupInactiveKeys(ctx)
}

func (s *Service) cleanupRefreshTokens(ctx context.Context) {
	cutoff := time.Now().UTC().Add(-s.retention)
	count, err := s.refreshRepo.DeleteExpiredAndRevoked(ctx, cutoff)
	if err != nil {
		s.logger.Error("refresh token cleanup failed", "error", err)
		return
	}
	if count > 0 {
		s.logger.Info("refresh tokens cleaned up", "deleted", count)
	}
}

func (s *Service) rotateKeys(ctx context.Context) {
	tenantIDs, err := s.jwkRepo.GetAllActiveTenantIDs(ctx)
	if err != nil {
		s.logger.Error("failed to get active tenant IDs for key rotation", "error", err)
		return
	}

	cutoff := time.Now().UTC().Add(-s.keyMaxAge)
	for _, tenantID := range tenantIDs {
		kp, err := s.jwkRepo.GetActive(ctx, tenantID)
		if err != nil {
			continue
		}

		if kp.CreatedAt.Before(cutoff) {
			kid, genErr := generateKeyID()
			if genErr != nil {
				s.logger.Error("failed to generate key ID", "error", genErr)
				continue
			}
			alg := tenant.Algorithm(kp.Algorithm)
			_, rotateErr := s.jwksSvc.RotateKey(ctx, tenantID, kid, alg)
			if rotateErr != nil {
				s.logger.Error("key rotation failed", "tenant_id", tenantID, "error", rotateErr)
				continue
			}
			s.logger.Info("key rotated", "tenant_id", tenantID, "algorithm", kp.Algorithm)
		}
	}
}

func (s *Service) cleanupInactiveKeys(ctx context.Context) {
	cutoff := time.Now().UTC().Add(-30 * 24 * time.Hour) // keep inactive keys for 30 days
	count, err := s.jwkRepo.DeleteInactive(ctx, cutoff)
	if err != nil {
		s.logger.Error("inactive key cleanup failed", "error", err)
		return
	}
	if count > 0 {
		s.logger.Info("inactive keys cleaned up", "deleted", count)
	}
}

func generateKeyID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
