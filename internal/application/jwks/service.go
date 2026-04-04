package jwks

import (
	"context"
	"log/slog"

	"github.com/authplex/internal/domain/jwk"
	"github.com/authplex/internal/domain/tenant"
	apperrors "github.com/authplex/pkg/sdk/errors"
)

// Service provides JWKS management operations.
type Service struct {
	repo      jwk.Repository
	generator jwk.Generator
	converter jwk.Converter
	logger    *slog.Logger
}

// NewService creates a new JWKS service.
func NewService(repo jwk.Repository, gen jwk.Generator, conv jwk.Converter, logger *slog.Logger) *Service {
	return &Service{
		repo:      repo,
		generator: gen,
		converter: conv,
		logger:    logger,
	}
}

// GetJWKS returns the public JWKS for a tenant.
func (s *Service) GetJWKS(ctx context.Context, tenantID string) (jwk.Set, *apperrors.AppError) {
	keys, err := s.repo.GetAllPublic(ctx, tenantID)
	if err != nil {
		s.logger.Error("failed to get public keys", "tenant_id", tenantID, "error", err)
		return jwk.Set{}, apperrors.Wrap(apperrors.ErrInternal, "failed to retrieve keys", err)
	}

	publicJWKs := make([]jwk.PublicJWK, 0, len(keys))
	for _, kp := range keys {
		pubJWK, err := s.converter.PEMToPublicJWK(kp.PublicKey, kp.ID, kp.Algorithm)
		if err != nil {
			s.logger.Error("failed to convert key to JWK", "key_id", kp.ID, "error", err)
			continue
		}
		publicJWKs = append(publicJWKs, pubJWK)
	}

	return jwk.Set{Keys: publicJWKs}, nil
}

// EnsureKeyPair creates a new key pair for the tenant if none exists.
// Returns the active key pair.
func (s *Service) EnsureKeyPair(ctx context.Context, tenantID string, kid string, alg tenant.Algorithm) (jwk.KeyPair, *apperrors.AppError) {
	existing, err := s.repo.GetActive(ctx, tenantID)
	if err == nil {
		return existing, nil
	}

	s.logger.Info("generating new key pair", "tenant_id", tenantID, "algorithm", alg)

	privPEM, pubPEM, genErr := s.generateKeyPair(alg)
	if genErr != nil {
		return jwk.KeyPair{}, genErr
	}

	keyType := jwk.RSA
	if alg == tenant.ES256 {
		keyType = jwk.EC
	}

	kp, valErr := jwk.NewKeyPair(kid, tenantID, keyType, string(alg), privPEM, pubPEM)
	if valErr != nil {
		return jwk.KeyPair{}, apperrors.Wrap(apperrors.ErrInternal, "key pair validation failed", valErr)
	}

	if err := s.repo.Store(ctx, kp); err != nil {
		return jwk.KeyPair{}, apperrors.Wrap(apperrors.ErrInternal, "failed to store key pair", err)
	}

	return kp, nil
}

// RotateKey deactivates the current key and creates a new one for the tenant.
func (s *Service) RotateKey(ctx context.Context, tenantID string, kid string, alg tenant.Algorithm) (jwk.KeyPair, *apperrors.AppError) {
	existing, err := s.repo.GetActive(ctx, tenantID)
	if err == nil {
		if deactivateErr := s.repo.Deactivate(ctx, existing.ID); deactivateErr != nil {
			return jwk.KeyPair{}, apperrors.Wrap(apperrors.ErrInternal, "failed to deactivate old key", deactivateErr)
		}
	}

	s.logger.Info("rotating key", "tenant_id", tenantID, "algorithm", alg)

	privPEM, pubPEM, genErr := s.generateKeyPair(alg)
	if genErr != nil {
		return jwk.KeyPair{}, genErr
	}

	keyType := jwk.RSA
	if alg == tenant.ES256 {
		keyType = jwk.EC
	}

	kp, valErr := jwk.NewKeyPair(kid, tenantID, keyType, string(alg), privPEM, pubPEM)
	if valErr != nil {
		return jwk.KeyPair{}, apperrors.Wrap(apperrors.ErrInternal, "key pair validation failed", valErr)
	}

	if err := s.repo.Store(ctx, kp); err != nil {
		return jwk.KeyPair{}, apperrors.Wrap(apperrors.ErrInternal, "failed to store new key pair", err)
	}

	return kp, nil
}

// GetActiveKeyPair returns the active key pair for a tenant.
func (s *Service) GetActiveKeyPair(ctx context.Context, tenantID string) (jwk.KeyPair, *apperrors.AppError) {
	kp, err := s.repo.GetActive(ctx, tenantID)
	if err != nil {
		return jwk.KeyPair{}, apperrors.Wrap(apperrors.ErrNotFound, "no active key for tenant", err)
	}
	return kp, nil
}

func (s *Service) generateKeyPair(alg tenant.Algorithm) ([]byte, []byte, *apperrors.AppError) {
	switch alg {
	case tenant.RS256:
		priv, pub, err := s.generator.GenerateRSA()
		if err != nil {
			return nil, nil, apperrors.Wrap(apperrors.ErrInternal, "RSA key generation failed", err)
		}
		return priv, pub, nil
	case tenant.ES256:
		priv, pub, err := s.generator.GenerateEC()
		if err != nil {
			return nil, nil, apperrors.Wrap(apperrors.ErrInternal, "EC key generation failed", err)
		}
		return priv, pub, nil
	default:
		return nil, nil, apperrors.New(apperrors.ErrBadRequest, "unsupported algorithm: "+string(alg))
	}
}
