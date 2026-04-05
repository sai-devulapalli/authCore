package client

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"log/slog"

	auditsvc "github.com/authplex/internal/application/audit"
	domainaudit "github.com/authplex/internal/domain/audit"
	"github.com/authplex/internal/domain/client"
	apperrors "github.com/authplex/pkg/sdk/errors"
)

// Service provides OAuth client management operations.
type Service struct {
	repo     client.Repository
	hasher   client.SecretHasher
	auditSvc *auditsvc.Service
	logger   *slog.Logger
}

// WithAudit configures audit event logging.
func (s *Service) WithAudit(a *auditsvc.Service) *Service {
	s.auditSvc = a
	return s
}

// NewService creates a new client service.
func NewService(repo client.Repository, hasher client.SecretHasher, logger *slog.Logger) *Service {
	return &Service{
		repo:   repo,
		hasher: hasher,
		logger: logger,
	}
}

// Create registers a new OAuth client.
// For confidential clients, generates and returns the secret exactly once.
func (s *Service) Create(ctx context.Context, req CreateClientRequest) (ClientResponse, *apperrors.AppError) {
	var id string
	if req.ClientID != "" {
		id = req.ClientID
	} else {
		var err error
		id, err = generateClientID()
		if err != nil {
			return ClientResponse{}, apperrors.Wrap(apperrors.ErrInternal, "failed to generate client ID", err)
		}
	}

	grantTypes := make([]client.GrantType, len(req.GrantTypes))
	for i, gt := range req.GrantTypes {
		grantTypes[i] = client.GrantType(gt)
	}

	c, valErr := client.NewClient(id, req.TenantID, req.ClientName,
		client.ClientType(req.ClientType), req.RedirectURIs, req.AllowedScopes, grantTypes)
	if valErr != nil {
		return ClientResponse{}, apperrors.Wrap(apperrors.ErrBadRequest, "invalid client", valErr)
	}

	var plaintextSecret string
	if c.ClientType == client.Confidential {
		secret := req.ClientSecret
		if secret == "" {
			var err error
			secret, err = generateSecret()
			if err != nil {
				return ClientResponse{}, apperrors.Wrap(apperrors.ErrInternal, "failed to generate secret", err)
			}
		}
		hash, err := s.hasher.Hash(secret)
		if err != nil {
			return ClientResponse{}, apperrors.Wrap(apperrors.ErrInternal, "failed to hash secret", err)
		}
		c.SecretHash = hash
		plaintextSecret = secret
	}

	if err := s.repo.Create(ctx, c); err != nil {
		return ClientResponse{}, apperrors.Wrap(apperrors.ErrInternal, "failed to create client", err)
	}

	s.logger.Info("client created", "client_id", c.ID, "tenant_id", c.TenantID, "type", c.ClientType)
	if s.auditSvc != nil {
		s.auditSvc.Log(ctx, req.TenantID, "system", "system", domainaudit.EventClientCreated, "client", c.ID, nil, nil)
	}

	return toResponse(c, plaintextSecret), nil
}

// Get returns a client by ID.
func (s *Service) Get(ctx context.Context, clientID, tenantID string) (ClientResponse, *apperrors.AppError) {
	c, err := s.repo.GetByID(ctx, clientID, tenantID)
	if err != nil {
		return ClientResponse{}, apperrors.Wrap(apperrors.ErrNotFound, "client not found", err)
	}
	if c.IsDeleted() {
		return ClientResponse{}, apperrors.New(apperrors.ErrNotFound, "client not found")
	}
	return toResponse(c, ""), nil
}

// Update updates an existing client.
func (s *Service) Update(ctx context.Context, clientID string, req UpdateClientRequest) (ClientResponse, *apperrors.AppError) {
	c, err := s.repo.GetByID(ctx, clientID, req.TenantID)
	if err != nil {
		return ClientResponse{}, apperrors.Wrap(apperrors.ErrNotFound, "client not found", err)
	}

	if req.ClientName != "" {
		c.ClientName = req.ClientName
	}
	if req.RedirectURIs != nil {
		c.RedirectURIs = req.RedirectURIs
	}
	if req.AllowedScopes != nil {
		c.AllowedScopes = req.AllowedScopes
	}

	if err := s.repo.Update(ctx, c); err != nil {
		return ClientResponse{}, apperrors.Wrap(apperrors.ErrInternal, "failed to update client", err)
	}

	s.logger.Info("client updated", "client_id", c.ID)
	return toResponse(c, ""), nil
}

// Delete soft-deletes a client.
func (s *Service) Delete(ctx context.Context, clientID, tenantID string) *apperrors.AppError {
	if err := s.repo.Delete(ctx, clientID, tenantID); err != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to delete client", err)
	}
	s.logger.Info("client deleted", "client_id", clientID)
	if s.auditSvc != nil {
		s.auditSvc.Log(ctx, tenantID, "system", "system", domainaudit.EventClientDeleted, "client", clientID, nil, nil)
	}
	return nil
}

// List returns a paginated list of clients for a tenant.
func (s *Service) List(ctx context.Context, tenantID string, offset, limit int) ([]ClientResponse, int, *apperrors.AppError) {
	clients, total, err := s.repo.List(ctx, tenantID, offset, limit)
	if err != nil {
		return nil, 0, apperrors.Wrap(apperrors.ErrInternal, "failed to list clients", err)
	}
	responses := make([]ClientResponse, len(clients))
	for i, c := range clients {
		responses[i] = toResponse(c, "")
	}
	return responses, total, nil
}

// Authenticate validates a confidential client's credentials.
func (s *Service) Authenticate(ctx context.Context, clientID, clientSecret, tenantID string) (client.Client, *apperrors.AppError) {
	c, err := s.repo.GetByID(ctx, clientID, tenantID)
	if err != nil {
		return client.Client{}, apperrors.New(apperrors.ErrInvalidClient, "client not found")
	}
	if c.IsDeleted() {
		return client.Client{}, apperrors.New(apperrors.ErrInvalidClient, "client not found")
	}
	if c.ClientType != client.Confidential {
		return client.Client{}, apperrors.New(apperrors.ErrInvalidClient, "client is not confidential")
	}
	if err := s.hasher.Verify(clientSecret, c.SecretHash); err != nil {
		return client.Client{}, apperrors.New(apperrors.ErrInvalidClient, "invalid client credentials")
	}
	return c, nil
}

// ValidateClient validates a public client exists and is active.
func (s *Service) ValidateClient(ctx context.Context, clientID, tenantID string) (client.Client, *apperrors.AppError) {
	c, err := s.repo.GetByID(ctx, clientID, tenantID)
	if err != nil {
		return client.Client{}, apperrors.New(apperrors.ErrInvalidClient, "client not found")
	}
	if c.IsDeleted() {
		return client.Client{}, apperrors.New(apperrors.ErrInvalidClient, "client not found")
	}
	return c, nil
}

// GenerateAPIKey generates a non-expiring API key for a client.
// The raw key is returned once; only the SHA-256 hash is stored.
func (s *Service) GenerateAPIKey(ctx context.Context, clientID, tenantID string) (string, *apperrors.AppError) {
	// Verify client exists
	c, err := s.repo.GetByID(ctx, clientID, tenantID)
	if err != nil {
		return "", apperrors.Wrap(apperrors.ErrNotFound, "client not found", err)
	}
	if c.IsDeleted() {
		return "", apperrors.New(apperrors.ErrNotFound, "client not found")
	}

	// Generate a random 32-byte API key (base64url encoded)
	rawKey, genErr := generateSecret()
	if genErr != nil {
		return "", apperrors.Wrap(apperrors.ErrInternal, "failed to generate API key", genErr)
	}

	// Hash with SHA-256 before storing
	hash := sha256.Sum256([]byte(rawKey))

	if err := s.repo.UpdateAPIKey(ctx, clientID, tenantID, hash[:]); err != nil {
		return "", apperrors.Wrap(apperrors.ErrInternal, "failed to store API key", err)
	}

	s.logger.Info("API key generated", "client_id", clientID, "tenant_id", tenantID)
	if s.auditSvc != nil {
		s.auditSvc.Log(ctx, tenantID, "system", "system", domainaudit.EventClientCreated, "client", clientID, nil, map[string]any{
			"action": "api_key_generated",
		})
	}

	return rawKey, nil
}

// ValidateAPIKey validates an API key and returns the associated client.
func (s *Service) ValidateAPIKey(ctx context.Context, apiKey, tenantID string) (*client.Client, *apperrors.AppError) {
	// Hash the input key with SHA-256
	hash := sha256.Sum256([]byte(apiKey))

	// Look up client by API key hash + tenant
	c, err := s.repo.GetByAPIKeyHash(ctx, hash[:], tenantID)
	if err != nil {
		return nil, apperrors.New(apperrors.ErrInvalidClient, "invalid API key")
	}
	if c.IsDeleted() {
		return nil, apperrors.New(apperrors.ErrInvalidClient, "invalid API key")
	}

	return &c, nil
}

func toResponse(c client.Client, secret string) ClientResponse {
	grantTypes := make([]string, len(c.AllowedGrantTypes))
	for i, gt := range c.AllowedGrantTypes {
		grantTypes[i] = string(gt)
	}
	return ClientResponse{
		ClientID:      c.ID,
		ClientSecret:  secret,
		ClientName:    c.ClientName,
		ClientType:    string(c.ClientType),
		RedirectURIs:  c.RedirectURIs,
		AllowedScopes: c.AllowedScopes,
		GrantTypes:    grantTypes,
	}
}

func generateClientID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func generateSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
