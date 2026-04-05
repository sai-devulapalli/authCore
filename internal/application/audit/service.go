package audit

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	webhooksvc "github.com/authplex/internal/application/webhook"
	domainaudit "github.com/authplex/internal/domain/audit"
	apperrors "github.com/authplex/pkg/sdk/errors"
)

// Service provides audit logging operations.
type Service struct {
	repo       domainaudit.Repository
	logger     *slog.Logger
	webhookSvc *webhooksvc.Service
}

// NewService creates a new audit service.
func NewService(repo domainaudit.Repository, logger *slog.Logger) *Service {
	return &Service{repo: repo, logger: logger}
}

// WithWebhooks sets the webhook service for event delivery.
func (s *Service) WithWebhooks(svc *webhooksvc.Service) {
	s.webhookSvc = svc
}

// Log records an audit event.
func (s *Service) Log(ctx context.Context, tenantID, actorID, actorType string, action domainaudit.EventType, resourceType, resourceID string, r *http.Request, details map[string]any) {
	id, _ := generateID()

	var ip, ua string
	if r != nil {
		ip = extractIP(r)
		ua = r.UserAgent()
	}

	event := domainaudit.Event{
		ID:           id,
		TenantID:     tenantID,
		ActorID:      actorID,
		ActorType:    actorType,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		IPAddress:    ip,
		UserAgent:    ua,
		Details:      details,
		Timestamp:    time.Now().UTC(),
	}

	if err := s.repo.Store(ctx, event); err != nil {
		s.logger.Error("failed to store audit event", "error", err, "action", action)
	}

	if s.webhookSvc != nil {
		go s.webhookSvc.Deliver(ctx, tenantID, string(action), map[string]any{
			"event":         action,
			"actor_id":      actorID,
			"resource_type": resourceType,
			"resource_id":   resourceID,
			"timestamp":     time.Now().UTC(),
		})
	}
}

// Query retrieves audit events matching the filter.
func (s *Service) Query(ctx context.Context, filter domainaudit.QueryFilter) ([]domainaudit.Event, *apperrors.AppError) {
	events, err := s.repo.Query(ctx, filter)
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrInternal, "failed to query audit events", err)
	}
	return events, nil
}

func extractIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.Split(xff, ",")[0]
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	return strings.Split(r.RemoteAddr, ":")[0]
}

func generateID() (string, error) {
	return uuid.New().String(), nil
}
