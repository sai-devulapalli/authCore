package audit

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"log/slog"
	"net/http"
	"strings"
	"time"

	domainaudit "github.com/authcore/internal/domain/audit"
	apperrors "github.com/authcore/pkg/sdk/errors"
)

// Service provides audit logging operations.
type Service struct {
	repo   domainaudit.Repository
	logger *slog.Logger
}

// NewService creates a new audit service.
func NewService(repo domainaudit.Repository, logger *slog.Logger) *Service {
	return &Service{repo: repo, logger: logger}
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
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
