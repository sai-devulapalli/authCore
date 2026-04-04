package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/authplex/internal/domain/webhook"
)

// Service provides webhook management and delivery operations.
type Service struct {
	repo   webhook.Repository
	logger *slog.Logger
	client *http.Client
}

// NewService creates a new webhook service.
func NewService(repo webhook.Repository, logger *slog.Logger) *Service {
	return &Service{
		repo:   repo,
		logger: logger,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// Create registers a new webhook for a tenant.
func (s *Service) Create(ctx context.Context, tenantID, url string, events []string) (*webhook.Webhook, error) {
	id, err := generateID()
	if err != nil {
		return nil, fmt.Errorf("generate webhook id: %w", err)
	}

	secret, err := generateSecret()
	if err != nil {
		return nil, fmt.Errorf("generate webhook secret: %w", err)
	}

	w := webhook.Webhook{
		ID:        id,
		TenantID:  tenantID,
		URL:       url,
		Secret:    secret,
		Events:    events,
		Enabled:   true,
		CreatedAt: time.Now().UTC(),
	}

	if err := s.repo.Create(ctx, w); err != nil {
		return nil, fmt.Errorf("create webhook: %w", err)
	}

	return &w, nil
}

// List returns all webhooks for a tenant.
func (s *Service) List(ctx context.Context, tenantID string) ([]webhook.Webhook, error) {
	return s.repo.List(ctx, tenantID)
}

// Delete removes a webhook.
func (s *Service) Delete(ctx context.Context, id, tenantID string) error {
	return s.repo.Delete(ctx, id, tenantID)
}

// Deliver sends an event payload to all matching webhooks for a tenant.
// This is fire-and-forget — it does not block the caller.
func (s *Service) Deliver(ctx context.Context, tenantID, eventType string, payload map[string]any) {
	hooks, err := s.repo.ListByEvent(ctx, tenantID, eventType)
	if err != nil {
		s.logger.Error("failed to list webhooks for delivery", "error", err, "tenant_id", tenantID, "event", eventType)
		return
	}

	body, err := json.Marshal(payload)
	if err != nil {
		s.logger.Error("failed to marshal webhook payload", "error", err)
		return
	}

	for _, hook := range hooks {
		go s.deliver(hook, body)
	}
}

func (s *Service) deliver(hook webhook.Webhook, body []byte) {
	req, err := http.NewRequest(http.MethodPost, hook.URL, bytes.NewReader(body))
	if err != nil {
		s.logger.Error("failed to create webhook request", "error", err, "webhook_id", hook.ID, "url", hook.URL)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-AuthPlex-Signature", sign(hook.Secret, body))

	resp, err := s.client.Do(req)
	if err != nil {
		s.logger.Error("webhook delivery failed", "error", err, "webhook_id", hook.ID, "url", hook.URL)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		s.logger.Debug("webhook delivered", "webhook_id", hook.ID, "url", hook.URL, "status", resp.StatusCode)
	} else {
		s.logger.Warn("webhook delivery non-2xx", "webhook_id", hook.ID, "url", hook.URL, "status", resp.StatusCode)
	}
}

// sign computes HMAC-SHA256 and returns "sha256=<hex>".
func sign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func generateID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func generateSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
