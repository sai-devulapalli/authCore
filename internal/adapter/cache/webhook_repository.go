package cache

import (
	"context"
	"fmt"
	"sync"

	"github.com/authplex/internal/domain/webhook"
)

// InMemoryWebhookRepository implements webhook.Repository.
type InMemoryWebhookRepository struct {
	mu       sync.RWMutex
	webhooks []webhook.Webhook
}

// NewInMemoryWebhookRepository creates a new in-memory webhook repository.
func NewInMemoryWebhookRepository() *InMemoryWebhookRepository {
	return &InMemoryWebhookRepository{}
}

var _ webhook.Repository = (*InMemoryWebhookRepository)(nil)

func (r *InMemoryWebhookRepository) Create(_ context.Context, w webhook.Webhook) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.webhooks = append(r.webhooks, w)
	return nil
}

func (r *InMemoryWebhookRepository) GetByID(_ context.Context, id, tenantID string) (webhook.Webhook, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, w := range r.webhooks {
		if w.ID == id && w.TenantID == tenantID {
			return w, nil
		}
	}
	return webhook.Webhook{}, fmt.Errorf("webhook not found")
}

func (r *InMemoryWebhookRepository) List(_ context.Context, tenantID string) ([]webhook.Webhook, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var result []webhook.Webhook
	for _, w := range r.webhooks {
		if w.TenantID == tenantID {
			result = append(result, w)
		}
	}
	return result, nil
}

func (r *InMemoryWebhookRepository) Delete(_ context.Context, id, tenantID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, w := range r.webhooks {
		if w.ID == id && w.TenantID == tenantID {
			r.webhooks = append(r.webhooks[:i], r.webhooks[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("webhook not found")
}

func (r *InMemoryWebhookRepository) ListByEvent(_ context.Context, tenantID, eventType string) ([]webhook.Webhook, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var result []webhook.Webhook
	for _, w := range r.webhooks {
		if w.TenantID == tenantID && w.Enabled {
			for _, e := range w.Events {
				if e == eventType {
					result = append(result, w)
					break
				}
			}
		}
	}
	return result, nil
}
