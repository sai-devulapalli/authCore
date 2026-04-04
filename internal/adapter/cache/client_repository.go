package cache

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"time"

	"github.com/authplex/internal/domain/client"
	apperrors "github.com/authplex/pkg/sdk/errors"
)

// InMemoryClientRepository implements client.Repository using an in-memory map.
type InMemoryClientRepository struct {
	mu      sync.RWMutex
	clients map[string]client.Client
}

// NewInMemoryClientRepository creates a new in-memory client repository.
func NewInMemoryClientRepository() *InMemoryClientRepository {
	return &InMemoryClientRepository{clients: make(map[string]client.Client)}
}

var _ client.Repository = (*InMemoryClientRepository)(nil)

func (r *InMemoryClientRepository) Create(_ context.Context, c client.Client) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.clients[c.ID] = c
	return nil
}

func (r *InMemoryClientRepository) GetByID(_ context.Context, id, tenantID string) (client.Client, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.clients[id]
	if !ok || !strings.EqualFold(c.TenantID, tenantID) {
		return client.Client{}, apperrors.New(apperrors.ErrNotFound, "client not found")
	}
	return c, nil
}

func (r *InMemoryClientRepository) Update(_ context.Context, c client.Client) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.clients[c.ID]; !ok {
		return apperrors.New(apperrors.ErrNotFound, "client not found")
	}
	r.clients[c.ID] = c
	return nil
}

func (r *InMemoryClientRepository) Delete(_ context.Context, id, tenantID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.clients[id]
	if !ok || c.TenantID != tenantID {
		return apperrors.New(apperrors.ErrNotFound, "client not found")
	}
	now := time.Now().UTC()
	c.DeletedAt = &now
	r.clients[id] = c
	return nil
}

func (r *InMemoryClientRepository) List(_ context.Context, tenantID string, offset, limit int) ([]client.Client, int, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var active []client.Client
	for _, c := range r.clients {
		if c.TenantID == tenantID && c.DeletedAt == nil {
			active = append(active, c)
		}
	}
	total := len(active)
	if offset >= total {
		return nil, total, nil
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return active[offset:end], total, nil
}

func (r *InMemoryClientRepository) UpdateAPIKey(_ context.Context, clientID, tenantID string, apiKeyHash []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.clients[clientID]
	if !ok || !strings.EqualFold(c.TenantID, tenantID) {
		return apperrors.New(apperrors.ErrNotFound, "client not found")
	}
	c.APIKeyHash = apiKeyHash
	r.clients[clientID] = c
	return nil
}

func (r *InMemoryClientRepository) GetByAPIKeyHash(_ context.Context, apiKeyHash []byte, tenantID string) (client.Client, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, c := range r.clients {
		if c.TenantID == tenantID && c.DeletedAt == nil && len(c.APIKeyHash) > 0 && bytes.Equal(c.APIKeyHash, apiKeyHash) {
			return c, nil
		}
	}
	return client.Client{}, apperrors.New(apperrors.ErrNotFound, "client not found")
}
