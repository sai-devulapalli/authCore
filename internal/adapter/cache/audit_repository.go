package cache

import (
	"context"
	"sync"

	"github.com/authcore/internal/domain/audit"
)

// InMemoryAuditRepository implements audit.Repository.
type InMemoryAuditRepository struct {
	mu     sync.Mutex
	events []audit.Event
}

// NewInMemoryAuditRepository creates a new in-memory audit repository.
func NewInMemoryAuditRepository() *InMemoryAuditRepository {
	return &InMemoryAuditRepository{}
}

var _ audit.Repository = (*InMemoryAuditRepository)(nil)

func (r *InMemoryAuditRepository) Store(_ context.Context, event audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event)
	return nil
}

func (r *InMemoryAuditRepository) Query(_ context.Context, filter audit.QueryFilter) ([]audit.Event, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	var result []audit.Event
	for _, e := range r.events {
		if filter.TenantID != "" && e.TenantID != filter.TenantID {
			continue
		}
		if filter.ActorID != "" && e.ActorID != filter.ActorID {
			continue
		}
		if filter.Action != "" && e.Action != filter.Action {
			continue
		}
		if filter.ResourceType != "" && e.ResourceType != filter.ResourceType {
			continue
		}
		if filter.ResourceID != "" && e.ResourceID != filter.ResourceID {
			continue
		}
		result = append(result, e)
	}

	// Pagination
	offset := filter.Offset
	if offset > len(result) {
		return nil, nil
	}
	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	end := offset + limit
	if end > len(result) {
		end = len(result)
	}
	return result[offset:end], nil
}
