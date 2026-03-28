package audit

import "context"

// Repository is the port interface for audit event persistence.
type Repository interface {
	Store(ctx context.Context, event Event) error
	Query(ctx context.Context, filter QueryFilter) ([]Event, error)
}

// QueryFilter defines criteria for querying audit events.
type QueryFilter struct {
	TenantID     string
	ActorID      string
	Action       EventType
	ResourceType string
	ResourceID   string
	Limit        int
	Offset       int
}
