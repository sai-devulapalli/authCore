package postgres

import (
	"context"
	"time"
)

// DefaultQueryTimeout is the maximum time a database query can take.
const DefaultQueryTimeout = 5 * time.Second

// WithQueryTimeout returns a context with the default query timeout applied.
// If the parent context already has a shorter deadline, that is preserved.
func WithQueryTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, DefaultQueryTimeout)
}
