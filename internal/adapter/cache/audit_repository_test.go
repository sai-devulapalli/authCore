package cache

import (
	"context"
	"testing"
	"time"

	"github.com/authplex/internal/domain/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuditRepo_StoreAndQuery(t *testing.T) {
	repo := NewInMemoryAuditRepository()
	ctx := context.Background()

	e := audit.Event{
		ID: "e1", TenantID: "t1", ActorID: "u1", Action: audit.EventLoginSuccess,
		ResourceType: "session", Timestamp: time.Now(),
	}
	require.NoError(t, repo.Store(ctx, e))

	events, err := repo.Query(ctx, audit.QueryFilter{TenantID: "t1"})
	require.NoError(t, err)
	assert.Len(t, events, 1)
	assert.Equal(t, audit.EventLoginSuccess, events[0].Action)
}

func TestAuditRepo_FilterByAction(t *testing.T) {
	repo := NewInMemoryAuditRepository()
	ctx := context.Background()

	repo.Store(ctx, audit.Event{ID: "e1", TenantID: "t1", Action: audit.EventLoginSuccess})
	repo.Store(ctx, audit.Event{ID: "e2", TenantID: "t1", Action: audit.EventLoginFailure})
	repo.Store(ctx, audit.Event{ID: "e3", TenantID: "t1", Action: audit.EventLoginSuccess})

	events, _ := repo.Query(ctx, audit.QueryFilter{TenantID: "t1", Action: audit.EventLoginFailure})
	assert.Len(t, events, 1)
}

func TestAuditRepo_Pagination(t *testing.T) {
	repo := NewInMemoryAuditRepository()
	ctx := context.Background()

	for i := 0; i < 10; i++ {
		repo.Store(ctx, audit.Event{ID: string(rune('a' + i)), TenantID: "t1", Action: audit.EventLoginSuccess})
	}

	events, _ := repo.Query(ctx, audit.QueryFilter{TenantID: "t1", Limit: 3, Offset: 0})
	assert.Len(t, events, 3)

	events, _ = repo.Query(ctx, audit.QueryFilter{TenantID: "t1", Limit: 3, Offset: 8})
	assert.Len(t, events, 2)
}

func TestAuditRepo_EmptyQuery(t *testing.T) {
	repo := NewInMemoryAuditRepository()
	events, err := repo.Query(context.Background(), audit.QueryFilter{TenantID: "empty"})
	require.NoError(t, err)
	assert.Empty(t, events)
}
