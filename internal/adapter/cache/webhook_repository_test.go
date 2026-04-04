package cache

import (
	"context"
	"testing"

	"github.com/authplex/internal/domain/webhook"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWebhookRepo_CreateAndList(t *testing.T) {
	repo := NewInMemoryWebhookRepository()
	ctx := context.Background()

	w := webhook.Webhook{ID: "w1", TenantID: "t1", URL: "https://example.com/hook", Events: []string{"login_success"}, Enabled: true}
	require.NoError(t, repo.Create(ctx, w))

	list, err := repo.List(ctx, "t1")
	require.NoError(t, err)
	assert.Len(t, list, 1)
	assert.Equal(t, "w1", list[0].ID)
}

func TestWebhookRepo_GetByID(t *testing.T) {
	repo := NewInMemoryWebhookRepository()
	ctx := context.Background()

	w := webhook.Webhook{ID: "w1", TenantID: "t1", URL: "https://example.com/hook", Events: []string{"login_success"}, Enabled: true}
	require.NoError(t, repo.Create(ctx, w))

	got, err := repo.GetByID(ctx, "w1", "t1")
	require.NoError(t, err)
	assert.Equal(t, "https://example.com/hook", got.URL)
}

func TestWebhookRepo_GetByID_NotFound(t *testing.T) {
	repo := NewInMemoryWebhookRepository()
	_, err := repo.GetByID(context.Background(), "nonexistent", "t1")
	require.Error(t, err)
}

func TestWebhookRepo_Delete(t *testing.T) {
	repo := NewInMemoryWebhookRepository()
	ctx := context.Background()

	w := webhook.Webhook{ID: "w1", TenantID: "t1", URL: "https://example.com/hook", Events: []string{"login_success"}, Enabled: true}
	require.NoError(t, repo.Create(ctx, w))

	require.NoError(t, repo.Delete(ctx, "w1", "t1"))

	_, err := repo.GetByID(ctx, "w1", "t1")
	require.Error(t, err)
}

func TestWebhookRepo_Delete_NotFound(t *testing.T) {
	repo := NewInMemoryWebhookRepository()
	err := repo.Delete(context.Background(), "nonexistent", "t1")
	require.Error(t, err)
}

func TestWebhookRepo_ListByEvent(t *testing.T) {
	repo := NewInMemoryWebhookRepository()
	ctx := context.Background()

	w1 := webhook.Webhook{ID: "w1", TenantID: "t1", URL: "https://example.com/hook1", Events: []string{"login_success"}, Enabled: true}
	w2 := webhook.Webhook{ID: "w2", TenantID: "t1", URL: "https://example.com/hook2", Events: []string{"register"}, Enabled: true}
	w3 := webhook.Webhook{ID: "w3", TenantID: "t1", URL: "https://example.com/hook3", Events: []string{"login_success"}, Enabled: false}
	repo.Create(ctx, w1) //nolint:errcheck
	repo.Create(ctx, w2) //nolint:errcheck
	repo.Create(ctx, w3) //nolint:errcheck

	results, err := repo.ListByEvent(ctx, "t1", "login_success")
	require.NoError(t, err)
	// Only w1 matches: enabled and has "login_success"; w3 is disabled
	assert.Len(t, results, 1)
	assert.Equal(t, "w1", results[0].ID)
}
