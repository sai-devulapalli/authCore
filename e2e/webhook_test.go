//go:build e2e

package e2e

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Webhook CRUD
// ---------------------------------------------------------------------------

func TestE2E_WebhookCRUD(t *testing.T) {
	env := setupFullTestServer(t)
	defer env.server.Close()

	adminHeaders := map[string]string{
		"Authorization": "Bearer " + env.adminKey,
	}

	tenantID := env.createTenant(t, "webhook-crud-t", "RS256")

	var webhookID string

	t.Run("create webhook subscription", func(t *testing.T) {
		status, body := env.doJSON(t, http.MethodPost, "/tenants/"+tenantID+"/webhooks", map[string]any{
			"url":    "https://hooks.example.com/events",
			"events": []string{"user.registered", "user.login"},
		}, adminHeaders)
		require.Equal(t, http.StatusCreated, status)
		data := body["data"].(map[string]any)
		// Fields use Go struct names (no json tags): ID, URL, TenantID, etc.
		id := data["ID"]
		if id == nil {
			id = data["id"]
		}
		assert.NotEmpty(t, id, "webhook should have an ID")
		webhookID = fmt.Sprintf("%v", id)

		u := data["URL"]
		if u == nil {
			u = data["url"]
		}
		assert.Equal(t, "https://hooks.example.com/events", u)
	})

	t.Run("list webhooks returns the created one", func(t *testing.T) {
		status, body := env.get(t, "/tenants/"+tenantID+"/webhooks", adminHeaders)
		require.Equal(t, http.StatusOK, status)
		data := body["data"].(map[string]any)
		webhooks := data["webhooks"].([]any)
		assert.Equal(t, 1, len(webhooks))
	})

	t.Run("create second webhook", func(t *testing.T) {
		status, _ := env.doJSON(t, http.MethodPost, "/tenants/"+tenantID+"/webhooks", map[string]any{
			"url":    "https://hooks2.example.com/events",
			"events": []string{"tenant.created"},
		}, adminHeaders)
		assert.Equal(t, http.StatusCreated, status)
	})

	t.Run("list webhooks returns 2", func(t *testing.T) {
		status, body := env.get(t, "/tenants/"+tenantID+"/webhooks", adminHeaders)
		require.Equal(t, http.StatusOK, status)
		data := body["data"].(map[string]any)
		count := data["count"].(float64)
		assert.Equal(t, float64(2), count)
	})

	t.Run("delete webhook", func(t *testing.T) {
		status, _ := env.doJSON(t, http.MethodDelete, "/tenants/"+tenantID+"/webhooks/"+webhookID, nil, adminHeaders)
		assert.Equal(t, http.StatusNoContent, status)
	})

	t.Run("list webhooks after delete returns 1", func(t *testing.T) {
		status, body := env.get(t, "/tenants/"+tenantID+"/webhooks", adminHeaders)
		require.Equal(t, http.StatusOK, status)
		data := body["data"].(map[string]any)
		count := data["count"].(float64)
		assert.Equal(t, float64(1), count)
	})

	t.Run("create webhook without URL returns 400", func(t *testing.T) {
		status, _ := env.doJSON(t, http.MethodPost, "/tenants/"+tenantID+"/webhooks", map[string]any{
			"events": []string{"user.registered"},
		}, adminHeaders)
		assert.Equal(t, http.StatusBadRequest, status)
	})

	t.Run("webhooks on different tenant are isolated", func(t *testing.T) {
		tenantB := env.createTenant(t, "webhook-iso-t", "RS256")
		status, body := env.get(t, "/tenants/"+tenantB+"/webhooks", adminHeaders)
		require.Equal(t, http.StatusOK, status)
		data := body["data"].(map[string]any)
		count := data["count"].(float64)
		assert.Equal(t, float64(0), count, "tenant B should have no webhooks")
	})
}
