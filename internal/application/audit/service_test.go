package audit

import (
	"context"
	"log/slog"
	"net/http/httptest"
	"testing"

	"github.com/authplex/internal/adapter/cache"
	domainaudit "github.com/authplex/internal/domain/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLog(t *testing.T) {
	repo := cache.NewInMemoryAuditRepository()
	svc := NewService(repo, slog.Default())

	req := httptest.NewRequest("POST", "/login", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	req.Header.Set("User-Agent", "TestAgent")

	svc.Log(context.Background(), "t1", "user-1", "user", domainaudit.EventLoginSuccess,
		"session", "sess-1", req, map[string]any{"method": "password"})

	events, appErr := svc.Query(context.Background(), domainaudit.QueryFilter{TenantID: "t1"})
	require.Nil(t, appErr)
	assert.Len(t, events, 1)
	assert.Equal(t, domainaudit.EventLoginSuccess, events[0].Action)
	assert.Equal(t, "user-1", events[0].ActorID)
	assert.Equal(t, "192.168.1.1", events[0].IPAddress)
}

func TestLog_NilRequest(t *testing.T) {
	repo := cache.NewInMemoryAuditRepository()
	svc := NewService(repo, slog.Default())

	svc.Log(context.Background(), "t1", "system", "system", domainaudit.EventTokenRevoked,
		"token", "jti-1", nil, nil)

	events, _ := svc.Query(context.Background(), domainaudit.QueryFilter{TenantID: "t1"})
	assert.Len(t, events, 1)
	assert.Empty(t, events[0].IPAddress)
}

func TestQuery_Empty(t *testing.T) {
	repo := cache.NewInMemoryAuditRepository()
	svc := NewService(repo, slog.Default())

	events, appErr := svc.Query(context.Background(), domainaudit.QueryFilter{TenantID: "empty"})
	require.Nil(t, appErr)
	assert.Empty(t, events)
}

func TestQuery_FilterByAction(t *testing.T) {
	repo := cache.NewInMemoryAuditRepository()
	svc := NewService(repo, slog.Default())

	svc.Log(context.Background(), "t1", "u1", "user", domainaudit.EventLoginSuccess, "", "", nil, nil)
	svc.Log(context.Background(), "t1", "u2", "user", domainaudit.EventLoginFailure, "", "", nil, nil)
	svc.Log(context.Background(), "t1", "u1", "user", domainaudit.EventRegister, "", "", nil, nil)

	events, _ := svc.Query(context.Background(), domainaudit.QueryFilter{
		TenantID: "t1", Action: domainaudit.EventLoginFailure,
	})
	assert.Len(t, events, 1)
	assert.Equal(t, "u2", events[0].ActorID)
}

func TestExtractIP(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.50, 70.41.3.18")
	assert.Equal(t, "203.0.113.50", extractIP(req))

	req2 := httptest.NewRequest("GET", "/", nil)
	req2.Header.Set("X-Real-IP", "10.0.0.1")
	assert.Equal(t, "10.0.0.1", extractIP(req2))

	req3 := httptest.NewRequest("GET", "/", nil)
	req3.RemoteAddr = "192.168.1.1:8080"
	assert.Equal(t, "192.168.1.1", extractIP(req3))
}
