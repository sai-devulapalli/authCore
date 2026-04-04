package middleware

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	tenantsvc "github.com/authplex/internal/application/tenant"
	"github.com/authplex/internal/config"
	"github.com/authplex/internal/domain/shared"
	"github.com/authplex/internal/domain/tenant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Mock Repository ---

type mockTenantRepo struct {
	getByIDFunc     func(ctx context.Context, id string) (tenant.Tenant, error)
	getByDomainFunc func(ctx context.Context, domain string) (tenant.Tenant, error)
}

func (m *mockTenantRepo) GetByID(ctx context.Context, id string) (tenant.Tenant, error) {
	if m.getByIDFunc != nil {
		return m.getByIDFunc(ctx, id)
	}
	return tenant.Tenant{}, errors.New("not found")
}

func (m *mockTenantRepo) GetByDomain(ctx context.Context, domain string) (tenant.Tenant, error) {
	if m.getByDomainFunc != nil {
		return m.getByDomainFunc(ctx, domain)
	}
	return tenant.Tenant{}, errors.New("not found")
}

func (m *mockTenantRepo) Create(_ context.Context, _ tenant.Tenant) error { return nil }
func (m *mockTenantRepo) Update(_ context.Context, _ tenant.Tenant) error { return nil }
func (m *mockTenantRepo) Delete(_ context.Context, _ string) error        { return nil }
func (m *mockTenantRepo) List(_ context.Context, _, _ int) ([]tenant.Tenant, int, error) {
	return nil, 0, nil
}

func (m *mockTenantRepo) IncrementTokenVersion(_ context.Context, _ string) error {
	return nil
}

// --- Tests ---

func TestTenantResolver_HeaderMode_Success(t *testing.T) {
	repo := &mockTenantRepo{
		getByIDFunc: func(_ context.Context, id string) (tenant.Tenant, error) {
			return tenant.Tenant{ID: id, Domain: "example.com"}, nil
		},
	}
	svc := tenantsvc.NewService(repo, slog.Default())
	resolver := NewTenantResolver(svc, config.TenantModeHeader, slog.Default())

	var capturedTenantID string
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		id, ok := shared.TenantFromContext(r.Context())
		require.True(t, ok)
		capturedTenantID = id
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Tenant-ID", "tenant-1")
	w := httptest.NewRecorder()

	resolver.Middleware(next).ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "tenant-1", capturedTenantID)
}

func TestTenantResolver_HeaderMode_MissingHeader(t *testing.T) {
	svc := tenantsvc.NewService(&mockTenantRepo{}, slog.Default())
	resolver := NewTenantResolver(svc, config.TenantModeHeader, slog.Default())

	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("next handler should not be called")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	// No X-Tenant-ID header
	w := httptest.NewRecorder()

	resolver.Middleware(next).ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTenantResolver_HeaderMode_TenantNotFound(t *testing.T) {
	svc := tenantsvc.NewService(&mockTenantRepo{}, slog.Default())
	resolver := NewTenantResolver(svc, config.TenantModeHeader, slog.Default())

	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("next handler should not be called")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Tenant-ID", "nonexistent")
	w := httptest.NewRecorder()

	resolver.Middleware(next).ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestTenantResolver_DomainMode_Success(t *testing.T) {
	repo := &mockTenantRepo{
		getByDomainFunc: func(_ context.Context, domain string) (tenant.Tenant, error) {
			return tenant.Tenant{ID: "t1", Domain: domain}, nil
		},
	}
	svc := tenantsvc.NewService(repo, slog.Default())
	resolver := NewTenantResolver(svc, config.TenantModeDomain, slog.Default())

	var capturedTenantID string
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		id, _ := shared.TenantFromContext(r.Context())
		capturedTenantID = id
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
	w := httptest.NewRecorder()

	resolver.Middleware(next).ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "t1", capturedTenantID)
}
