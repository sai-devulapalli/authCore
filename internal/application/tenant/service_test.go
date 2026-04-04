package tenant

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/authplex/internal/config"
	"github.com/authplex/internal/domain/tenant"
	apperrors "github.com/authplex/pkg/sdk/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Mock Repository ---

type mockTenantRepo struct {
	getByIDFunc    func(ctx context.Context, id string) (tenant.Tenant, error)
	getByDomainFunc func(ctx context.Context, domain string) (tenant.Tenant, error)
	createFunc     func(ctx context.Context, t tenant.Tenant) error
	updateFunc     func(ctx context.Context, t tenant.Tenant) error
	deleteFunc     func(ctx context.Context, id string) error
	listFunc       func(ctx context.Context, offset, limit int) ([]tenant.Tenant, int, error)
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

func (m *mockTenantRepo) Create(ctx context.Context, t tenant.Tenant) error {
	if m.createFunc != nil {
		return m.createFunc(ctx, t)
	}
	return nil
}

func (m *mockTenantRepo) Update(ctx context.Context, t tenant.Tenant) error {
	if m.updateFunc != nil {
		return m.updateFunc(ctx, t)
	}
	return nil
}

func (m *mockTenantRepo) Delete(ctx context.Context, id string) error {
	if m.deleteFunc != nil {
		return m.deleteFunc(ctx, id)
	}
	return nil
}

func (m *mockTenantRepo) List(ctx context.Context, offset, limit int) ([]tenant.Tenant, int, error) {
	if m.listFunc != nil {
		return m.listFunc(ctx, offset, limit)
	}
	return nil, 0, nil
}

func (m *mockTenantRepo) IncrementTokenVersion(_ context.Context, _ string) error {
	return nil
}

// --- Tests ---

func TestCreate_Success(t *testing.T) {
	repo := &mockTenantRepo{}
	svc := NewService(repo, slog.Default())

	created, appErr := svc.Create(context.Background(), CreateTenantRequest{
		ID:        "t1",
		Domain:    "example.com",
		Issuer:    "https://example.com",
		Algorithm: tenant.RS256,
	})

	require.Nil(t, appErr)
	assert.Equal(t, "t1", created.ID)
	assert.Equal(t, "example.com", created.Domain)
}

func TestCreate_ValidationError(t *testing.T) {
	svc := NewService(&mockTenantRepo{}, slog.Default())

	_, appErr := svc.Create(context.Background(), CreateTenantRequest{
		ID: "", // invalid
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrBadRequest, appErr.Code)
}

func TestCreate_RepoError(t *testing.T) {
	repo := &mockTenantRepo{
		createFunc: func(_ context.Context, _ tenant.Tenant) error {
			return errors.New("db error")
		},
	}
	svc := NewService(repo, slog.Default())

	_, appErr := svc.Create(context.Background(), CreateTenantRequest{
		ID: "t1", Domain: "ex.com", Issuer: "https://ex.com", Algorithm: tenant.RS256,
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrInternal, appErr.Code)
}

func TestGet_Success(t *testing.T) {
	repo := &mockTenantRepo{
		getByIDFunc: func(_ context.Context, _ string) (tenant.Tenant, error) {
			return tenant.Tenant{ID: "t1", Domain: "ex.com"}, nil
		},
	}
	svc := NewService(repo, slog.Default())

	got, appErr := svc.Get(context.Background(), "t1")

	require.Nil(t, appErr)
	assert.Equal(t, "t1", got.ID)
}

func TestGet_NotFound(t *testing.T) {
	svc := NewService(&mockTenantRepo{}, slog.Default())

	_, appErr := svc.Get(context.Background(), "nonexistent")

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrNotFound, appErr.Code)
}

func TestGet_Deleted(t *testing.T) {
	now := time.Now()
	repo := &mockTenantRepo{
		getByIDFunc: func(_ context.Context, _ string) (tenant.Tenant, error) {
			return tenant.Tenant{ID: "t1", DeletedAt: &now}, nil
		},
	}
	svc := NewService(repo, slog.Default())

	_, appErr := svc.Get(context.Background(), "t1")

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrNotFound, appErr.Code)
}

func TestUpdate_Success(t *testing.T) {
	repo := &mockTenantRepo{
		getByIDFunc: func(_ context.Context, _ string) (tenant.Tenant, error) {
			return tenant.Tenant{ID: "t1", Domain: "old.com", Issuer: "https://old.com"}, nil
		},
	}
	svc := NewService(repo, slog.Default())

	updated, appErr := svc.Update(context.Background(), "t1", UpdateTenantRequest{
		Domain: "new.com",
	})

	require.Nil(t, appErr)
	assert.Equal(t, "new.com", updated.Domain)
	assert.Equal(t, "https://old.com", updated.Issuer)
}

func TestUpdate_NotFound(t *testing.T) {
	svc := NewService(&mockTenantRepo{}, slog.Default())

	_, appErr := svc.Update(context.Background(), "nonexistent", UpdateTenantRequest{})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrNotFound, appErr.Code)
}

func TestDelete_Success(t *testing.T) {
	svc := NewService(&mockTenantRepo{}, slog.Default())

	appErr := svc.Delete(context.Background(), "t1")

	assert.Nil(t, appErr)
}

func TestDelete_Error(t *testing.T) {
	repo := &mockTenantRepo{
		deleteFunc: func(_ context.Context, _ string) error {
			return errors.New("db error")
		},
	}
	svc := NewService(repo, slog.Default())

	appErr := svc.Delete(context.Background(), "t1")

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrInternal, appErr.Code)
}

func TestList_Success(t *testing.T) {
	repo := &mockTenantRepo{
		listFunc: func(_ context.Context, _, _ int) ([]tenant.Tenant, int, error) {
			return []tenant.Tenant{
				{ID: "t1"}, {ID: "t2"},
			}, 2, nil
		},
	}
	svc := NewService(repo, slog.Default())

	tenants, total, appErr := svc.List(context.Background(), 0, 10)

	require.Nil(t, appErr)
	assert.Len(t, tenants, 2)
	assert.Equal(t, 2, total)
}

func TestResolve_HeaderMode(t *testing.T) {
	repo := &mockTenantRepo{
		getByIDFunc: func(_ context.Context, id string) (tenant.Tenant, error) {
			return tenant.Tenant{ID: id, Domain: "ex.com"}, nil
		},
	}
	svc := NewService(repo, slog.Default())

	resolved, appErr := svc.Resolve(context.Background(), "t1", config.TenantModeHeader)

	require.Nil(t, appErr)
	assert.Equal(t, "t1", resolved.ID)
}

func TestResolve_DomainMode(t *testing.T) {
	repo := &mockTenantRepo{
		getByDomainFunc: func(_ context.Context, domain string) (tenant.Tenant, error) {
			return tenant.Tenant{ID: "t1", Domain: domain}, nil
		},
	}
	svc := NewService(repo, slog.Default())

	resolved, appErr := svc.Resolve(context.Background(), "example.com", config.TenantModeDomain)

	require.Nil(t, appErr)
	assert.Equal(t, "t1", resolved.ID)
}

func TestResolve_NotFound(t *testing.T) {
	svc := NewService(&mockTenantRepo{}, slog.Default())

	_, appErr := svc.Resolve(context.Background(), "nonexistent", config.TenantModeHeader)

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrNotFound, appErr.Code)
}

func TestResolve_Deleted(t *testing.T) {
	now := time.Now()
	repo := &mockTenantRepo{
		getByIDFunc: func(_ context.Context, _ string) (tenant.Tenant, error) {
			return tenant.Tenant{ID: "t1", DeletedAt: &now}, nil
		},
	}
	svc := NewService(repo, slog.Default())

	_, appErr := svc.Resolve(context.Background(), "t1", config.TenantModeHeader)

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrNotFound, appErr.Code)
}

func TestResolve_UnknownMode(t *testing.T) {
	svc := NewService(&mockTenantRepo{}, slog.Default())

	_, appErr := svc.Resolve(context.Background(), "id", config.TenantMode("unknown"))

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrInternal, appErr.Code)
}
