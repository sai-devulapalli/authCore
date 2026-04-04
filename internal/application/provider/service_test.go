package provider

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/authplex/internal/domain/identity"
	apperrors "github.com/authplex/pkg/sdk/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockProviderRepo struct {
	createFunc  func(ctx context.Context, p identity.IdentityProvider) error
	getByIDFunc func(ctx context.Context, id, tenantID string) (identity.IdentityProvider, error)
	listFunc    func(ctx context.Context, tenantID string) ([]identity.IdentityProvider, error)
	deleteFunc  func(ctx context.Context, id, tenantID string) error
}

func (m *mockProviderRepo) Create(ctx context.Context, p identity.IdentityProvider) error {
	if m.createFunc != nil {
		return m.createFunc(ctx, p)
	}
	return nil
}

func (m *mockProviderRepo) GetByID(ctx context.Context, id, tenantID string) (identity.IdentityProvider, error) {
	if m.getByIDFunc != nil {
		return m.getByIDFunc(ctx, id, tenantID)
	}
	return identity.IdentityProvider{}, errors.New("not found")
}

func (m *mockProviderRepo) GetByType(_ context.Context, _ string, _ identity.ProviderType) (identity.IdentityProvider, error) {
	return identity.IdentityProvider{}, errors.New("not found")
}

func (m *mockProviderRepo) List(ctx context.Context, tenantID string) ([]identity.IdentityProvider, error) {
	if m.listFunc != nil {
		return m.listFunc(ctx, tenantID)
	}
	return nil, nil
}

func (m *mockProviderRepo) Update(_ context.Context, _ identity.IdentityProvider) error { return nil }

func (m *mockProviderRepo) Delete(ctx context.Context, id, tenantID string) error {
	if m.deleteFunc != nil {
		return m.deleteFunc(ctx, id, tenantID)
	}
	return nil
}

func TestCreate_Success(t *testing.T) {
	svc := NewService(&mockProviderRepo{}, slog.Default())

	resp, appErr := svc.Create(context.Background(), CreateProviderRequest{
		ProviderType: "google",
		ClientID:     "google-client-id",
		ClientSecret: "google-secret",
		Scopes:       []string{"openid", "email"},
		TenantID:     "t1",
	})

	require.Nil(t, appErr)
	assert.NotEmpty(t, resp.ID)
	assert.Equal(t, "google", resp.ProviderType)
	assert.Equal(t, "google-client-id", resp.ClientID)
	assert.True(t, resp.Enabled)
}

func TestCreate_InvalidProviderType(t *testing.T) {
	svc := NewService(&mockProviderRepo{}, slog.Default())

	_, appErr := svc.Create(context.Background(), CreateProviderRequest{
		ProviderType: "facebook",
		ClientID:     "cid",
		TenantID:     "t1",
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrBadRequest, appErr.Code)
}

func TestGet_Success(t *testing.T) {
	repo := &mockProviderRepo{
		getByIDFunc: func(_ context.Context, id, _ string) (identity.IdentityProvider, error) {
			return identity.IdentityProvider{ID: id, ProviderType: identity.ProviderGoogle, ClientID: "cid", Enabled: true}, nil
		},
	}
	svc := NewService(repo, slog.Default())

	resp, appErr := svc.Get(context.Background(), "p1", "t1")

	require.Nil(t, appErr)
	assert.Equal(t, "p1", resp.ID)
}

func TestGet_NotFound(t *testing.T) {
	svc := NewService(&mockProviderRepo{}, slog.Default())

	_, appErr := svc.Get(context.Background(), "nonexistent", "t1")

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrNotFound, appErr.Code)
}

func TestList_Success(t *testing.T) {
	repo := &mockProviderRepo{
		listFunc: func(_ context.Context, _ string) ([]identity.IdentityProvider, error) {
			return []identity.IdentityProvider{
				{ID: "p1", ProviderType: identity.ProviderGoogle, ClientID: "cid1"},
				{ID: "p2", ProviderType: identity.ProviderGitHub, ClientID: "cid2"},
			}, nil
		},
	}
	svc := NewService(repo, slog.Default())

	resp, appErr := svc.List(context.Background(), "t1")

	require.Nil(t, appErr)
	assert.Len(t, resp, 2)
}

func TestDelete_Success(t *testing.T) {
	svc := NewService(&mockProviderRepo{}, slog.Default())

	appErr := svc.Delete(context.Background(), "p1", "t1")

	assert.Nil(t, appErr)
}

func TestDelete_Error(t *testing.T) {
	repo := &mockProviderRepo{
		deleteFunc: func(_ context.Context, _, _ string) error {
			return errors.New("db error")
		},
	}
	svc := NewService(repo, slog.Default())

	appErr := svc.Delete(context.Background(), "p1", "t1")

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrInternal, appErr.Code)
}

func TestCreate_RepoError(t *testing.T) {
	repo := &mockProviderRepo{
		createFunc: func(_ context.Context, _ identity.IdentityProvider) error {
			return errors.New("db error")
		},
	}
	svc := NewService(repo, slog.Default())

	_, appErr := svc.Create(context.Background(), CreateProviderRequest{
		ProviderType: "google", ClientID: "cid", TenantID: "t1",
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrInternal, appErr.Code)
}
