package client

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/authplex/internal/domain/client"
	apperrors "github.com/authplex/pkg/sdk/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Mocks ---

type mockClientRepo struct {
	createFunc  func(ctx context.Context, c client.Client) error
	getByIDFunc func(ctx context.Context, id, tenantID string) (client.Client, error)
	updateFunc  func(ctx context.Context, c client.Client) error
	deleteFunc  func(ctx context.Context, id, tenantID string) error
	listFunc    func(ctx context.Context, tenantID string, offset, limit int) ([]client.Client, int, error)
}

func (m *mockClientRepo) Create(ctx context.Context, c client.Client) error {
	if m.createFunc != nil {
		return m.createFunc(ctx, c)
	}
	return nil
}

func (m *mockClientRepo) GetByID(ctx context.Context, id, tenantID string) (client.Client, error) {
	if m.getByIDFunc != nil {
		return m.getByIDFunc(ctx, id, tenantID)
	}
	return client.Client{}, errors.New("not found")
}

func (m *mockClientRepo) Update(ctx context.Context, c client.Client) error {
	if m.updateFunc != nil {
		return m.updateFunc(ctx, c)
	}
	return nil
}

func (m *mockClientRepo) Delete(ctx context.Context, id, tenantID string) error {
	if m.deleteFunc != nil {
		return m.deleteFunc(ctx, id, tenantID)
	}
	return nil
}

func (m *mockClientRepo) List(ctx context.Context, tenantID string, offset, limit int) ([]client.Client, int, error) {
	if m.listFunc != nil {
		return m.listFunc(ctx, tenantID, offset, limit)
	}
	return nil, 0, nil
}

func (m *mockClientRepo) UpdateAPIKey(_ context.Context, _, _ string, _ []byte) error {
	return nil
}

func (m *mockClientRepo) GetByAPIKeyHash(_ context.Context, _ []byte, _ string) (client.Client, error) {
	return client.Client{}, errors.New("not found")
}

type mockHasher struct {
	hashFunc   func(secret string) ([]byte, error)
	verifyFunc func(secret string, hash []byte) error
}

func (m *mockHasher) Hash(secret string) ([]byte, error) {
	if m.hashFunc != nil {
		return m.hashFunc(secret)
	}
	return []byte("hashed"), nil
}

func (m *mockHasher) Verify(secret string, hash []byte) error {
	if m.verifyFunc != nil {
		return m.verifyFunc(secret, hash)
	}
	return nil
}

// --- Tests ---

func TestCreate_PublicClient(t *testing.T) {
	svc := NewService(&mockClientRepo{}, &mockHasher{}, slog.Default())

	resp, appErr := svc.Create(context.Background(), CreateClientRequest{
		ClientName:    "My SPA",
		ClientType:    "public",
		RedirectURIs:  []string{"https://example.com/callback"},
		AllowedScopes: []string{"openid", "profile"},
		GrantTypes:    []string{"authorization_code"},
		TenantID:      "t1",
	})

	require.Nil(t, appErr)
	assert.NotEmpty(t, resp.ClientID)
	assert.Empty(t, resp.ClientSecret, "public client should not have a secret")
	assert.Equal(t, "My SPA", resp.ClientName)
	assert.Equal(t, "public", resp.ClientType)
}

func TestCreate_ConfidentialClient(t *testing.T) {
	svc := NewService(&mockClientRepo{}, &mockHasher{}, slog.Default())

	resp, appErr := svc.Create(context.Background(), CreateClientRequest{
		ClientName:    "Server App",
		ClientType:    "confidential",
		RedirectURIs:  []string{"https://example.com/callback"},
		AllowedScopes: []string{"openid"},
		GrantTypes:    []string{"authorization_code", "client_credentials"},
		TenantID:      "t1",
	})

	require.Nil(t, appErr)
	assert.NotEmpty(t, resp.ClientID)
	assert.NotEmpty(t, resp.ClientSecret, "confidential client should have a secret")
	assert.Equal(t, "confidential", resp.ClientType)
}

func TestCreate_ValidationError(t *testing.T) {
	svc := NewService(&mockClientRepo{}, &mockHasher{}, slog.Default())

	_, appErr := svc.Create(context.Background(), CreateClientRequest{
		ClientName: "", // invalid
		ClientType: "public",
		TenantID:   "t1",
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrBadRequest, appErr.Code)
}

func TestCreate_RepoError(t *testing.T) {
	repo := &mockClientRepo{
		createFunc: func(_ context.Context, _ client.Client) error {
			return errors.New("db error")
		},
	}
	svc := NewService(repo, &mockHasher{}, slog.Default())

	_, appErr := svc.Create(context.Background(), CreateClientRequest{
		ClientName: "App", ClientType: "public", TenantID: "t1",
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrInternal, appErr.Code)
}

func TestGet_Success(t *testing.T) {
	repo := &mockClientRepo{
		getByIDFunc: func(_ context.Context, id, _ string) (client.Client, error) {
			return client.Client{ID: id, ClientName: "App", ClientType: client.Public}, nil
		},
	}
	svc := NewService(repo, &mockHasher{}, slog.Default())

	resp, appErr := svc.Get(context.Background(), "c1", "t1")

	require.Nil(t, appErr)
	assert.Equal(t, "c1", resp.ClientID)
	assert.Empty(t, resp.ClientSecret)
}

func TestGet_NotFound(t *testing.T) {
	svc := NewService(&mockClientRepo{}, &mockHasher{}, slog.Default())

	_, appErr := svc.Get(context.Background(), "nonexistent", "t1")

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrNotFound, appErr.Code)
}

func TestUpdate_Success(t *testing.T) {
	repo := &mockClientRepo{
		getByIDFunc: func(_ context.Context, _, _ string) (client.Client, error) {
			return client.Client{ID: "c1", ClientName: "Old", ClientType: client.Public}, nil
		},
	}
	svc := NewService(repo, &mockHasher{}, slog.Default())

	resp, appErr := svc.Update(context.Background(), "c1", UpdateClientRequest{
		ClientName: "New Name",
		TenantID:   "t1",
	})

	require.Nil(t, appErr)
	assert.Equal(t, "New Name", resp.ClientName)
}

func TestDelete_Success(t *testing.T) {
	svc := NewService(&mockClientRepo{}, &mockHasher{}, slog.Default())

	appErr := svc.Delete(context.Background(), "c1", "t1")

	assert.Nil(t, appErr)
}

func TestList_Success(t *testing.T) {
	repo := &mockClientRepo{
		listFunc: func(_ context.Context, _ string, _, _ int) ([]client.Client, int, error) {
			return []client.Client{
				{ID: "c1", ClientName: "App1", ClientType: client.Public},
				{ID: "c2", ClientName: "App2", ClientType: client.Confidential},
			}, 2, nil
		},
	}
	svc := NewService(repo, &mockHasher{}, slog.Default())

	resp, total, appErr := svc.List(context.Background(), "t1", 0, 10)

	require.Nil(t, appErr)
	assert.Len(t, resp, 2)
	assert.Equal(t, 2, total)
}

func TestAuthenticate_Success(t *testing.T) {
	repo := &mockClientRepo{
		getByIDFunc: func(_ context.Context, _, _ string) (client.Client, error) {
			return client.Client{
				ID:         "c1",
				ClientType: client.Confidential,
				SecretHash: []byte("hash"),
			}, nil
		},
	}
	svc := NewService(repo, &mockHasher{}, slog.Default())

	c, appErr := svc.Authenticate(context.Background(), "c1", "secret", "t1")

	require.Nil(t, appErr)
	assert.Equal(t, "c1", c.ID)
}

func TestAuthenticate_WrongSecret(t *testing.T) {
	repo := &mockClientRepo{
		getByIDFunc: func(_ context.Context, _, _ string) (client.Client, error) {
			return client.Client{
				ID: "c1", ClientType: client.Confidential, SecretHash: []byte("hash"),
			}, nil
		},
	}
	hasher := &mockHasher{
		verifyFunc: func(_ string, _ []byte) error { return errors.New("mismatch") },
	}
	svc := NewService(repo, hasher, slog.Default())

	_, appErr := svc.Authenticate(context.Background(), "c1", "wrong", "t1")

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrInvalidClient, appErr.Code)
}

func TestAuthenticate_PublicClient(t *testing.T) {
	repo := &mockClientRepo{
		getByIDFunc: func(_ context.Context, _, _ string) (client.Client, error) {
			return client.Client{ID: "c1", ClientType: client.Public}, nil
		},
	}
	svc := NewService(repo, &mockHasher{}, slog.Default())

	_, appErr := svc.Authenticate(context.Background(), "c1", "secret", "t1")

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrInvalidClient, appErr.Code)
}

func TestValidateClient_Success(t *testing.T) {
	repo := &mockClientRepo{
		getByIDFunc: func(_ context.Context, _, _ string) (client.Client, error) {
			return client.Client{ID: "c1", ClientType: client.Public}, nil
		},
	}
	svc := NewService(repo, &mockHasher{}, slog.Default())

	c, appErr := svc.ValidateClient(context.Background(), "c1", "t1")

	require.Nil(t, appErr)
	assert.Equal(t, "c1", c.ID)
}

func TestValidateClient_NotFound(t *testing.T) {
	svc := NewService(&mockClientRepo{}, &mockHasher{}, slog.Default())

	_, appErr := svc.ValidateClient(context.Background(), "nonexistent", "t1")

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrInvalidClient, appErr.Code)
}

func TestCreate_HashError(t *testing.T) {
	hasher := &mockHasher{
		hashFunc: func(_ string) ([]byte, error) {
			return nil, errors.New("hash failed")
		},
	}
	svc := NewService(&mockClientRepo{}, hasher, slog.Default())

	_, appErr := svc.Create(context.Background(), CreateClientRequest{
		ClientName: "App", ClientType: "confidential", TenantID: "t1",
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrInternal, appErr.Code)
}

// --- API Key mock repo ---

type mockAPIKeyRepo struct {
	mockClientRepo
	storedClients map[string]client.Client
	apiKeyHashes  map[string][]byte // clientID -> hash
}

func newMockAPIKeyRepo() *mockAPIKeyRepo {
	return &mockAPIKeyRepo{
		storedClients: make(map[string]client.Client),
		apiKeyHashes:  make(map[string][]byte),
	}
}

func (m *mockAPIKeyRepo) Create(_ context.Context, c client.Client) error {
	m.storedClients[c.ID] = c
	return nil
}

func (m *mockAPIKeyRepo) GetByID(_ context.Context, id, _ string) (client.Client, error) {
	c, ok := m.storedClients[id]
	if !ok {
		return client.Client{}, errors.New("not found")
	}
	return c, nil
}

func (m *mockAPIKeyRepo) UpdateAPIKey(_ context.Context, clientID, _ string, hash []byte) error {
	m.apiKeyHashes[clientID] = hash
	return nil
}

func (m *mockAPIKeyRepo) GetByAPIKeyHash(_ context.Context, hash []byte, _ string) (client.Client, error) {
	for clientID, stored := range m.apiKeyHashes {
		if string(stored) == string(hash) {
			return m.storedClients[clientID], nil
		}
	}
	return client.Client{}, errors.New("not found")
}

// --- API Key Tests ---

func TestClientSvc_GenerateAPIKey(t *testing.T) {
	repo := newMockAPIKeyRepo()
	repo.storedClients["c1"] = client.Client{ID: "c1", TenantID: "t1", ClientType: client.Public}
	svc := NewService(repo, &mockHasher{}, slog.Default())

	key, appErr := svc.GenerateAPIKey(context.Background(), "c1", "t1")

	require.Nil(t, appErr)
	assert.NotEmpty(t, key)
}

func TestClientSvc_GenerateAPIKey_NotFound(t *testing.T) {
	repo := newMockAPIKeyRepo()
	svc := NewService(repo, &mockHasher{}, slog.Default())

	_, appErr := svc.GenerateAPIKey(context.Background(), "nonexistent", "t1")

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrNotFound, appErr.Code)
}

func TestClientSvc_ValidateAPIKey(t *testing.T) {
	repo := newMockAPIKeyRepo()
	repo.storedClients["c1"] = client.Client{ID: "c1", TenantID: "t1", ClientType: client.Public}
	svc := NewService(repo, &mockHasher{}, slog.Default())

	rawKey, appErr := svc.GenerateAPIKey(context.Background(), "c1", "t1")
	require.Nil(t, appErr)

	got, appErr := svc.ValidateAPIKey(context.Background(), rawKey, "t1")

	require.Nil(t, appErr)
	require.NotNil(t, got)
	assert.Equal(t, "c1", got.ID)
}

func TestClientSvc_ValidateAPIKey_WrongKey(t *testing.T) {
	repo := newMockAPIKeyRepo()
	repo.storedClients["c1"] = client.Client{ID: "c1", TenantID: "t1", ClientType: client.Public}
	svc := NewService(repo, &mockHasher{}, slog.Default())

	_, appErr := svc.GenerateAPIKey(context.Background(), "c1", "t1")
	require.Nil(t, appErr)

	_, appErr = svc.ValidateAPIKey(context.Background(), "wrong-key-value", "t1")

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrInvalidClient, appErr.Code)
}

func TestClientSvc_WithAudit(t *testing.T) {
	svc := NewService(&mockClientRepo{}, &mockHasher{}, slog.Default())
	result := svc.WithAudit(nil)
	assert.NotNil(t, result)
}
