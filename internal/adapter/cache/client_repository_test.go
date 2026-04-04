package cache

import (
	"context"
	"testing"

	"github.com/authplex/internal/domain/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientRepo_CreateAndGetByID(t *testing.T) {
	repo := NewInMemoryClientRepository()
	ctx := context.Background()
	c, _ := client.NewClient("c1", "t1", "App", client.Public, []string{"https://example.com/cb"}, nil, nil)
	require.NoError(t, repo.Create(ctx, c))

	got, err := repo.GetByID(ctx, "c1", "t1")
	require.NoError(t, err)
	assert.Equal(t, "c1", got.ID)
}

func TestClientRepo_GetByID_NotFound(t *testing.T) {
	repo := NewInMemoryClientRepository()
	_, err := repo.GetByID(context.Background(), "x", "t1")
	require.Error(t, err)
}

func TestClientRepo_GetByID_WrongTenant(t *testing.T) {
	repo := NewInMemoryClientRepository()
	ctx := context.Background()
	c, _ := client.NewClient("c1", "t1", "App", client.Public, nil, nil, nil)
	repo.Create(ctx, c) //nolint:errcheck

	_, err := repo.GetByID(ctx, "c1", "t2")
	require.Error(t, err)
}

func TestClientRepo_Update(t *testing.T) {
	repo := NewInMemoryClientRepository()
	ctx := context.Background()
	c, _ := client.NewClient("c1", "t1", "Old", client.Public, nil, nil, nil)
	repo.Create(ctx, c) //nolint:errcheck
	c.ClientName = "New"
	require.NoError(t, repo.Update(ctx, c))
	got, _ := repo.GetByID(ctx, "c1", "t1")
	assert.Equal(t, "New", got.ClientName)
}

func TestClientRepo_Update_NotFound(t *testing.T) {
	repo := NewInMemoryClientRepository()
	err := repo.Update(context.Background(), client.Client{ID: "x"})
	require.Error(t, err)
}

func TestClientRepo_Delete(t *testing.T) {
	repo := NewInMemoryClientRepository()
	ctx := context.Background()
	c, _ := client.NewClient("c1", "t1", "App", client.Public, nil, nil, nil)
	repo.Create(ctx, c) //nolint:errcheck
	require.NoError(t, repo.Delete(ctx, "c1", "t1"))
	got, _ := repo.GetByID(ctx, "c1", "t1")
	assert.True(t, got.IsDeleted())
}

func TestClientRepo_Delete_NotFound(t *testing.T) {
	repo := NewInMemoryClientRepository()
	err := repo.Delete(context.Background(), "x", "t1")
	require.Error(t, err)
}

func TestClientRepo_List(t *testing.T) {
	repo := NewInMemoryClientRepository()
	ctx := context.Background()
	c1, _ := client.NewClient("c1", "t1", "A", client.Public, nil, nil, nil)
	c2, _ := client.NewClient("c2", "t1", "B", client.Public, nil, nil, nil)
	repo.Create(ctx, c1) //nolint:errcheck
	repo.Create(ctx, c2) //nolint:errcheck

	clients, total, err := repo.List(ctx, "t1", 0, 10)
	require.NoError(t, err)
	assert.Equal(t, 2, total)
	assert.Len(t, clients, 2)
}

func TestClientRepo_UpdateAPIKey(t *testing.T) {
	repo := NewInMemoryClientRepository()
	ctx := context.Background()
	c, _ := client.NewClient("c1", "t1", "App", client.Public, nil, nil, nil)
	require.NoError(t, repo.Create(ctx, c))

	hash := []byte{1, 2, 3}
	require.NoError(t, repo.UpdateAPIKey(ctx, "c1", "t1", hash))

	got, err := repo.GetByID(ctx, "c1", "t1")
	require.NoError(t, err)
	assert.Equal(t, hash, got.APIKeyHash)
}

func TestClientRepo_UpdateAPIKey_NotFound(t *testing.T) {
	repo := NewInMemoryClientRepository()
	err := repo.UpdateAPIKey(context.Background(), "nonexistent", "t1", []byte{1, 2, 3})
	require.Error(t, err)
}

func TestClientRepo_GetByAPIKeyHash(t *testing.T) {
	repo := NewInMemoryClientRepository()
	ctx := context.Background()
	c, _ := client.NewClient("c1", "t1", "App", client.Public, nil, nil, nil)
	require.NoError(t, repo.Create(ctx, c))

	hash := []byte{1, 2, 3}
	require.NoError(t, repo.UpdateAPIKey(ctx, "c1", "t1", hash))

	got, err := repo.GetByAPIKeyHash(ctx, hash, "t1")
	require.NoError(t, err)
	assert.Equal(t, "c1", got.ID)
}

func TestClientRepo_GetByAPIKeyHash_NotFound(t *testing.T) {
	repo := NewInMemoryClientRepository()
	ctx := context.Background()
	c, _ := client.NewClient("c1", "t1", "App", client.Public, nil, nil, nil)
	require.NoError(t, repo.Create(ctx, c))

	require.NoError(t, repo.UpdateAPIKey(ctx, "c1", "t1", []byte{1, 2, 3}))

	_, err := repo.GetByAPIKeyHash(ctx, []byte{9, 9, 9}, "t1")
	require.Error(t, err)
}
