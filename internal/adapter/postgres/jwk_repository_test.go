//go:build functional

package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/authplex/internal/domain/jwk"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func setupPostgres(t *testing.T) (*sql.DB, func()) {
	t.Helper()
	ctx := context.Background()

	req := testcontainers.ContainerRequest{
		Image:        "postgres:16-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "test",
			"POSTGRES_PASSWORD": "test",
			"POSTGRES_DB":       "testdb",
		},
		WaitingFor: wait.ForListeningPort("5432/tcp").WithStartupTimeout(60 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)

	host, err := container.Host(ctx)
	require.NoError(t, err)
	port, err := container.MappedPort(ctx, "5432")
	require.NoError(t, err)

	dsn := fmt.Sprintf("postgres://test:test@%s:%s/testdb?sslmode=disable", host, port.Port())
	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	require.NoError(t, db.Ping())

	// Run migration
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS jwk_pairs (
		id          TEXT PRIMARY KEY,
		tenant_id   TEXT NOT NULL,
		key_type    TEXT NOT NULL,
		algorithm   TEXT NOT NULL,
		key_use     TEXT NOT NULL DEFAULT 'sig',
		private_key BYTEA NOT NULL,
		public_key  BYTEA NOT NULL,
		active      BOOLEAN NOT NULL DEFAULT true,
		created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
		expires_at  TIMESTAMPTZ
	)`)
	require.NoError(t, err)

	cleanup := func() {
		db.Close()
		container.Terminate(ctx) //nolint:errcheck
	}

	return db, cleanup
}

func TestJWKRepository_StoreAndGetActive(t *testing.T) {
	db, cleanup := setupPostgres(t)
	defer cleanup()

	repo := NewJWKRepository(db)
	ctx := context.Background()

	kp, err := jwk.NewKeyPair("kid-1", "tenant-1", jwk.RSA, "RS256", []byte("priv"), []byte("pub"))
	require.NoError(t, err)

	require.NoError(t, repo.Store(ctx, kp))

	active, err := repo.GetActive(ctx, "tenant-1")
	require.NoError(t, err)
	assert.Equal(t, "kid-1", active.ID)
	assert.Equal(t, "tenant-1", active.TenantID)
	assert.Equal(t, jwk.RSA, active.KeyType)
	assert.True(t, active.Active)
}

func TestJWKRepository_GetActive_NotFound(t *testing.T) {
	db, cleanup := setupPostgres(t)
	defer cleanup()

	repo := NewJWKRepository(db)
	ctx := context.Background()

	_, err := repo.GetActive(ctx, "nonexistent")
	require.Error(t, err)
}

func TestJWKRepository_GetAllPublic(t *testing.T) {
	db, cleanup := setupPostgres(t)
	defer cleanup()

	repo := NewJWKRepository(db)
	ctx := context.Background()

	kp1, _ := jwk.NewKeyPair("kid-1", "tenant-1", jwk.RSA, "RS256", []byte("priv1"), []byte("pub1"))
	kp2, _ := jwk.NewKeyPair("kid-2", "tenant-1", jwk.EC, "ES256", []byte("priv2"), []byte("pub2"))
	require.NoError(t, repo.Store(ctx, kp1))
	require.NoError(t, repo.Store(ctx, kp2))

	pairs, err := repo.GetAllPublic(ctx, "tenant-1")
	require.NoError(t, err)
	assert.Len(t, pairs, 2)
}

func TestJWKRepository_Deactivate(t *testing.T) {
	db, cleanup := setupPostgres(t)
	defer cleanup()

	repo := NewJWKRepository(db)
	ctx := context.Background()

	kp, _ := jwk.NewKeyPair("kid-1", "tenant-1", jwk.RSA, "RS256", []byte("priv"), []byte("pub"))
	require.NoError(t, repo.Store(ctx, kp))

	require.NoError(t, repo.Deactivate(ctx, "kid-1"))

	_, err := repo.GetActive(ctx, "tenant-1")
	require.Error(t, err)
}

func TestJWKRepository_Deactivate_NotFound(t *testing.T) {
	db, cleanup := setupPostgres(t)
	defer cleanup()

	repo := NewJWKRepository(db)
	ctx := context.Background()

	err := repo.Deactivate(ctx, "nonexistent")
	require.Error(t, err)
}

func TestJWKRepository_TenantIsolation(t *testing.T) {
	db, cleanup := setupPostgres(t)
	defer cleanup()

	repo := NewJWKRepository(db)
	ctx := context.Background()

	kp1, _ := jwk.NewKeyPair("kid-1", "tenant-1", jwk.RSA, "RS256", []byte("priv1"), []byte("pub1"))
	kp2, _ := jwk.NewKeyPair("kid-2", "tenant-2", jwk.RSA, "RS256", []byte("priv2"), []byte("pub2"))
	require.NoError(t, repo.Store(ctx, kp1))
	require.NoError(t, repo.Store(ctx, kp2))

	pairs, err := repo.GetAllPublic(ctx, "tenant-1")
	require.NoError(t, err)
	assert.Len(t, pairs, 1)
	assert.Equal(t, "kid-1", pairs[0].ID)
}
