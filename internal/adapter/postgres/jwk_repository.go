package postgres

import (
	"context"
	"database/sql"
	"time"

	"github.com/authplex/internal/domain/jwk"
	apperrors "github.com/authplex/pkg/sdk/errors"
)

// JWKRepository implements jwk.Repository using PostgreSQL.
type JWKRepository struct {
	db *sql.DB
}

// NewJWKRepository creates a new PostgreSQL-backed JWK repository.
func NewJWKRepository(db *sql.DB) *JWKRepository {
	return &JWKRepository{db: db}
}

var _ jwk.Repository = (*JWKRepository)(nil)

// Store persists a new key pair.
func (r *JWKRepository) Store(ctx context.Context, kp jwk.KeyPair) error {
	ctx, cancel := WithQueryTimeout(ctx)
	defer cancel()
	query := `INSERT INTO jwk_pairs (id, tenant_id, key_type, algorithm, key_use, private_key, public_key, active, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

	_, err := r.db.ExecContext(ctx, query,
		kp.ID,
		kp.TenantID,
		string(kp.KeyType),
		kp.Algorithm,
		string(kp.Use),
		kp.PrivateKey,
		kp.PublicKey,
		kp.Active,
		kp.CreatedAt,
		kp.ExpiresAt,
	)
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to store key pair", err)
	}
	return nil
}

// GetActive returns the active key pair for a tenant.
func (r *JWKRepository) GetActive(ctx context.Context, tenantID string) (jwk.KeyPair, error) {
	ctx, cancel := WithQueryTimeout(ctx)
	defer cancel()
	query := `SELECT id, tenant_id, key_type, algorithm, key_use, private_key, public_key, active, created_at, expires_at
		FROM jwk_pairs WHERE tenant_id = $1 AND active = true ORDER BY created_at DESC LIMIT 1`

	var kp jwk.KeyPair
	var keyType, algorithm, use string
	var expiresAt *time.Time

	err := r.db.QueryRowContext(ctx, query, tenantID).Scan(
		&kp.ID,
		&kp.TenantID,
		&keyType,
		&algorithm,
		&use,
		&kp.PrivateKey,
		&kp.PublicKey,
		&kp.Active,
		&kp.CreatedAt,
		&expiresAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return jwk.KeyPair{}, apperrors.New(apperrors.ErrNotFound, "no active key pair for tenant")
		}
		return jwk.KeyPair{}, apperrors.Wrap(apperrors.ErrInternal, "failed to query active key pair", err)
	}

	kp.KeyType = jwk.KeyType(keyType)
	kp.Algorithm = algorithm
	kp.Use = jwk.KeyUse(use)
	kp.ExpiresAt = expiresAt

	return kp, nil
}

// GetAllPublic returns all key pairs for a tenant (for JWKS endpoint).
func (r *JWKRepository) GetAllPublic(ctx context.Context, tenantID string) ([]jwk.KeyPair, error) {
	ctx, cancel := WithQueryTimeout(ctx)
	defer cancel()
	query := `SELECT id, tenant_id, key_type, algorithm, key_use, public_key, active, created_at, expires_at
		FROM jwk_pairs WHERE tenant_id = $1 ORDER BY created_at DESC`

	rows, err := r.db.QueryContext(ctx, query, tenantID)
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrInternal, "failed to query key pairs", err)
	}
	defer rows.Close()

	var pairs []jwk.KeyPair
	for rows.Next() {
		var kp jwk.KeyPair
		var keyType, algorithm, use string
		var expiresAt *time.Time

		if err := rows.Scan(
			&kp.ID,
			&kp.TenantID,
			&keyType,
			&algorithm,
			&use,
			&kp.PublicKey,
			&kp.Active,
			&kp.CreatedAt,
			&expiresAt,
		); err != nil {
			return nil, apperrors.Wrap(apperrors.ErrInternal, "failed to scan key pair", err)
		}

		kp.KeyType = jwk.KeyType(keyType)
		kp.Algorithm = algorithm
		kp.Use = jwk.KeyUse(use)
		kp.ExpiresAt = expiresAt
		pairs = append(pairs, kp)
	}

	if err := rows.Err(); err != nil {
		return nil, apperrors.Wrap(apperrors.ErrInternal, "rows iteration error", err)
	}

	return pairs, nil
}

// Deactivate marks a key pair as inactive and sets its expiry.
func (r *JWKRepository) Deactivate(ctx context.Context, keyID string) error {
	ctx, cancel := WithQueryTimeout(ctx)
	defer cancel()
	query := `UPDATE jwk_pairs SET active = false, expires_at = $1 WHERE id = $2`

	now := time.Now().UTC()
	result, err := r.db.ExecContext(ctx, query, now, keyID)
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to deactivate key pair", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to check affected rows", err)
	}
	if rows == 0 {
		return apperrors.New(apperrors.ErrNotFound, "key pair not found")
	}

	return nil
}

// GetAllActiveTenantIDs returns distinct tenant IDs that have active key pairs.
func (r *JWKRepository) GetAllActiveTenantIDs(ctx context.Context) ([]string, error) {
	ctx, cancel := WithQueryTimeout(ctx)
	defer cancel()
	query := `SELECT DISTINCT tenant_id FROM jwk_pairs WHERE active = true`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrInternal, "failed to query active tenant IDs", err)
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, apperrors.Wrap(apperrors.ErrInternal, "failed to scan tenant ID", err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// DeleteInactive removes inactive key pairs that expired before the given time.
func (r *JWKRepository) DeleteInactive(ctx context.Context, olderThan time.Time) (int64, error) {
	ctx, cancel := WithQueryTimeout(ctx)
	defer cancel()
	query := `DELETE FROM jwk_pairs WHERE active = false AND expires_at IS NOT NULL AND expires_at < $1`
	result, err := r.db.ExecContext(ctx, query, olderThan)
	if err != nil {
		return 0, apperrors.Wrap(apperrors.ErrInternal, "failed to cleanup inactive keys", err)
	}
	n, _ := result.RowsAffected()
	return n, nil
}
