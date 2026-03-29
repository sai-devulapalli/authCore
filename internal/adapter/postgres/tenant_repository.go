package postgres

import (
	"context"
	"database/sql"
	"time"

	"github.com/authcore/internal/domain/tenant"
	apperrors "github.com/authcore/pkg/sdk/errors"
)

// TenantRepository implements tenant.Repository using PostgreSQL.
type TenantRepository struct {
	db *sql.DB
}

// NewTenantRepository creates a new PostgreSQL-backed tenant repository.
func NewTenantRepository(db *sql.DB) *TenantRepository {
	return &TenantRepository{db: db}
}

var _ tenant.Repository = (*TenantRepository)(nil)

// Create persists a new tenant.
func (r *TenantRepository) Create(ctx context.Context, t tenant.Tenant) error {
	ctx, cancel := WithQueryTimeout(ctx)
	defer cancel()
	query := `INSERT INTO tenants (id, domain, issuer, algorithm, active_key_id, token_version, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	_, err := r.db.ExecContext(ctx, query,
		t.ID, t.Domain, t.Issuer,
		string(t.SigningConfig.Algorithm),
		t.SigningConfig.ActiveKeyID,
		t.TokenVersion,
		t.CreatedAt, t.UpdatedAt,
	)
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to create tenant", err)
	}
	return nil
}

// GetByID returns a tenant by ID.
func (r *TenantRepository) GetByID(ctx context.Context, id string) (tenant.Tenant, error) {
	ctx, cancel := WithQueryTimeout(ctx)
	defer cancel()
	query := `SELECT id, domain, issuer, algorithm, active_key_id, token_version, created_at, updated_at, deleted_at
		FROM tenants WHERE id = $1`

	return r.scanTenant(r.db.QueryRowContext(ctx, query, id))
}

// GetByDomain returns a tenant by domain (non-deleted only).
func (r *TenantRepository) GetByDomain(ctx context.Context, domain string) (tenant.Tenant, error) {
	ctx, cancel := WithQueryTimeout(ctx)
	defer cancel()
	query := `SELECT id, domain, issuer, algorithm, active_key_id, token_version, created_at, updated_at, deleted_at
		FROM tenants WHERE domain = $1 AND deleted_at IS NULL`

	return r.scanTenant(r.db.QueryRowContext(ctx, query, domain))
}

// Update updates an existing tenant.
func (r *TenantRepository) Update(ctx context.Context, t tenant.Tenant) error {
	ctx, cancel := WithQueryTimeout(ctx)
	defer cancel()
	query := `UPDATE tenants SET domain = $1, issuer = $2, algorithm = $3, active_key_id = $4, updated_at = $5
		WHERE id = $6 AND deleted_at IS NULL`

	result, err := r.db.ExecContext(ctx, query,
		t.Domain, t.Issuer,
		string(t.SigningConfig.Algorithm),
		t.SigningConfig.ActiveKeyID,
		time.Now().UTC(), t.ID,
	)
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to update tenant", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to check affected rows", err)
	}
	if rows == 0 {
		return apperrors.New(apperrors.ErrNotFound, "tenant not found")
	}
	return nil
}

// Delete soft-deletes a tenant.
func (r *TenantRepository) Delete(ctx context.Context, id string) error {
	ctx, cancel := WithQueryTimeout(ctx)
	defer cancel()
	query := `UPDATE tenants SET deleted_at = $1 WHERE id = $2 AND deleted_at IS NULL`

	result, err := r.db.ExecContext(ctx, query, time.Now().UTC(), id)
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to delete tenant", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to check affected rows", err)
	}
	if rows == 0 {
		return apperrors.New(apperrors.ErrNotFound, "tenant not found")
	}
	return nil
}

// IncrementTokenVersion atomically increments a tenant's token version.
func (r *TenantRepository) IncrementTokenVersion(ctx context.Context, id string) error {
	ctx, cancel := WithQueryTimeout(ctx)
	defer cancel()
	query := `UPDATE tenants SET token_version = token_version + 1, updated_at = $1 WHERE id = $2 AND deleted_at IS NULL`
	result, err := r.db.ExecContext(ctx, query, time.Now().UTC(), id)
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to increment tenant token version", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to check affected rows", err)
	}
	if rows == 0 {
		return apperrors.New(apperrors.ErrNotFound, "tenant not found")
	}
	return nil
}

// List returns a paginated list of non-deleted tenants.
func (r *TenantRepository) List(ctx context.Context, offset, limit int) ([]tenant.Tenant, int, error) {
	ctx, cancel := WithQueryTimeout(ctx)
	defer cancel()
	countQuery := `SELECT COUNT(*) FROM tenants WHERE deleted_at IS NULL`
	var total int
	if err := r.db.QueryRowContext(ctx, countQuery).Scan(&total); err != nil {
		return nil, 0, apperrors.Wrap(apperrors.ErrInternal, "failed to count tenants", err)
	}

	query := `SELECT id, domain, issuer, algorithm, active_key_id, token_version, created_at, updated_at, deleted_at
		FROM tenants WHERE deleted_at IS NULL ORDER BY created_at DESC LIMIT $1 OFFSET $2`

	rows, err := r.db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, 0, apperrors.Wrap(apperrors.ErrInternal, "failed to list tenants", err)
	}
	defer rows.Close()

	var tenants []tenant.Tenant
	for rows.Next() {
		t, err := r.scanRow(rows)
		if err != nil {
			return nil, 0, err
		}
		tenants = append(tenants, t)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, apperrors.Wrap(apperrors.ErrInternal, "rows iteration error", err)
	}

	return tenants, total, nil
}

func (r *TenantRepository) scanTenant(row *sql.Row) (tenant.Tenant, error) {
	var t tenant.Tenant
	var alg, activeKeyID string
	var deletedAt *time.Time

	err := row.Scan(&t.ID, &t.Domain, &t.Issuer, &alg, &activeKeyID, &t.TokenVersion, &t.CreatedAt, &t.UpdatedAt, &deletedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return tenant.Tenant{}, apperrors.New(apperrors.ErrNotFound, "tenant not found")
		}
		return tenant.Tenant{}, apperrors.Wrap(apperrors.ErrInternal, "failed to scan tenant", err)
	}

	t.SigningConfig = tenant.SigningConfig{
		Algorithm:   tenant.Algorithm(alg),
		ActiveKeyID: activeKeyID,
	}
	t.DeletedAt = deletedAt
	return t, nil
}

type scannable interface {
	Scan(dest ...any) error
}

func (r *TenantRepository) scanRow(row scannable) (tenant.Tenant, error) {
	var t tenant.Tenant
	var alg, activeKeyID string
	var deletedAt *time.Time

	err := row.Scan(&t.ID, &t.Domain, &t.Issuer, &alg, &activeKeyID, &t.TokenVersion, &t.CreatedAt, &t.UpdatedAt, &deletedAt)
	if err != nil {
		return tenant.Tenant{}, apperrors.Wrap(apperrors.ErrInternal, "failed to scan tenant row", err)
	}

	t.SigningConfig = tenant.SigningConfig{
		Algorithm:   tenant.Algorithm(alg),
		ActiveKeyID: activeKeyID,
	}
	t.DeletedAt = deletedAt
	return t, nil
}
