package postgres

import (
	"context"
	"database/sql"
	"time"

	"github.com/authcore/internal/domain/rbac"
	apperrors "github.com/authcore/pkg/sdk/errors"
)

// RoleRepository implements rbac.RoleRepository using PostgreSQL.
type RoleRepository struct {
	db *sql.DB
}

// NewRoleRepository creates a new PostgreSQL-backed role repository.
func NewRoleRepository(db *sql.DB) *RoleRepository {
	return &RoleRepository{db: db}
}

var _ rbac.RoleRepository = (*RoleRepository)(nil)

func (r *RoleRepository) Create(ctx context.Context, role rbac.Role) error {
	ctx, cancel := WithQueryTimeout(ctx)
	defer cancel()
	query := `INSERT INTO roles (id, tenant_id, name, description, permissions, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`

	_, err := r.db.ExecContext(ctx, query,
		role.ID, role.TenantID, role.Name, role.Description,
		pgArray(role.Permissions), role.CreatedAt, role.UpdatedAt,
	)
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to create role", err)
	}
	return nil
}

func (r *RoleRepository) GetByID(ctx context.Context, id, tenantID string) (rbac.Role, error) {
	ctx, cancel := WithQueryTimeout(ctx)
	defer cancel()
	query := `SELECT id, tenant_id, name, description, permissions, created_at, updated_at
		FROM roles WHERE id = $1 AND tenant_id = $2`
	return r.scanRole(r.db.QueryRowContext(ctx, query, id, tenantID))
}

func (r *RoleRepository) GetByName(ctx context.Context, name, tenantID string) (rbac.Role, error) {
	ctx, cancel := WithQueryTimeout(ctx)
	defer cancel()
	query := `SELECT id, tenant_id, name, description, permissions, created_at, updated_at
		FROM roles WHERE name = $1 AND tenant_id = $2`
	return r.scanRole(r.db.QueryRowContext(ctx, query, name, tenantID))
}

func (r *RoleRepository) List(ctx context.Context, tenantID string) ([]rbac.Role, error) {
	ctx, cancel := WithQueryTimeout(ctx)
	defer cancel()
	query := `SELECT id, tenant_id, name, description, permissions, created_at, updated_at
		FROM roles WHERE tenant_id = $1`

	rows, err := r.db.QueryContext(ctx, query, tenantID)
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrInternal, "failed to list roles", err)
	}
	defer rows.Close()

	var roles []rbac.Role
	for rows.Next() {
		role, err := r.scanRoleRow(rows)
		if err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}
	if err := rows.Err(); err != nil {
		return nil, apperrors.Wrap(apperrors.ErrInternal, "failed to iterate roles", err)
	}
	return roles, nil
}

func (r *RoleRepository) Update(ctx context.Context, role rbac.Role) error {
	ctx, cancel := WithQueryTimeout(ctx)
	defer cancel()
	query := `UPDATE roles SET name = $1, description = $2, permissions = $3, updated_at = $4
		WHERE id = $5 AND tenant_id = $6`

	result, err := r.db.ExecContext(ctx, query,
		role.Name, role.Description, pgArray(role.Permissions),
		time.Now().UTC(), role.ID, role.TenantID,
	)
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to update role", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return apperrors.New(apperrors.ErrNotFound, "role not found")
	}
	return nil
}

func (r *RoleRepository) Delete(ctx context.Context, id, tenantID string) error {
	ctx, cancel := WithQueryTimeout(ctx)
	defer cancel()
	query := `DELETE FROM roles WHERE id = $1 AND tenant_id = $2`

	result, err := r.db.ExecContext(ctx, query, id, tenantID)
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to delete role", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return apperrors.New(apperrors.ErrNotFound, "role not found")
	}
	return nil
}

func (r *RoleRepository) scanRole(row *sql.Row) (rbac.Role, error) {
	var role rbac.Role
	var perms pgArray

	err := row.Scan(
		&role.ID, &role.TenantID, &role.Name, &role.Description,
		&perms, &role.CreatedAt, &role.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return rbac.Role{}, apperrors.New(apperrors.ErrNotFound, "role not found")
		}
		return rbac.Role{}, apperrors.Wrap(apperrors.ErrInternal, "failed to scan role", err)
	}
	role.Permissions = []string(perms)
	return role, nil
}

func (r *RoleRepository) scanRoleRow(rows *sql.Rows) (rbac.Role, error) {
	var role rbac.Role
	var perms pgArray

	err := rows.Scan(
		&role.ID, &role.TenantID, &role.Name, &role.Description,
		&perms, &role.CreatedAt, &role.UpdatedAt,
	)
	if err != nil {
		return rbac.Role{}, apperrors.Wrap(apperrors.ErrInternal, "failed to scan role", err)
	}
	role.Permissions = []string(perms)
	return role, nil
}
