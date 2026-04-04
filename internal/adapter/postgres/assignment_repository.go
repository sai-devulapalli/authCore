package postgres

import (
	"context"
	"database/sql"
	"time"

	"github.com/authplex/internal/domain/rbac"
	apperrors "github.com/authplex/pkg/sdk/errors"
)

// AssignmentRepository implements rbac.AssignmentRepository using PostgreSQL.
type AssignmentRepository struct {
	db       *sql.DB
	roleRepo rbac.RoleRepository
}

// NewAssignmentRepository creates a new PostgreSQL-backed assignment repository.
func NewAssignmentRepository(db *sql.DB, roleRepo rbac.RoleRepository) *AssignmentRepository {
	return &AssignmentRepository{db: db, roleRepo: roleRepo}
}

var _ rbac.AssignmentRepository = (*AssignmentRepository)(nil)

func (r *AssignmentRepository) Assign(ctx context.Context, userID, roleID, tenantID string) error {
	ctx, cancel := WithQueryTimeout(ctx)
	defer cancel()
	query := `INSERT INTO user_role_assignments (user_id, role_id, tenant_id, assigned_at)
		VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`

	_, err := r.db.ExecContext(ctx, query, userID, roleID, tenantID, time.Now().UTC())
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to assign role", err)
	}
	return nil
}

func (r *AssignmentRepository) Revoke(ctx context.Context, userID, roleID, tenantID string) error {
	ctx, cancel := WithQueryTimeout(ctx)
	defer cancel()
	query := `DELETE FROM user_role_assignments WHERE user_id = $1 AND role_id = $2 AND tenant_id = $3`

	result, err := r.db.ExecContext(ctx, query, userID, roleID, tenantID)
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to revoke role", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return apperrors.New(apperrors.ErrNotFound, "assignment not found")
	}
	return nil
}

func (r *AssignmentRepository) GetUserRoles(ctx context.Context, userID, tenantID string) ([]rbac.Role, error) {
	ctx, cancel := WithQueryTimeout(ctx)
	defer cancel()
	query := `SELECT r.id, r.tenant_id, r.name, r.description, r.permissions, r.created_at, r.updated_at
		FROM roles r
		JOIN user_role_assignments a ON r.id = a.role_id
		WHERE a.user_id = $1 AND a.tenant_id = $2`

	rows, err := r.db.QueryContext(ctx, query, userID, tenantID)
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrInternal, "failed to get user roles", err)
	}
	defer rows.Close()

	var roles []rbac.Role
	for rows.Next() {
		var role rbac.Role
		var perms pgArray

		err := rows.Scan(
			&role.ID, &role.TenantID, &role.Name, &role.Description,
			&perms, &role.CreatedAt, &role.UpdatedAt,
		)
		if err != nil {
			return nil, apperrors.Wrap(apperrors.ErrInternal, "failed to scan role", err)
		}
		role.Permissions = []string(perms)
		roles = append(roles, role)
	}
	if err := rows.Err(); err != nil {
		return nil, apperrors.Wrap(apperrors.ErrInternal, "failed to iterate user roles", err)
	}
	return roles, nil
}

func (r *AssignmentRepository) GetRoleUsers(ctx context.Context, roleID, tenantID string) ([]string, error) {
	ctx, cancel := WithQueryTimeout(ctx)
	defer cancel()
	query := `SELECT user_id FROM user_role_assignments WHERE role_id = $1 AND tenant_id = $2`

	rows, err := r.db.QueryContext(ctx, query, roleID, tenantID)
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrInternal, "failed to get role users", err)
	}
	defer rows.Close()

	var users []string
	for rows.Next() {
		var userID string
		if err := rows.Scan(&userID); err != nil {
			return nil, apperrors.Wrap(apperrors.ErrInternal, "failed to scan user id", err)
		}
		users = append(users, userID)
	}
	if err := rows.Err(); err != nil {
		return nil, apperrors.Wrap(apperrors.ErrInternal, "failed to iterate role users", err)
	}
	return users, nil
}
