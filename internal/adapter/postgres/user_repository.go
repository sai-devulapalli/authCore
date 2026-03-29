package postgres

import (
	"context"
	"database/sql"
	"time"

	"github.com/authcore/internal/domain/user"
	apperrors "github.com/authcore/pkg/sdk/errors"
)

// UserRepository implements user.Repository using PostgreSQL.
type UserRepository struct {
	db *sql.DB
}

// NewUserRepository creates a new PostgreSQL-backed user repository.
func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db: db}
}

var _ user.Repository = (*UserRepository)(nil)

func (r *UserRepository) Create(ctx context.Context, u user.User) error {
	ctx, cancel := WithQueryTimeout(ctx)
	defer cancel()
	query := `INSERT INTO users (id, tenant_id, email, phone, password_hash, name, email_verified, phone_verified, enabled, token_version, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`

	_, err := r.db.ExecContext(ctx, query,
		u.ID, u.TenantID, u.Email, u.Phone, u.PasswordHash, u.Name,
		u.EmailVerified, u.PhoneVerified, u.Enabled, u.TokenVersion, u.CreatedAt, u.UpdatedAt,
	)
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to create user", err)
	}
	return nil
}

func (r *UserRepository) GetByID(ctx context.Context, id, tenantID string) (user.User, error) {
	ctx, cancel := WithQueryTimeout(ctx)
	defer cancel()
	query := `SELECT id, tenant_id, email, phone, password_hash, name, email_verified, phone_verified, enabled, token_version, created_at, updated_at, deleted_at
		FROM users WHERE id = $1 AND tenant_id = $2`
	return r.scanUser(r.db.QueryRowContext(ctx, query, id, tenantID))
}

func (r *UserRepository) GetByEmail(ctx context.Context, email, tenantID string) (user.User, error) {
	ctx, cancel := WithQueryTimeout(ctx)
	defer cancel()
	query := `SELECT id, tenant_id, email, phone, password_hash, name, email_verified, phone_verified, enabled, token_version, created_at, updated_at, deleted_at
		FROM users WHERE email = $1 AND tenant_id = $2 AND deleted_at IS NULL`
	return r.scanUser(r.db.QueryRowContext(ctx, query, email, tenantID))
}

func (r *UserRepository) GetByPhone(ctx context.Context, phone, tenantID string) (user.User, error) {
	query := `SELECT id, tenant_id, email, phone, password_hash, name, email_verified, phone_verified, enabled, token_version, created_at, updated_at, deleted_at
		FROM users WHERE phone = $1 AND tenant_id = $2 AND phone != '' AND deleted_at IS NULL`
	return r.scanUser(r.db.QueryRowContext(ctx, query, phone, tenantID))
}

func (r *UserRepository) Update(ctx context.Context, u user.User) error {
	query := `UPDATE users SET email = $1, phone = $2, password_hash = $3, name = $4, email_verified = $5, phone_verified = $6, enabled = $7, updated_at = $8
		WHERE id = $9 AND tenant_id = $10`
	_, err := r.db.ExecContext(ctx, query,
		u.Email, u.Phone, u.PasswordHash, u.Name, u.EmailVerified, u.PhoneVerified, u.Enabled,
		time.Now().UTC(), u.ID, u.TenantID,
	)
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to update user", err)
	}
	return nil
}

func (r *UserRepository) Delete(ctx context.Context, id, tenantID string) error {
	query := `UPDATE users SET deleted_at = $1 WHERE id = $2 AND tenant_id = $3 AND deleted_at IS NULL`
	result, err := r.db.ExecContext(ctx, query, time.Now().UTC(), id, tenantID)
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to delete user", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return apperrors.New(apperrors.ErrNotFound, "user not found")
	}
	return nil
}

func (r *UserRepository) IncrementTokenVersion(ctx context.Context, id, tenantID string) error {
	query := `UPDATE users SET token_version = token_version + 1, updated_at = $1 WHERE id = $2 AND tenant_id = $3 AND deleted_at IS NULL`
	result, err := r.db.ExecContext(ctx, query, time.Now().UTC(), id, tenantID)
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to increment user token version", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return apperrors.New(apperrors.ErrNotFound, "user not found")
	}
	return nil
}

func (r *UserRepository) scanUser(row *sql.Row) (user.User, error) {
	var u user.User
	var deletedAt *time.Time

	err := row.Scan(
		&u.ID, &u.TenantID, &u.Email, &u.Phone, &u.PasswordHash, &u.Name,
		&u.EmailVerified, &u.PhoneVerified, &u.Enabled, &u.TokenVersion,
		&u.CreatedAt, &u.UpdatedAt, &deletedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return user.User{}, apperrors.New(apperrors.ErrNotFound, "user not found")
		}
		return user.User{}, apperrors.Wrap(apperrors.ErrInternal, "failed to scan user", err)
	}
	u.DeletedAt = deletedAt
	return u, nil
}
