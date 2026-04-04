package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"time"

	"github.com/authplex/internal/domain/token"
	apperrors "github.com/authplex/pkg/sdk/errors"
)

// hashRefreshToken returns a SHA-256 hash of the token for storage.
// Refresh tokens are stored as hashes so that a database compromise
// does not expose usable tokens.
func hashRefreshToken(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// RefreshTokenRepository implements token.RefreshTokenRepository using PostgreSQL.
type RefreshTokenRepository struct {
	db *sql.DB
}

// NewRefreshTokenRepository creates a new PostgreSQL-backed refresh token repository.
func NewRefreshTokenRepository(db *sql.DB) *RefreshTokenRepository {
	return &RefreshTokenRepository{db: db}
}

var _ token.RefreshTokenRepository = (*RefreshTokenRepository)(nil)

func (r *RefreshTokenRepository) Store(ctx context.Context, rt token.RefreshToken) error {
	ctx, cancel := WithQueryTimeout(ctx)
	defer cancel()
	query := `INSERT INTO refresh_tokens (id, token, client_id, subject, tenant_id, scope, family_id, expires_at, created_at, rotated)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (id) DO UPDATE SET rotated = EXCLUDED.rotated, revoked_at = EXCLUDED.revoked_at`

	hashed := hashRefreshToken(rt.Token)
	_, err := r.db.ExecContext(ctx, query,
		rt.ID, hashed, rt.ClientID, rt.Subject, rt.TenantID,
		rt.Scope, rt.FamilyID, rt.ExpiresAt, rt.CreatedAt, rt.Rotated,
	)
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to store refresh token", err)
	}
	return nil
}

func (r *RefreshTokenRepository) GetByToken(ctx context.Context, tok string) (token.RefreshToken, error) {
	ctx, cancel := WithQueryTimeout(ctx)
	defer cancel()
	query := `SELECT id, token, client_id, subject, tenant_id, scope, family_id, expires_at, created_at, revoked_at, rotated
		FROM refresh_tokens WHERE token = $1`

	var rt token.RefreshToken
	var revokedAt *time.Time

	hashed := hashRefreshToken(tok)
	err := r.db.QueryRowContext(ctx, query, hashed).Scan(
		&rt.ID, &rt.Token, &rt.ClientID, &rt.Subject, &rt.TenantID,
		&rt.Scope, &rt.FamilyID, &rt.ExpiresAt, &rt.CreatedAt, &revokedAt, &rt.Rotated,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return token.RefreshToken{}, apperrors.New(apperrors.ErrNotFound, "refresh token not found")
		}
		return token.RefreshToken{}, apperrors.Wrap(apperrors.ErrInternal, "failed to query refresh token", err)
	}
	rt.RevokedAt = revokedAt
	return rt, nil
}

func (r *RefreshTokenRepository) RevokeByToken(ctx context.Context, tok string) error {
	hashed := hashRefreshToken(tok)
	query := `UPDATE refresh_tokens SET revoked_at = $1 WHERE token = $2 AND revoked_at IS NULL`
	_, err := r.db.ExecContext(ctx, query, time.Now().UTC(), hashed)
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to revoke refresh token", err)
	}
	return nil
}

func (r *RefreshTokenRepository) RevokeFamily(ctx context.Context, familyID string) error {
	query := `UPDATE refresh_tokens SET revoked_at = $1 WHERE family_id = $2 AND revoked_at IS NULL`
	_, err := r.db.ExecContext(ctx, query, time.Now().UTC(), familyID)
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to revoke token family", err)
	}
	return nil
}

func (r *RefreshTokenRepository) DeleteExpiredAndRevoked(ctx context.Context, olderThan time.Time) (int64, error) {
	query := `DELETE FROM refresh_tokens WHERE (revoked_at IS NOT NULL AND revoked_at < $1) OR (expires_at < $1)`
	result, err := r.db.ExecContext(ctx, query, olderThan)
	if err != nil {
		return 0, apperrors.Wrap(apperrors.ErrInternal, "failed to cleanup refresh tokens", err)
	}
	n, _ := result.RowsAffected()
	return n, nil
}
