package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/authcore/internal/domain/identity"
	apperrors "github.com/authcore/pkg/sdk/errors"
)

// ExternalIdentityRepository implements identity.ExternalIdentityRepository using PostgreSQL.
type ExternalIdentityRepository struct {
	db *sql.DB
}

// NewExternalIdentityRepository creates a new PostgreSQL-backed external identity repository.
func NewExternalIdentityRepository(db *sql.DB) *ExternalIdentityRepository {
	return &ExternalIdentityRepository{db: db}
}

var _ identity.ExternalIdentityRepository = (*ExternalIdentityRepository)(nil)

func (r *ExternalIdentityRepository) Create(ctx context.Context, ei identity.ExternalIdentity) error {
	ctx, cancel := WithQueryTimeout(ctx)
	defer cancel()
	profileJSON, _ := json.Marshal(ei.ProfileData)
	query := `INSERT INTO external_identities (id, provider_id, external_subject, internal_subject, tenant_id, email, name, profile_data, linked_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

	_, err := r.db.ExecContext(ctx, query,
		ei.ID, ei.ProviderID, ei.ExternalSubject, ei.InternalSubject, ei.TenantID,
		ei.Email, ei.Name, string(profileJSON), ei.LinkedAt, ei.UpdatedAt,
	)
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to create external identity", err)
	}
	return nil
}

func (r *ExternalIdentityRepository) GetByExternalSubject(ctx context.Context, providerID, externalSubject string) (identity.ExternalIdentity, error) {
	ctx, cancel := WithQueryTimeout(ctx)
	defer cancel()
	query := `SELECT id, provider_id, external_subject, internal_subject, tenant_id, email, name, profile_data, linked_at, updated_at
		FROM external_identities WHERE provider_id = $1 AND external_subject = $2`
	return r.scanIdentity(r.db.QueryRowContext(ctx, query, providerID, externalSubject))
}

func (r *ExternalIdentityRepository) GetByInternalSubject(ctx context.Context, tenantID, internalSubject string) ([]identity.ExternalIdentity, error) {
	ctx, cancel := WithQueryTimeout(ctx)
	defer cancel()
	query := `SELECT id, provider_id, external_subject, internal_subject, tenant_id, email, name, profile_data, linked_at, updated_at
		FROM external_identities WHERE tenant_id = $1 AND internal_subject = $2`

	rows, err := r.db.QueryContext(ctx, query, tenantID, internalSubject)
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrInternal, "failed to query external identities", err)
	}
	defer rows.Close()

	var identities []identity.ExternalIdentity
	for rows.Next() {
		var ei identity.ExternalIdentity
		var profileJSON string
		if err := rows.Scan(
			&ei.ID, &ei.ProviderID, &ei.ExternalSubject, &ei.InternalSubject, &ei.TenantID,
			&ei.Email, &ei.Name, &profileJSON, &ei.LinkedAt, &ei.UpdatedAt,
		); err != nil {
			return nil, apperrors.Wrap(apperrors.ErrInternal, "failed to scan external identity", err)
		}
		ei.ProfileData = make(map[string]any)
		json.Unmarshal([]byte(profileJSON), &ei.ProfileData) //nolint:errcheck
		identities = append(identities, ei)
	}
	return identities, rows.Err()
}

func (r *ExternalIdentityRepository) Update(ctx context.Context, ei identity.ExternalIdentity) error {
	ctx, cancel := WithQueryTimeout(ctx)
	defer cancel()
	profileJSON, _ := json.Marshal(ei.ProfileData)
	query := `UPDATE external_identities SET email = $1, name = $2, profile_data = $3, updated_at = $4
		WHERE id = $5`
	_, err := r.db.ExecContext(ctx, query, ei.Email, ei.Name, string(profileJSON), time.Now().UTC(), ei.ID)
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to update external identity", err)
	}
	return nil
}

func (r *ExternalIdentityRepository) scanIdentity(row *sql.Row) (identity.ExternalIdentity, error) {
	var ei identity.ExternalIdentity
	var profileJSON string

	err := row.Scan(
		&ei.ID, &ei.ProviderID, &ei.ExternalSubject, &ei.InternalSubject, &ei.TenantID,
		&ei.Email, &ei.Name, &profileJSON, &ei.LinkedAt, &ei.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return identity.ExternalIdentity{}, apperrors.New(apperrors.ErrNotFound, "external identity not found")
		}
		return identity.ExternalIdentity{}, apperrors.Wrap(apperrors.ErrInternal, "failed to scan external identity", err)
	}

	ei.ProfileData = make(map[string]any)
	json.Unmarshal([]byte(profileJSON), &ei.ProfileData) //nolint:errcheck
	return ei, nil
}
