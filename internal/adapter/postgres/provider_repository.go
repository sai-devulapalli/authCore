package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/authcore/internal/domain/identity"
	apperrors "github.com/authcore/pkg/sdk/errors"
)

// ProviderRepository implements identity.ProviderRepository using PostgreSQL.
type ProviderRepository struct {
	db *sql.DB
}

// NewProviderRepository creates a new PostgreSQL-backed provider repository.
func NewProviderRepository(db *sql.DB) *ProviderRepository {
	return &ProviderRepository{db: db}
}

var _ identity.ProviderRepository = (*ProviderRepository)(nil)

func (r *ProviderRepository) Create(ctx context.Context, p identity.IdentityProvider) error {
	ctx, cancel := WithQueryTimeout(ctx)
	defer cancel()
	extraJSON, _ := json.Marshal(p.ExtraConfig)
	query := `INSERT INTO identity_providers (id, tenant_id, provider_type, client_id, client_secret, scopes, discovery_url, auth_url, token_url, userinfo_url, enabled, extra_config, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`

	_, err := r.db.ExecContext(ctx, query,
		p.ID, p.TenantID, string(p.ProviderType), p.ClientID, p.ClientSecret,
		pgArray(p.Scopes), p.DiscoveryURL, p.AuthURL, p.TokenURL, p.UserInfoURL,
		p.Enabled, string(extraJSON), p.CreatedAt, p.UpdatedAt,
	)
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to create provider", err)
	}
	return nil
}

func (r *ProviderRepository) GetByID(ctx context.Context, id, tenantID string) (identity.IdentityProvider, error) {
	ctx, cancel := WithQueryTimeout(ctx)
	defer cancel()
	query := `SELECT id, tenant_id, provider_type, client_id, client_secret, scopes, discovery_url, auth_url, token_url, userinfo_url, enabled, extra_config, created_at, updated_at
		FROM identity_providers WHERE id = $1 AND tenant_id = $2`
	return r.scanProvider(r.db.QueryRowContext(ctx, query, id, tenantID))
}

func (r *ProviderRepository) GetByType(ctx context.Context, tenantID string, pt identity.ProviderType) (identity.IdentityProvider, error) {
	ctx, cancel := WithQueryTimeout(ctx)
	defer cancel()
	query := `SELECT id, tenant_id, provider_type, client_id, client_secret, scopes, discovery_url, auth_url, token_url, userinfo_url, enabled, extra_config, created_at, updated_at
		FROM identity_providers WHERE tenant_id = $1 AND provider_type = $2`
	return r.scanProvider(r.db.QueryRowContext(ctx, query, tenantID, string(pt)))
}

func (r *ProviderRepository) List(ctx context.Context, tenantID string) ([]identity.IdentityProvider, error) {
	ctx, cancel := WithQueryTimeout(ctx)
	defer cancel()
	query := `SELECT id, tenant_id, provider_type, client_id, client_secret, scopes, discovery_url, auth_url, token_url, userinfo_url, enabled, extra_config, created_at, updated_at
		FROM identity_providers WHERE tenant_id = $1`

	rows, err := r.db.QueryContext(ctx, query, tenantID)
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrInternal, "failed to list providers", err)
	}
	defer rows.Close()

	var providers []identity.IdentityProvider
	for rows.Next() {
		p, err := r.scanRow(rows)
		if err != nil {
			return nil, err
		}
		providers = append(providers, p)
	}
	return providers, rows.Err()
}

func (r *ProviderRepository) Update(ctx context.Context, p identity.IdentityProvider) error {
	ctx, cancel := WithQueryTimeout(ctx)
	defer cancel()
	extraJSON, _ := json.Marshal(p.ExtraConfig)
	query := `UPDATE identity_providers SET client_id = $1, client_secret = $2, scopes = $3, discovery_url = $4, auth_url = $5, token_url = $6, userinfo_url = $7, enabled = $8, extra_config = $9, updated_at = $10
		WHERE id = $11 AND tenant_id = $12`
	_, err := r.db.ExecContext(ctx, query,
		p.ClientID, p.ClientSecret, pgArray(p.Scopes), p.DiscoveryURL, p.AuthURL, p.TokenURL, p.UserInfoURL,
		p.Enabled, string(extraJSON), time.Now().UTC(), p.ID, p.TenantID,
	)
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to update provider", err)
	}
	return nil
}

func (r *ProviderRepository) Delete(ctx context.Context, id, tenantID string) error {
	ctx, cancel := WithQueryTimeout(ctx)
	defer cancel()
	query := `DELETE FROM identity_providers WHERE id = $1 AND tenant_id = $2`
	result, err := r.db.ExecContext(ctx, query, id, tenantID)
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to delete provider", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return apperrors.New(apperrors.ErrNotFound, "provider not found")
	}
	return nil
}

func (r *ProviderRepository) scanProvider(row *sql.Row) (identity.IdentityProvider, error) {
	var p identity.IdentityProvider
	var providerType string
	var scopes []string
	var extraJSON string

	err := row.Scan(
		&p.ID, &p.TenantID, &providerType, &p.ClientID, &p.ClientSecret,
		(*pgArray)(&scopes), &p.DiscoveryURL, &p.AuthURL, &p.TokenURL, &p.UserInfoURL,
		&p.Enabled, &extraJSON, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return identity.IdentityProvider{}, apperrors.New(apperrors.ErrNotFound, "provider not found")
		}
		return identity.IdentityProvider{}, apperrors.Wrap(apperrors.ErrInternal, "failed to scan provider", err)
	}

	p.ProviderType = identity.ProviderType(providerType)
	p.Scopes = scopes
	p.ExtraConfig = make(map[string]string)
	json.Unmarshal([]byte(extraJSON), &p.ExtraConfig) //nolint:errcheck
	return p, nil
}

type scannable2 interface {
	Scan(dest ...any) error
}

func (r *ProviderRepository) scanRow(row scannable2) (identity.IdentityProvider, error) {
	var p identity.IdentityProvider
	var providerType string
	var scopes []string
	var extraJSON string

	err := row.Scan(
		&p.ID, &p.TenantID, &providerType, &p.ClientID, &p.ClientSecret,
		(*pgArray)(&scopes), &p.DiscoveryURL, &p.AuthURL, &p.TokenURL, &p.UserInfoURL,
		&p.Enabled, &extraJSON, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		return identity.IdentityProvider{}, apperrors.Wrap(apperrors.ErrInternal, "failed to scan provider row", err)
	}

	p.ProviderType = identity.ProviderType(providerType)
	p.Scopes = scopes
	p.ExtraConfig = make(map[string]string)
	json.Unmarshal([]byte(extraJSON), &p.ExtraConfig) //nolint:errcheck
	return p, nil
}
