-- 003_create_clients.sql
-- OAuth 2.0 client registry.
-- id: internal UUID primary key (auto-generated, not exposed to OAuth protocols).
-- client_id: user-visible OAuth client identifier (e.g. "careos-backend").

CREATE TABLE IF NOT EXISTS clients (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id           VARCHAR(100) NOT NULL UNIQUE,
    tenant_id           UUID NOT NULL,
    client_name         VARCHAR(200) NOT NULL,
    client_type         VARCHAR(20) NOT NULL CHECK (client_type IN ('public', 'confidential')),
    secret_hash         BYTEA,
    redirect_uris       TEXT[] NOT NULL DEFAULT '{}',
    allowed_scopes      TEXT[] NOT NULL DEFAULT '{}',
    allowed_grant_types TEXT[] NOT NULL DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at          TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_clients_tenant ON clients(tenant_id) WHERE deleted_at IS NULL;
