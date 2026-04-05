-- 002_create_tenants.sql
-- Creates the tenants table for multi-tenancy support.

CREATE TABLE IF NOT EXISTS tenants (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain          VARCHAR(253) NOT NULL UNIQUE,
    issuer          TEXT NOT NULL UNIQUE,
    algorithm       VARCHAR(10) NOT NULL,
    active_key_id   UUID,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at      TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_tenants_domain ON tenants(domain) WHERE deleted_at IS NULL;
