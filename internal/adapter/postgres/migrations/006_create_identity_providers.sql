-- 006_create_identity_providers.sql
-- External identity providers for social login.

CREATE TABLE IF NOT EXISTS identity_providers (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    provider_type   VARCHAR(50) NOT NULL,
    client_id       VARCHAR(200) NOT NULL,
    client_secret   BYTEA,
    scopes          TEXT[] NOT NULL DEFAULT '{}',
    discovery_url   TEXT,
    auth_url        TEXT,
    token_url       TEXT,
    userinfo_url    TEXT,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    extra_config    JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(tenant_id, provider_type)
);
