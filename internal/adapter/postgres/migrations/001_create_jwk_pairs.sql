-- 001_create_jwk_pairs.sql
-- Creates the JWK key pairs table for storing tenant signing keys.

CREATE TABLE IF NOT EXISTS jwk_pairs (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL,
    key_type    VARCHAR(10) NOT NULL,
    algorithm   VARCHAR(10) NOT NULL,
    key_use     VARCHAR(3) NOT NULL DEFAULT 'sig',
    private_key BYTEA NOT NULL,
    public_key  BYTEA NOT NULL,
    active      BOOLEAN NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_jwk_pairs_tenant_active ON jwk_pairs(tenant_id, active);
