-- 005_create_refresh_tokens.sql
-- Refresh token storage with rotation tracking.

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token       TEXT NOT NULL UNIQUE,
    client_id   VARCHAR(100) NOT NULL,
    subject     UUID NOT NULL,
    tenant_id   UUID NOT NULL,
    scope       TEXT NOT NULL DEFAULT '',
    family_id   UUID NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at  TIMESTAMPTZ,
    rotated     BOOLEAN NOT NULL DEFAULT false
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token ON refresh_tokens(token);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family ON refresh_tokens(family_id);
