-- 008_create_mfa.sql
-- MFA enrollments and challenges.

CREATE TABLE IF NOT EXISTS totp_enrollments (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subject     UUID NOT NULL,
    tenant_id   UUID NOT NULL,
    secret      BYTEA NOT NULL,
    confirmed   BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(tenant_id, subject)
);

CREATE TABLE IF NOT EXISTS mfa_challenges (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subject                 UUID NOT NULL,
    tenant_id               UUID NOT NULL,
    methods                 TEXT[] NOT NULL DEFAULT '{}',
    expires_at              TIMESTAMPTZ NOT NULL,
    verified                BOOLEAN NOT NULL DEFAULT false,
    original_client_id      VARCHAR(100),
    original_redirect_uri   TEXT,
    original_scope          TEXT,
    original_state          TEXT,
    code_challenge          VARCHAR(128),
    code_challenge_method   VARCHAR(10),
    nonce                   VARCHAR(100)
);

CREATE INDEX IF NOT EXISTS idx_mfa_challenges_expires ON mfa_challenges(expires_at);
