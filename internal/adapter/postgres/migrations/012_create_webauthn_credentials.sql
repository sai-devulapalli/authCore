-- 012_create_webauthn_credentials.sql
-- WebAuthn / passkey credential storage.

CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subject          UUID NOT NULL,
    tenant_id        UUID NOT NULL,
    credential_id    BYTEA NOT NULL UNIQUE,
    public_key       BYTEA NOT NULL,
    aaguid           BYTEA,
    sign_count       INTEGER NOT NULL DEFAULT 0,
    attestation_type VARCHAR(50) NOT NULL DEFAULT 'none',
    display_name     VARCHAR(200),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_webauthn_subject ON webauthn_credentials(tenant_id, subject);
