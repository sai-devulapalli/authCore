-- 014_create_admin_users.sql
-- Admin user accounts for the management API.

CREATE TABLE IF NOT EXISTS admin_users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email         VARCHAR(254) NOT NULL UNIQUE,
    password_hash BYTEA NOT NULL,
    role          VARCHAR(50) NOT NULL DEFAULT 'readonly',
    tenant_ids    UUID[] NOT NULL DEFAULT '{}',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
