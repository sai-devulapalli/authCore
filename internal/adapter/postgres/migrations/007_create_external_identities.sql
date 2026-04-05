-- 007_create_external_identities.sql
-- Links external provider identities to internal subjects.

CREATE TABLE IF NOT EXISTS external_identities (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_id       UUID NOT NULL,
    external_subject  VARCHAR(500) NOT NULL,
    internal_subject  UUID NOT NULL,
    tenant_id         UUID NOT NULL,
    email             VARCHAR(254),
    name              VARCHAR(200),
    profile_data      JSONB NOT NULL DEFAULT '{}',
    linked_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(provider_id, external_subject)
);

CREATE INDEX IF NOT EXISTS idx_external_identities_internal ON external_identities(tenant_id, internal_subject);
