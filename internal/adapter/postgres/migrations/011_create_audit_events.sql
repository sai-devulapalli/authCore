-- 011_create_audit_events.sql
-- Audit event logging for compliance.

CREATE TABLE IF NOT EXISTS audit_events (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    actor_id        TEXT NOT NULL DEFAULT '',
    actor_type      TEXT NOT NULL DEFAULT 'system',
    action          TEXT NOT NULL,
    resource_type   TEXT NOT NULL DEFAULT '',
    resource_id     TEXT NOT NULL DEFAULT '',
    ip_address      TEXT DEFAULT '',
    user_agent      TEXT DEFAULT '',
    details         JSONB NOT NULL DEFAULT '{}',
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_audit_tenant_time ON audit_events(tenant_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_events(tenant_id, actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_events(tenant_id, action);
