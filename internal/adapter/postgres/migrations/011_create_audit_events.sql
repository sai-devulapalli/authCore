-- 011_create_audit_events.sql
-- Audit event logging for compliance.

CREATE TABLE IF NOT EXISTS audit_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    actor_id        VARCHAR(100) NOT NULL DEFAULT '',
    actor_type      VARCHAR(20) NOT NULL DEFAULT 'system',
    action          VARCHAR(100) NOT NULL,
    resource_type   VARCHAR(100) NOT NULL DEFAULT '',
    resource_id     VARCHAR(100) NOT NULL DEFAULT '',
    ip_address      VARCHAR(45) DEFAULT '',
    user_agent      TEXT DEFAULT '',
    details         JSONB NOT NULL DEFAULT '{}',
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_audit_tenant_time ON audit_events(tenant_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_events(tenant_id, actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_events(tenant_id, action);
