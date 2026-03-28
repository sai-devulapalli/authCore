-- 010_create_rbac.sql
-- Role-Based Access Control tables.

CREATE TABLE IF NOT EXISTS roles (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    name        TEXT NOT NULL,
    description TEXT DEFAULT '',
    permissions TEXT[] NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(tenant_id, name)
);

CREATE TABLE IF NOT EXISTS user_role_assignments (
    user_id     TEXT NOT NULL,
    role_id     TEXT NOT NULL,
    tenant_id   TEXT NOT NULL,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, role_id, tenant_id)
);

CREATE INDEX IF NOT EXISTS idx_user_roles ON user_role_assignments(user_id, tenant_id);
CREATE INDEX IF NOT EXISTS idx_role_users ON user_role_assignments(role_id, tenant_id);
