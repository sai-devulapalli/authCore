-- 009_add_user_phone.sql
-- Add phone number support to users table.

ALTER TABLE users ADD COLUMN IF NOT EXISTS phone VARCHAR(30) DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS phone_verified BOOLEAN NOT NULL DEFAULT false;

CREATE INDEX IF NOT EXISTS idx_users_tenant_phone ON users(tenant_id, phone) WHERE phone != '' AND deleted_at IS NULL;
