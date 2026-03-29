-- 016_audit_immutability.sql
-- Make audit_events table append-only (tamper-proof).
-- The application role cannot UPDATE or DELETE audit events.
-- Only INSERT and SELECT are permitted.

-- Create a restricted role for the application if it doesn't exist
DO $$
BEGIN
    -- Revoke UPDATE and DELETE on audit_events from PUBLIC
    REVOKE UPDATE, DELETE ON audit_events FROM PUBLIC;

    -- Create a rule that prevents UPDATE
    CREATE OR REPLACE RULE audit_no_update AS ON UPDATE TO audit_events DO INSTEAD NOTHING;

    -- Create a rule that prevents DELETE
    CREATE OR REPLACE RULE audit_no_delete AS ON DELETE TO audit_events DO INSTEAD NOTHING;
END $$;
