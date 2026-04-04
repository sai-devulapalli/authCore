# AuthPlex Operations Runbook

## Incident Response Procedures

### Database Unavailable

**Symptoms:** HTTP 500 errors, connection timeout logs, health check failures.

**Diagnosis:**
1. Check database connectivity: `psql -h <host> -U authplex -d authplex -c "SELECT 1"`
2. Review database logs for OOM, disk full, or connection limit errors.
3. Check `pg_stat_activity` for long-running queries or lock contention.

**Resolution:**
1. If connection pool exhausted: restart the AuthPlex process to reset connections.
2. If disk full: expand storage or archive old audit events.
3. If Postgres crashed: restart the database service and verify replication status.
4. If DNS issue: verify database hostname resolves correctly.

**Mitigation:** All Postgres queries use `WithQueryTimeout` (5s default). Clients receive HTTP 500 with a generic error; no internal details are leaked.

---

### Redis Unavailable

**Symptoms:** Session creation/validation failures, increased latency on token operations.

**Diagnosis:**
1. Check Redis connectivity: `redis-cli -u <AUTHPLEX_REDIS_URL> ping`
2. Review Redis logs for memory limits or eviction.

**Resolution:**
1. Restart Redis if crashed.
2. If memory exhausted: increase `maxmemory` or review eviction policy.
3. If network partition: verify security group / firewall rules.

**Fallback:** AuthPlex degrades gracefully. Stateless JWT validation continues to work without Redis. Session-based flows will fail until Redis recovers.

---

### High Latency / Slow Queries

**Symptoms:** P99 latency spikes, query timeout errors in logs.

**Diagnosis:**
1. Check `pg_stat_statements` for slow queries.
2. Review OpenTelemetry traces for bottleneck spans.
3. Check connection pool saturation in metrics.

**Resolution:**
1. Identify and optimize slow queries (add indexes, rewrite).
2. If table bloat: run `VACUUM ANALYZE` on affected tables.
3. If connection pool saturated: increase pool size or scale horizontally.
4. If audit_events table is large: archive old events and add time-based partitioning.

---

### Auth Bypass Detected

**Symptoms:** Unauthorized access in audit logs, tokens issued without valid credentials.

**Immediate Actions (P0 - do these first):**
1. Rotate all tenant signing keys immediately via the key rotation endpoint.
2. Increment token version on affected tenants to invalidate all outstanding tokens.
3. Disable the compromised client in the client registry.

**Investigation:**
1. Query audit logs filtered by the suspicious actor/IP.
2. Review identity provider configurations for tampering.
3. Check for leaked client secrets in environment or logs.

**Post-Incident:**
1. Rotate all client secrets for the affected tenant.
2. Force password resets for affected users.
3. Review and tighten RBAC permissions.

---

### Rate Limiting Triggered

**Symptoms:** HTTP 429 responses, legitimate users reporting access denied.

**Diagnosis:**
1. Identify the source IPs or tenant IDs triggering rate limits.
2. Check if a single client is generating excessive traffic (misconfigured retry loop).

**Resolution:**
1. If legitimate traffic spike: temporarily increase rate limits.
2. If abuse: block the offending IP at the load balancer / WAF level.
3. If a single tenant is affected: review their client application for retry storms.

---

### Tenant Data Leak Suspected

**Symptoms:** User reports seeing another tenant's data, audit logs show cross-tenant access.

**Immediate Actions (P0):**
1. Disable the affected tenant(s) to stop further exposure.
2. Capture and preserve all audit logs for the time window.

**Investigation:**
1. Review Row-Level Security (RLS) policies on all tables.
2. Check for queries missing `tenant_id` filters.
3. Audit recent code deployments for regressions in tenant isolation.
4. Verify the tenant resolution middleware (`X-Tenant-ID` header / domain mode).

**Post-Incident:**
1. Notify affected tenants per data breach policy.
2. Add integration tests to prevent regression.
3. Review and strengthen RLS policies.

---

### Key Rotation Failure

**Symptoms:** Key rotation endpoint returns errors, JWK store shows no active key for a tenant.

**Diagnosis:**
1. Check JWK repository for the tenant: does an active key exist?
2. Review logs for database write failures during key generation.
3. Verify the encryption key (`AUTHPLEX_ENCRYPTION_KEY`) is set and valid.

**Resolution:**
1. If no active key: manually trigger key rotation via the management API.
2. If database write failed: resolve the database issue first (see "Database Unavailable").
3. If encryption key missing: set `AUTHPLEX_ENCRYPTION_KEY` and restart.

**Prevention:** Configure `AUTHPLEX_KEY_ROTATION_DAYS` (default 90) and monitor key expiry dates. Set up alerts for keys expiring within 7 days.
