# AuthPlex Incident Response Playbook

**Version:** 1.0  
**Date:** 2026-04-05  
**Classification:** Internal — Restricted  
**Owner:** Security / Platform Team

---

## Incident Severity Definitions

| Severity | Definition | Response Time | Examples |
|----------|-----------|---------------|---------|
| **P0 — Critical** | Active breach; data exfiltration likely; production authentication unavailable | 15 minutes | Compromised admin key in use, tenant isolation breach, JWT key exposure |
| **P1 — High** | Imminent breach risk; significant service degradation | 1 hour | Credential stuffing attack in progress, Redis compromised |
| **P2 — Medium** | Suspected compromise; limited impact | 4 hours | Anomalous audit events, failed MFA flood |
| **P3 — Low** | Policy violation; no active exploitation | 24 hours | Key found in git (not yet exploited) |

---

## General Incident Response Steps

1. **Detect** — Identify the incident via monitoring, user report, or security alert
2. **Declare** — Assign severity, create incident channel, notify on-call
3. **Contain** — Stop the bleeding immediately (see scenario-specific steps)
4. **Eradicate** — Remove root cause
5. **Recover** — Restore to known-good state
6. **Review** — Post-incident review within 48 hours

---

## Scenario 1 — Compromised Admin API Key

**Severity:** P0  
**GDPR Notification Required:** If admin key used to access/exfiltrate personal data — yes, within 72 hours

### Detection Signals

```bash
# Audit log patterns indicating key compromise:
# 1. Admin actions from unexpected IP
SELECT * FROM audit_events
WHERE event_type IN ('tenant_created', 'user_deleted', 'client_created', 'rbac_role_assigned')
  AND actor_type = 'admin'
  AND created_at > NOW() - INTERVAL '24 hours'
ORDER BY created_at DESC;

# 2. Key found in public repository
# Search GitHub: https://github.com/search?q=authplex_admin_&type=code

# 3. Unusual volume of admin API calls
SELECT
    DATE_TRUNC('hour', created_at) AS hour,
    COUNT(*) AS event_count,
    ip_address
FROM audit_events
WHERE actor_type = 'admin'
GROUP BY hour, ip_address
ORDER BY hour DESC;
```

**Alert triggers:**
- `admin_login` event from IP not in allowlist
- More than 50 admin API calls in 1 hour from any single IP
- Any admin action at unusual hours (define per organization)

### Immediate Containment (Execute within 15 minutes)

```bash
# Step 1: Identify all admin actions in the past 30 days
psql $AUTHPLEX_DB_URL <<EOF
SELECT
    event_type,
    actor_id,
    ip_address,
    user_agent,
    metadata,
    created_at
FROM audit_events
WHERE actor_type = 'admin'
  AND created_at > NOW() - INTERVAL '30 days'
ORDER BY created_at DESC;
EOF

# Step 2: Generate new admin key
NEW_KEY="authplex_admin_$(openssl rand -hex 32)"
echo "NEW KEY: ${NEW_KEY}"  # Store securely — do NOT paste in Slack

# Step 3: Update secrets manager BEFORE restarting
# AWS:
aws secretsmanager update-secret \
  --secret-id authplex/production/admin-key \
  --secret-string "${NEW_KEY}"

# Step 4: Rolling restart (zero-downtime key rotation)
kubectl rollout restart deployment/authplex -n auth
kubectl rollout status deployment/authplex -n auth --timeout=120s

# Step 5: Verify old key is rejected
OLD_KEY="authplex_admin_the_old_key_value"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer ${OLD_KEY}" \
  https://auth.example.com/api/v1/admin/tenants)
echo "Old key status: ${STATUS}"  # Expected: 401

# Step 6: Verify new key works
STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer ${NEW_KEY}" \
  https://auth.example.com/api/v1/admin/tenants)
echo "New key status: ${STATUS}"  # Expected: 200
```

### Eradication

```bash
# Audit all admin actions taken with the compromised key
psql $AUTHPLEX_DB_URL <<EOF
-- Review actions taken during compromise window
SELECT event_type, target_type, target_id, metadata, created_at, ip_address
FROM audit_events
WHERE actor_type = 'admin'
  AND created_at BETWEEN '${COMPROMISE_START}' AND '${COMPROMISE_END}'
ORDER BY created_at;

-- Check for new tenants created (attacker may have created a backdoor tenant)
SELECT id, name, created_at FROM tenants
WHERE created_at > '${COMPROMISE_START}' - INTERVAL '1 hour'
ORDER BY created_at;

-- Check for new OAuth clients created
SELECT id, tenant_id, name, created_at FROM oauth_clients
WHERE created_at > '${COMPROMISE_START}' - INTERVAL '1 hour';

-- Check for new admin users or role escalations
SELECT * FROM rbac_assignments
WHERE role = 'tenant_admin'
  AND created_at > '${COMPROMISE_START}' - INTERVAL '1 hour';
EOF
```

### Recovery

```bash
# Remove any backdoor resources created during compromise
# EXAMPLE — adjust based on eradication findings:
curl -X DELETE https://auth.example.com/api/v1/admin/tenants/${BACKDOOR_TENANT_ID} \
     -H "Authorization: Bearer ${NEW_KEY}"

# Notify all tenant admins of the incident (if personal data was accessed)
# Use SMTP integration or direct database notification

# Update all consumers of the admin key (CI/CD pipelines, scripts, monitoring)
# Verify rotation in git secrets and CI environments
```

### Post-Incident Review Checklist

```
[ ] Root cause identified (how was key exfiltrated?)
[ ] Timeline documented (first use, discovery, containment)
[ ] All actions taken with compromised key reviewed
[ ] Backdoor resources removed
[ ] Key rotation completed and verified
[ ] All consumers updated with new key
[ ] GDPR assessment: was personal data accessed? If yes, notify DPA within 72h
[ ] Process improvement: implement key expiry feature (see COMPLIANCE.md gap #2)
[ ] Add monitoring alert for admin actions from new IPs
[ ] Update runbook with lessons learned
```

---

## Scenario 2 — Mass Credential Stuffing Attack

**Severity:** P1  
**GDPR Notification Required:** Only if passwords actually compromised — unlikely if bcrypt holds

### Detection Signals

```bash
# Spike in failed login events
SELECT
    DATE_TRUNC('minute', created_at) AS minute,
    COUNT(*) AS failures,
    COUNT(DISTINCT ip_address) AS unique_ips,
    COUNT(DISTINCT user_id) AS unique_users
FROM audit_events
WHERE event_type = 'login_failed'
  AND created_at > NOW() - INTERVAL '1 hour'
GROUP BY minute
ORDER BY minute DESC;

# Threshold: > 100 failures per minute across > 10 IPs = credential stuffing
```

**Alert triggers:**
- `login_failed` events > 100/minute from > 5 unique IPs
- Rate limit hits (`http_429`) spike > 200% of baseline
- Single user account with > 10 consecutive failed logins

### Immediate Containment

```bash
# Step 1: Enable emergency rate limiting
# Reduce via environment variable + rolling restart
# From 20 req/min to 5 req/min:
export AUTHPLEX_RATE_LIMIT_PER_MIN=5
kubectl set env deployment/authplex AUTHPLEX_RATE_LIMIT_PER_MIN=5 -n auth

# Step 2: Extract attacker IP ranges
psql $AUTHPLEX_DB_URL <<EOF
SELECT
    ip_address,
    COUNT(*) AS failure_count,
    MIN(created_at) AS first_seen,
    MAX(created_at) AS last_seen
FROM audit_events
WHERE event_type = 'login_failed'
  AND created_at > NOW() - INTERVAL '2 hours'
GROUP BY ip_address
HAVING COUNT(*) > 10
ORDER BY failure_count DESC
LIMIT 50;
EOF

# Step 3: Block top attacking IPs at nginx/WAF level
# nginx:
echo "deny 1.2.3.4;" >> /etc/nginx/conf.d/blocklist.conf
nginx -s reload

# AWS WAF (if deployed):
aws wafv2 update-ip-set \
  --name authplex-blocklist \
  --scope REGIONAL \
  --id ${IP_SET_ID} \
  --addresses "1.2.3.4/32" "5.6.7.8/32"

# Step 4: Identify potentially compromised accounts
psql $AUTHPLEX_DB_URL <<EOF
SELECT DISTINCT
    u.email,
    u.id,
    COUNT(ae.id) AS failed_attempts
FROM audit_events ae
JOIN users u ON ae.user_id = u.id
WHERE ae.event_type = 'login_failed'
  AND ae.created_at > NOW() - INTERVAL '2 hours'
GROUP BY u.email, u.id
HAVING COUNT(ae.id) >= 5
ORDER BY failed_attempts DESC;
EOF
```

### Eradication

```bash
# Force re-authentication for potentially compromised accounts
# Revoke all active sessions for affected users
psql $AUTHPLEX_DB_URL <<EOF
-- Revoke sessions for affected users (example for user IDs from detection query)
UPDATE sessions SET revoked_at = NOW(), revoke_reason = 'security_incident'
WHERE user_id IN (SELECT user_id FROM /* compromised_users_temp_table */)
  AND revoked_at IS NULL;

-- Also revoke refresh tokens
UPDATE refresh_tokens SET revoked_at = NOW()
WHERE user_id IN (SELECT user_id FROM /* compromised_users_temp_table */)
  AND revoked_at IS NULL;
EOF

# Check HaveIBeenPwned for affected email addresses
# curl "https://haveibeenpwned.com/api/v3/breachedaccount/${EMAIL}" \
#   -H "hibp-api-key: YOUR_KEY"
```

### Recovery

```bash
# Send password reset emails to affected accounts
# Use SMTP integration:
curl -X POST https://auth.example.com/api/v1/admin/users/bulk-password-reset \
     -H "Authorization: Bearer ${ADMIN_KEY}" \
     -d '{"user_ids": ["uuid1", "uuid2"], "reason": "security_incident"}'

# Restore normal rate limits after attack subsides (30+ minutes of normal traffic)
kubectl set env deployment/authplex AUTHPLEX_RATE_LIMIT_PER_MIN=20 -n auth

# Enable MFA enforcement for affected tenant(s)
curl -X PATCH https://auth.example.com/api/v1/admin/tenants/${TENANT_ID} \
     -H "Authorization: Bearer ${ADMIN_KEY}" \
     -d '{"mfa_required": true}'
```

### Post-Incident Review Checklist

```
[ ] Attack timeline documented (start, peak, end)
[ ] Number of affected accounts identified and notified
[ ] Source IPs and ASNs documented (for WAF rule improvement)
[ ] Root cause: were credentials from a specific breach source? 
[ ] Implementation: account lockout feature (COMPLIANCE.md gap #5)
[ ] Implementation: HaveIBeenPwned integration (COMPLIANCE.md gap #6)
[ ] Consider: Cloudflare Turnstile / reCAPTCHA integration
[ ] Update WAF rules with attack signatures
[ ] Brief all affected tenant admins
```

---

## Scenario 3 — JWT Signing Key Exposed

**Severity:** P0 — All tokens are forgeable until key is rotated  
**GDPR Notification Required:** Yes if key was actively exploited to forge tokens

### Detection Signals

```bash
# Key found in git history
git log --all -p | grep -E 'BEGIN.*PRIVATE KEY' | head -5

# Key found in logs (should not happen, but check)
grep -iE 'BEGIN.*PRIVATE' /var/log/authplex/*.log

# Anomalous token issuance (attacker using forged tokens)
SELECT
    user_id,
    tenant_id,
    ip_address,
    COUNT(*) AS request_count
FROM audit_events
WHERE event_type IN ('api_access', 'resource_access')
  AND created_at > NOW() - INTERVAL '1 hour'
GROUP BY user_id, tenant_id, ip_address
HAVING COUNT(*) > 1000  -- abnormally high activity
ORDER BY request_count DESC;
```

### Immediate Containment (Complete within 30 minutes)

```bash
# Step 1: Generate new RSA key pair (use 4096-bit for extra margin)
openssl genrsa -out /tmp/new_jwt_key.pem 4096
# OR EC key:
openssl ecparam -name prime256v1 -genkey -noout -out /tmp/new_jwt_key.pem

# Step 2: Update secrets manager
aws secretsmanager update-secret \
  --secret-id authplex/production/jwt-private-key \
  --secret-string "$(cat /tmp/new_jwt_key.pem)"

# Delete the key from disk immediately
shred -u /tmp/new_jwt_key.pem

# Step 3: Rolling restart — new key takes effect
# All existing access tokens are immediately invalid (signed with old key)
# Clients will receive 401 and re-authenticate automatically
kubectl rollout restart deployment/authplex -n auth
kubectl rollout status deployment/authplex -n auth

# Step 4: Verify new JWKS is published
curl https://auth.example.com/.well-known/jwks.json | jq '.keys[0].kid'

# Step 5: Force revocation of ALL refresh tokens
# (Refresh tokens can be exchanged for new access tokens — must also revoke)
psql $AUTHPLEX_DB_URL <<EOF
UPDATE refresh_tokens
SET revoked_at = NOW(), revoke_reason = 'signing_key_rotation'
WHERE revoked_at IS NULL;
EOF

# Step 6: Notify all downstream resource servers to clear JWKS cache
# Document all services that cache JWKS and contact their operators
```

### Eradication

```bash
# Remove old key from all storage locations
# 1. Secrets manager: already updated in containment
# 2. Any backups that may contain the key:
#    - Review S3 backup contents
#    - Rotate if needed
# 3. Git history (if key was committed):
git filter-repo --path-glob '*.pem' --invert-paths
git filter-repo --replace-text expressions.txt  # expressions.txt: literal:PRIVATE KEY==>REDACTED

# Push cleaned history (requires force push — coordinate with team)
git push --force-with-lease origin main

# Rotate the leaked key in any downstream system that trusted it
# (Any service that hard-coded the public key for verification)
```

### Recovery

```bash
# Monitor for forged token usage (attacker may have pre-generated tokens)
# After key rotation, all valid tokens must be re-issued with new key
# Forged tokens from old key will fail verification

# Verify new tokens work
TOKEN=$(curl -s -X POST https://auth.example.com/token \
  -d "grant_type=client_credentials&client_id=TEST_CLIENT&client_secret=TEST_SECRET" \
  | jq -r '.access_token')

# Decode and verify kid matches new key
echo "${TOKEN}" | cut -d. -f1 | base64 -d 2>/dev/null | jq '.kid'

# Monitor error rates — expect spike of 401s as clients re-authenticate, then normalization
```

### Post-Incident Review Checklist

```
[ ] Root cause: where was the key exposed? (git, logs, env var, container image)
[ ] Timeline: how long was key exposed before detection?
[ ] Were any forged tokens detected in audit logs? (look for users with unusual activity)
[ ] All downstream JWKS caches cleared
[ ] All refresh tokens revoked
[ ] Git history cleaned if key was committed
[ ] Implement: key versioning with `kid` (THREAT_MODEL.md T-02 recommendation)
[ ] Implement: automatic 90-day key rotation
[ ] Add monitoring: alert on any key-like string appearing in logs
[ ] GDPR assessment: if attacker impersonated users to access data, 72h notification required
```

---

## Scenario 4 — Tenant Data Isolation Breach

**Severity:** P0 — Potential PHI exposure; GDPR 72-hour notification required  
**GDPR Notification Required:** Yes, immediately upon confirmation

### Detection Signals

```bash
# Audit log shows cross-tenant resource access
SELECT
    ae.user_id,
    ae.tenant_id AS token_tenant,
    ae.metadata->>'resource_tenant_id' AS resource_tenant,
    ae.event_type,
    ae.created_at
FROM audit_events ae
WHERE ae.tenant_id != (ae.metadata->>'resource_tenant_id')::uuid
  AND ae.created_at > NOW() - INTERVAL '24 hours';

# User reports seeing wrong data (customer complaint)
# Check: does the user's JWT tenant_id match the tenant whose data they saw?

# Anomalous access patterns
SELECT user_id, COUNT(DISTINCT tenant_id) AS tenant_count
FROM audit_events
WHERE created_at > NOW() - INTERVAL '1 hour'
GROUP BY user_id
HAVING COUNT(DISTINCT tenant_id) > 1;  -- User accessing multiple tenants = suspicious
```

### Immediate Containment

```bash
# Step 1: Identify scope — which tenants are affected?
# Run the detection query above to identify:
AFFECTED_TENANT_A="tenant-id-whose-data-was-exposed"
AFFECTED_TENANT_B="tenant-id-whose-user-accessed-wrong-data"

# Step 2: Suspend affected tenants if ongoing breach
curl -X PATCH https://auth.example.com/api/v1/admin/tenants/${AFFECTED_TENANT_A} \
     -H "Authorization: Bearer ${ADMIN_KEY}" \
     -d '{"status": "suspended", "reason": "security_investigation"}'

# Step 3: Revoke ALL sessions for affected tenants
psql $AUTHPLEX_DB_URL <<EOF
UPDATE sessions SET revoked_at = NOW(), revoke_reason = 'security_incident'
WHERE tenant_id IN ('${AFFECTED_TENANT_A}', '${AFFECTED_TENANT_B}')
  AND revoked_at IS NULL;

UPDATE refresh_tokens SET revoked_at = NOW()
WHERE tenant_id IN ('${AFFECTED_TENANT_A}', '${AFFECTED_TENANT_B}')
  AND revoked_at IS NULL;
EOF

# Step 4: Preserve evidence — do NOT delete audit logs
# Create a read-only snapshot of relevant audit entries:
psql $AUTHPLEX_DB_URL <<EOF
CREATE TABLE incident_evidence_$(date +%Y%m%d) AS
SELECT * FROM audit_events
WHERE (tenant_id = '${AFFECTED_TENANT_A}' OR tenant_id = '${AFFECTED_TENANT_B}')
  AND created_at > NOW() - INTERVAL '7 days';
EOF
```

### Eradication

```bash
# Identify root cause — likely candidates:
# 1. Missing tenant_id filter in a specific query
# 2. RLS policy not applied to a table
# 3. Middleware bug that sets wrong tenant context

# Check RLS status on all tables:
psql $AUTHPLEX_DB_URL <<EOF
SELECT tablename, rowsecurity, forcerowsecurity
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY tablename;
EOF

# Test every endpoint with cross-tenant credentials (see PENTEST_CHECKLIST.md PT-TI-*)
# Add a regression test immediately:
# go test ./e2e/... -run TestTenantIsolation

# Deploy fix with hotfix branch (never bypass tests)
```

### Recovery

```bash
# After fix is deployed and tested:

# Re-enable affected tenants
curl -X PATCH https://auth.example.com/api/v1/admin/tenants/${AFFECTED_TENANT_A} \
     -H "Authorization: Bearer ${ADMIN_KEY}" \
     -d '{"status": "active"}'

# Notify affected tenants (GDPR Article 33 — 72-hour requirement)
# Email must include:
# - What happened
# - What data was potentially accessed
# - When it occurred
# - What has been done
# - What the tenant should do (if anything)
# - Contact for further questions

# If PHI involved, notify supervisory authority (DPA)
```

### Post-Incident Review Checklist

```
[ ] Root cause: specific query or middleware bug identified
[ ] Number of affected records determined
[ ] Data accessed: was it read-only or were writes made?
[ ] All affected tenants notified (GDPR Art. 33 — 72h from awareness)
[ ] DPA notified if high risk to individuals
[ ] Fix deployed and regression test added
[ ] All related queries audited for similar issues
[ ] RLS verified on all tenant-scoped tables (use detection query above)
[ ] Cross-tenant penetration tests executed and passing
[ ] Legal counsel briefed
[ ] PR post-mortem document shared with team
```

---

## Scenario 5 — Redis Compromise (Session Token Theft)

**Severity:** P1  
**GDPR Notification Required:** Possibly — if attacker actively used stolen tokens to access personal data

### Detection Signals

```bash
# Redis AUTH failure spike
# Check Redis logs:
docker logs redis 2>&1 | grep -c "WRONGPASS"
# Or in Kubernetes:
kubectl logs -n data deploy/redis | grep "WRONGPASS" | tail -20

# Unexpected Redis commands (if Redis is monitored)
# redis-cli MONITOR | grep -v "PING" | head -100

# Sessions invalidated unexpectedly (attacker flushed Redis)
# Spike in re-authentication events:
SELECT DATE_TRUNC('minute', created_at), COUNT(*)
FROM audit_events
WHERE event_type = 'login_success'
  AND created_at > NOW() - INTERVAL '30 minutes'
GROUP BY 1 ORDER BY 1;

# Anomalous session reuse from different IPs
SELECT
    session_id,
    COUNT(DISTINCT ip_address) AS ip_count,
    array_agg(DISTINCT ip_address) AS ips
FROM audit_events
WHERE event_type = 'api_access'
  AND created_at > NOW() - INTERVAL '1 hour'
GROUP BY session_id
HAVING COUNT(DISTINCT ip_address) > 2;  -- Same token from many IPs = theft
```

### Immediate Containment

```bash
# Step 1: Flush ALL session namespaces from Redis
# This forces all users to re-authenticate — high impact but necessary
redis-cli -u "${AUTHPLEX_REDIS_URL}" KEYS "authplex:session:*" | \
  xargs redis-cli -u "${AUTHPLEX_REDIS_URL}" DEL

# Also flush refresh tokens, MFA states, OTPs:
redis-cli -u "${AUTHPLEX_REDIS_URL}" KEYS "authplex:*" | \
  xargs redis-cli -u "${AUTHPLEX_REDIS_URL}" DEL

# Step 2: Also revoke in Postgres (in case Redis is restored from attacker's dump)
psql $AUTHPLEX_DB_URL <<EOF
UPDATE sessions SET revoked_at = NOW(), revoke_reason = 'redis_compromise'
WHERE revoked_at IS NULL;

UPDATE refresh_tokens SET revoked_at = NOW()
WHERE revoked_at IS NULL;
EOF

# Step 3: Immediately rotate Redis password
NEW_REDIS_PASS="$(openssl rand -hex 32)"

# Update Redis config
redis-cli -u "${AUTHPLEX_REDIS_URL}" CONFIG SET requirepass "${NEW_REDIS_PASS}"

# Update secrets manager
aws secretsmanager update-secret \
  --secret-id authplex/production/redis-password \
  --secret-string "${NEW_REDIS_PASS}"

# Step 4: Restart AuthPlex with new Redis credentials
kubectl rollout restart deployment/authplex -n auth
```

### Eradication

```bash
# Check Redis for persistence modules (attacker may have installed one)
redis-cli -u "redis://:${NEW_REDIS_PASS}@redis:6379" MODULE LIST
# Expected: empty list. Any module here is suspicious.

# Check Redis configuration for anomalies
redis-cli -u "redis://:${NEW_REDIS_PASS}@redis:6379" CONFIG GET "*" | \
  grep -A1 -E 'requirepass|bind|protected-mode|rename-command'

# Check if attacker used Redis as a pivot to other systems
# Look for: SLAVEOF commands, CONFIG REWRITE, BGSAVE to unusual path
redis-cli -u "redis://:${NEW_REDIS_PASS}@redis:6379" COMMAND GETKEYS SLAVEOF

# Review Redis slow log for unusual commands
redis-cli -u "redis://:${NEW_REDIS_PASS}@redis:6379" SLOWLOG GET 100

# If Redis persistence (RDB/AOF) is enabled, audit the dump file
# Check BGSAVE timestamp to see if attacker triggered a dump
redis-cli -u "redis://:${NEW_REDIS_PASS}@redis:6379" LASTSAVE
```

### Recovery

```bash
# Monitor re-authentication rates — expect spike, then normalization
# Users will be prompted to log in again (expected behavior)

# If Redis was used to store data that needs restoration (e.g., rate limit counters):
# Restore from last clean RDB backup
redis-cli -u "redis://:${NEW_REDIS_PASS}@redis:6379" DEBUG RELOAD

# Verify ACLs are properly configured
redis-cli -u "redis://:${NEW_REDIS_PASS}@redis:6379" ACL LIST

# Monitor for the next 48 hours:
# - Unusual session reuse patterns
# - High re-authentication rates from specific IPs (attacker re-using stolen tokens)
```

### Post-Incident Review Checklist

```
[ ] How was Redis accessed? Network exposure, no-auth config, credential leak?
[ ] What data was in Redis at time of compromise? (sessions, OTPs, MFA state)
[ ] Did attacker actively use any stolen sessions? (check audit log for anomalous access)
[ ] GDPR assessment: if stolen sessions accessed personal data, notify within 72h
[ ] Redis AUTH enforcement added to startup validation (COMPLIANCE.md gap #1)
[ ] Network policy verified: Redis accessible only from AuthPlex pod
[ ] Redis AUTH added to production checklist (HARDENING.md §8)
[ ] Encryption at rest for Redis considered (AES-256-GCM on session data)
[ ] Redis monitoring added: AUTH failures, unusual command patterns
[ ] Incident timeline and lessons shared with team
```

---

## Appendix — Quick Reference Commands

### Query Audit Log

```bash
# All events in last 24h for a tenant
psql $AUTHPLEX_DB_URL -c "
SELECT event_type, actor_id, target_id, ip_address, created_at
FROM audit_events
WHERE tenant_id = '${TENANT_ID}'
  AND created_at > NOW() - INTERVAL '24 hours'
ORDER BY created_at DESC LIMIT 100;"

# Failed logins by IP
psql $AUTHPLEX_DB_URL -c "
SELECT ip_address, COUNT(*) as count
FROM audit_events
WHERE event_type = 'login_failed'
  AND created_at > NOW() - INTERVAL '1 hour'
GROUP BY ip_address ORDER BY count DESC LIMIT 20;"
```

### Revoke All Sessions for a User

```bash
psql $AUTHPLEX_DB_URL -c "
UPDATE sessions SET revoked_at = NOW() WHERE user_id = '${USER_ID}' AND revoked_at IS NULL;
UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = '${USER_ID}' AND revoked_at IS NULL;"
```

### Force Re-authentication for All Users in a Tenant

```bash
psql $AUTHPLEX_DB_URL -c "
UPDATE sessions SET revoked_at = NOW() WHERE tenant_id = '${TENANT_ID}' AND revoked_at IS NULL;
UPDATE refresh_tokens SET revoked_at = NOW() WHERE tenant_id = '${TENANT_ID}' AND revoked_at IS NULL;"
```

### Check AuthPlex Health

```bash
curl -s https://auth.example.com/health | jq .
# Expected: {"status":"ok","db":"ok","redis":"ok"}
```

### Restart AuthPlex (Rolling, Zero-Downtime)

```bash
kubectl rollout restart deployment/authplex -n auth
kubectl rollout status deployment/authplex -n auth --timeout=120s
```
