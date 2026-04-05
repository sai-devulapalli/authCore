# AuthPlex Threat Model

**Version:** 1.0  
**Date:** 2026-04-05  
**Scope:** AuthPlex self-hosted multi-tenant IAM engine — all 49 HTTP endpoints, Postgres persistence, optional Redis cache, Docker deployment  
**Methodology:** STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)  
**Context:** Healthcare-adjacent deployment where PHI may indirectly flow through authentication tokens and audit logs

---

## System Context Diagram

```
                        ┌─────────────────────────────────────────────────────┐
                        │                   AuthPlex                           │
  Browser / Mobile ─────┤  /login  /authorize  /token  /userinfo  /mfa/*     │
  API Client       ─────┤  /admin/* (Admin API Key)                           │
  SAML IdP         ─────┤  /saml/acs  /saml/metadata                         │
  Social Provider  ─────┤  /oauth/callback                                    │
                        │         │               │                            │
                        │     Postgres         Redis (optional)               │
                        └─────────────────────────────────────────────────────┘
```

**Trust Boundaries:**
- Public internet → AuthPlex API (TLS assumed via reverse proxy)
- AuthPlex → Postgres (internal network, parameterized SQL)
- AuthPlex → Redis (internal network, AUTH optional — see T-06)
- AuthPlex → Webhook URLs (outbound, SSRF risk — see T-09)
- AuthPlex Admin API → management plane (separate key auth)

---

## Threat Register

### T-01 — Credential Stuffing on /login

| Field | Detail |
|-------|--------|
| **STRIDE Category** | Spoofing |
| **Severity** | High |
| **Residual Risk** | Medium |

**Threat Description:**  
An attacker uses a list of leaked username/password pairs (e.g., from HaveIBeenPwned datasets) to systematically attempt authentication across all tenants. Because AuthPlex is multi-tenant, a single deployment may have thousands of user accounts across tenants, making it a high-value target.

**Attack Vector:**  
`POST /api/v1/auth/login` with rotating username/password pairs from breach databases. Rate limiting is per TCP `RemoteAddr`, which an attacker bypasses using residential proxy networks or per-IP rotation.

**Current Mitigation:**
- Rate limit: 20 req/min per `RemoteAddr` (not spoofable via `X-Forwarded-For`)
- bcrypt cost 12 on password comparison — ~100ms per attempt, limits parallel throughput
- Constant-time comparison on password verify to prevent timing oracle
- Failed login events recorded in audit log with IP and user agent

**Residual Risk:** Medium  
The 20 req/min rate limit still allows 28,800 attempts per day from a single IP. A botnet with 1,000 IPs can attempt 28.8M credentials per day. bcrypt throttles this to ~20 req/min per IP but distributed attacks remain viable.

**Recommended Fix:**
1. Add `failed_login_count` to user records; lock account after 10 consecutive failures with exponential backoff
2. Implement adaptive rate limiting: reduce to 5 req/min after 5 failures from an IP
3. Add optional CAPTCHA integration hook after 3 failures
4. Expose `POST /admin/users/{id}/unlock` to allow support-driven unlock
5. Add Prometheus counter `authplex_login_failures_total{tenant,ip_subnet}` for alerting

---

### T-02 — JWT Signing Key Compromise

| Field | Detail |
|-------|--------|
| **STRIDE Category** | Spoofing, Elevation of Privilege |
| **Severity** | Critical |
| **Residual Risk** | Medium |

**Threat Description:**  
The RSA/EC private key used to sign JWTs is exfiltrated from the running process environment, Docker secrets, or a misconfigured secrets manager. The attacker can forge access tokens for any user in any tenant, bypassing all authentication controls.

**Attack Vector:**  
Key extracted from: environment variable leak in error response, `/proc/self/environ` via path traversal, Docker `inspect` on a compromised host, git commit history, CI/CD logs.

**Current Mitigation:**
- stdlib crypto only — no JWT library with known CVEs
- Key loaded at startup into memory; not persisted to disk by default
- Tokens include `tenant_id`, `sub`, `iat`, `exp` claims — forged tokens still need valid values
- Short access token TTL (default 15 minutes) limits blast radius window

**Residual Risk:** Medium  
If the key is compromised, all currently valid tokens and all future tokens until rotation are forgeable. There is no built-in key rotation mechanism with zero-downtime overlap.

**Recommended Fix:**
1. Implement JWKS key versioning with `kid` (key ID) — support overlapping keys during rotation
2. Add `POST /admin/keys/rotate` endpoint: generates new key, keeps old key for `access_token_ttl` grace period, then removes it
3. Store private key in HashiCorp Vault or AWS Secrets Manager — never in env var in production
4. Log `key_rotation` event to audit log
5. Document the rotation procedure in `docs/security/HARDENING.md`

---

### T-03 — Tenant Data Isolation Bypass (IDOR)

| Field | Detail |
|-------|--------|
| **STRIDE Category** | Information Disclosure, Elevation of Privilege |
| **Severity** | Critical |
| **Residual Risk** | Low |

**Threat Description:**  
A user authenticated to Tenant A manipulates request parameters or tokens to access, modify, or delete resources belonging to Tenant B. In a healthcare context, this could expose PHI-adjacent data (user profiles, audit logs, RBAC assignments).

**Attack Vector:**  
1. Replace `tenant_id` in path parameter: `GET /api/v1/tenants/tenant-b-id/users`
2. Craft a JWT with modified `tenant_id` claim (requires key compromise — see T-02)
3. Exploit missing `tenant_id` filter in a query
4. Manipulate `X-Tenant-ID` header if middleware trusts it over JWT claim

**Current Mitigation:**
- `tenant_id` is included in ALL database queries as a mandatory filter
- Postgres Row-Level Security (RLS) enabled on tenant-scoped tables as defense-in-depth
- JWT `tenant_id` claim is authoritative; path parameter must match claim
- Parameterized SQL prevents injection-based filter bypass

**Residual Risk:** Low  
The combination of application-level filtering + RLS provides two independent layers. Residual risk is a logic bug in a specific query that omits the tenant filter.

**Recommended Fix:**
1. Add a linter rule (or `go vet` analysis) that flags any SQL query against tenant-scoped tables missing a `WHERE tenant_id = $N` clause
2. Write a dedicated E2E test: authenticate as Tenant A user, attempt to access Tenant B resource IDs, assert 403/404
3. Consider a middleware assertion: `assert token.TenantID == path.TenantID` before any handler executes

---

### T-04 — Admin API Key Theft / Replay

| Field | Detail |
|-------|--------|
| **STRIDE Category** | Spoofing, Elevation of Privilege |
| **Severity** | Critical |
| **Residual Risk** | High |

**Threat Description:**  
The static Admin API key (`authplex_admin_{random32hex}`) is exfiltrated from environment variables, CI/CD secrets, or intercepted in transit. Since it has no expiry, a stolen key grants permanent admin access until manually rotated.

**Attack Vector:**  
Key found in: `.env` file committed to git, CI/CD pipeline logs, Slack message, `docker inspect` output, HTTP request logs that include `Authorization` header, application error responses.

**Current Mitigation:**
- Key compared with constant-time comparison (timing-safe)
- All admin actions recorded in audit log
- Key format has high entropy (32 hex bytes = 128 bits)

**Residual Risk:** High  
No automatic expiry, no rotation tooling, no scoped permissions per key, no key issuance audit trail.

**Recommended Fix:**
1. Implement admin key expiry: store key metadata (created_at, expires_at, last_used_at) in Postgres
2. Add key scoping: `["read:users", "write:clients", "read:audit"]` — principle of least privilege
3. Add `POST /admin/keys` (create), `DELETE /admin/keys/{id}` (revoke), `GET /admin/keys` (list) endpoints
4. Enforce 90-day rotation; warn at 75 days via log/webhook
5. See `docs/security/HARDENING.md` for rotation procedure

---

### T-05 — OAuth Authorization Code Interception

| Field | Detail |
|-------|--------|
| **STRIDE Category** | Information Disclosure, Spoofing |
| **Severity** | High |
| **Residual Risk** | Low |

**Threat Description:**  
The OAuth 2.0 authorization code returned in the redirect URI is intercepted by a malicious actor via referrer header leakage, browser history, shared device, or a man-in-the-browser attack. The attacker redeems the code for tokens.

**Attack Vector:**  
1. Code in referrer header: redirect to `https://app.example.com/callback?code=X` — page loads third-party resource, referrer contains code
2. Open redirect on client app allows attacker-controlled redirect_uri
3. Code leaked in browser history or shared tab

**Current Mitigation:**
- PKCE S256 is **mandatory** — code cannot be redeemed without `code_verifier` that matches `code_challenge`
- Authorization codes are single-use; deleted after first redemption
- Authorization codes have short TTL (typically 10 minutes)
- `redirect_uri` must exactly match the registered client URI (no wildcard)
- `state` parameter validated to prevent CSRF

**Residual Risk:** Low  
PKCE S256 effectively neutralizes interception attacks. Even with the code, the attacker cannot derive the `code_verifier` from the `code_challenge` (SHA-256 is preimage-resistant).

**Recommended Fix:**
1. Add test: attempt to redeem code without `code_verifier` — assert 400
2. Add test: attempt to redeem code with wrong `code_verifier` — assert 400
3. Consider adding `iss` (issuer) parameter to authorization response (RFC 9207) to prevent mix-up attacks

---

### T-06 — Redis Session Token Theft

| Field | Detail |
|-------|--------|
| **STRIDE Category** | Information Disclosure, Spoofing |
| **Severity** | High |
| **Residual Risk** | High |

**Threat Description:**  
An attacker gains unauthenticated access to the Redis instance (no AUTH configured) and reads all session tokens, refresh tokens, MFA challenge state, and OTP codes stored in the cache. They can then impersonate any authenticated user.

**Attack Vector:**  
Redis deployed without `requirepass` in `redis.conf`. Attacker on the same network segment (or with access to the Docker bridge network) runs `redis-cli -h redis-host KEYS "*"` and reads all session data.

**Current Mitigation:**
- Session tokens are high-entropy random values (`crypto/rand`)
- Redis is optional — deployments can run without Redis using in-memory adapter
- Redis access should be restricted to internal network (not port-forwarded externally)

**Residual Risk:** High  
No enforcement of Redis AUTH in the application startup config. A misconfigured deployment (common in Kubernetes with default Redis Helm charts) runs Redis without a password.

**Recommended Fix:**
1. Add startup validation: if `AUTHPLEX_ENV=production` and Redis URL contains no credentials, **refuse to start** with a clear error message
2. Document required format: `redis://:password@host:6379/0`
3. See `docs/security/HARDENING.md` for Redis ACL hardening
4. Consider encrypting sensitive values at rest in Redis (AES-256-GCM with a separate data key)

---

### T-07 — Mass OTP Brute Force

| Field | Detail |
|-------|--------|
| **STRIDE Category** | Elevation of Privilege |
| **Severity** | High |
| **Residual Risk** | Low |

**Threat Description:**  
An attacker who has compromised a user's password attempts to brute force the 6-digit TOTP code (1,000,000 possible values) or email/SMS OTP by making rapid API calls to the MFA verification endpoint before the code expires.

**Attack Vector:**  
Rapid `POST /api/v1/mfa/totp/verify` or `POST /api/v1/mfa/otp/verify` with sequential or random 6-digit codes.

**Current Mitigation:**
- OTP: 5-attempt limit enforced, challenge deleted after 5 failures
- OTP: deleted on first successful use (no replay)
- OTP: 5-minute TTL — short window
- TOTP: 30-second window; codes are time-based, not stored server-side (only the secret is)

**Residual Risk:** Low  
5-attempt limit with 6 digits means probability of success is 5/1,000,000 = 0.0005% per challenge. TOTP window is also rate-limited.

**Recommended Fix:**
1. Add progressive delay between OTP attempts (100ms, 500ms, 1s, 5s, lockout)
2. Log `mfa_brute_force_detected` audit event when limit is hit
3. Notify user by email when MFA lockout occurs
4. For TOTP: track used codes per secret to prevent same-window replay (TOTP RFC 6238 §5.2 recommends this)

---

### T-08 — Privilege Escalation via RBAC Manipulation

| Field | Detail |
|-------|--------|
| **STRIDE Category** | Elevation of Privilege |
| **Severity** | High |
| **Residual Risk** | Low |

**Threat Description:**  
A user with limited permissions manipulates RBAC API calls to assign themselves a higher-privilege role (e.g., `tenant_admin`), or to grant permissions to resources they should not access.

**Attack Vector:**  
1. `POST /api/v1/rbac/assignments` with `role=tenant_admin` for their own `user_id`
2. Modify role permissions via `PATCH /api/v1/rbac/roles/{id}/permissions`
3. Exploit missing authorization check on role management endpoints

**Current Mitigation:**
- RBAC management endpoints require `tenant_admin` role (checked in middleware)
- `tenant_id` scoping prevents cross-tenant role assignment
- All RBAC changes recorded in audit log with `actor_id`

**Residual Risk:** Low  
Authorization check on management endpoints prevents self-escalation. Audit logging provides detection capability.

**Recommended Fix:**
1. Implement four-eyes principle for `tenant_admin` role assignment: require a second admin to approve
2. Add test: authenticated non-admin user attempts to assign themselves `tenant_admin` — assert 403
3. Alert on audit event `rbac_role_assigned` where `role=tenant_admin` via webhook

---

### T-09 — Webhook HMAC Bypass / SSRF

| Field | Detail |
|-------|--------|
| **STRIDE Category** | Tampering, Information Disclosure |
| **Severity** | High |
| **Residual Risk** | Medium |

**Threat Description:**  
**SSRF:** A tenant registers a webhook URL pointing to an internal service (`http://169.254.169.254/latest/meta-data/` for AWS IMDS, or `http://postgres:5432/`). AuthPlex sends an outbound HTTP request to this URL, potentially leaking internal credentials or triggering unintended actions.

**HMAC Bypass:** The webhook HMAC secret is weak, predictable, or the verification on the receiving end is timing-attack-vulnerable.

**Attack Vector:**  
`POST /admin/webhooks` with `url: "http://169.254.169.254/latest/meta-data/iam/security-credentials/default"` or `url: "http://internal-service.cluster.local/admin/reset"`.

**Current Mitigation:**
- HMAC-SHA256 signature on webhook payloads
- Webhook events recorded in audit log

**Residual Risk:** Medium  
No URL allowlist or blocklist for webhook registration. No DNS rebinding protection. No restriction on private IP ranges.

**Recommended Fix:**
1. Validate webhook URLs on registration: reject RFC 1918 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), loopback (127.0.0.0/8), link-local (169.254.0.0/16)
2. Resolve the hostname at registration time and at delivery time; block if resolved IP is in private range
3. Use a separate HTTP client with strict timeout (5s), no redirect following, no internal DNS resolution for webhook delivery
4. Add `POST /admin/webhooks/test` that sends to a fixed safe URL only (for testing HMAC)

---

### T-10 — SAML Assertion Forgery

| Field | Detail |
|-------|--------|
| **STRIDE Category** | Spoofing, Elevation of Privilege |
| **Severity** | Critical |
| **Residual Risk** | Medium |

**Threat Description:**  
An attacker crafts or modifies a SAML assertion to authenticate as a privileged user. Classic vectors include XML signature wrapping (XSW) attacks, comment injection in NameID, or replaying a valid assertion from a captured response.

**Attack Vector:**  
1. XML Signature Wrapping: duplicate the `<saml:Assertion>` element — one signed (valid), one unsigned (attacker-controlled). Some parsers process the unsigned one.
2. Replay: capture a valid SAML response, replay it within the validity window
3. Comment injection: `admin<!--comment-->@example.com` parsed as `admin@example.com` by one component but `admin@example.com<!--comment-->` by another

**Current Mitigation:**
- SAML SP mode only (AuthPlex does not issue SAML assertions, only consumes them — reduces attack surface)
- Uses `crewjam/saml` library, which has undergone security review
- Assertions validated for signature, audience, and time validity

**Residual Risk:** Medium  
Dependent on `crewjam/saml` library correctness. Historical CVEs exist in Go SAML libraries (e.g., CVE-2023-28119). No explicit XSW test in the test suite.

**Recommended Fix:**
1. Pin `crewjam/saml` to a specific version; subscribe to its security advisories
2. Add assertion replay protection: store `InResponseTo` values in Redis with TTL matching assertion validity
3. Add test: submit a SAML response with a modified (unsigned) assertion — assert authentication failure
4. Periodically run `govulncheck ./...` in CI to detect known vulnerabilities in dependencies

---

## Risk Summary Matrix

| ID | Threat | STRIDE | Severity | Residual Risk |
|----|--------|--------|----------|---------------|
| T-01 | Credential Stuffing | S | High | Medium |
| T-02 | JWT Key Compromise | S, EoP | Critical | Medium |
| T-03 | Tenant Isolation Bypass | ID, EoP | Critical | Low |
| T-04 | Admin Key Theft | S, EoP | Critical | **High** |
| T-05 | Auth Code Interception | ID, S | High | Low |
| T-06 | Redis Session Theft | ID, S | High | **High** |
| T-07 | OTP Brute Force | EoP | High | Low |
| T-08 | RBAC Escalation | EoP | High | Low |
| T-09 | Webhook SSRF / HMAC | T, ID | High | Medium |
| T-10 | SAML Assertion Forgery | S, EoP | Critical | Medium |

**Immediate action required (High residual risk):** T-04 (Admin key expiry), T-06 (Redis AUTH enforcement)

---

## Review Schedule

This threat model should be reviewed:
- Before each major feature release
- After any security incident
- Annually at minimum
- When deployment environment changes (new cloud provider, new network topology)

*Next scheduled review: 2027-04-05*
