# AuthPlex — Compliance Analysis

## Current Compliance Posture

| Standard | Status | Key Gaps |
|----------|--------|----------|
| GDPR (EU data protection) | Partial | No data export API, no hard delete, no consent management |
| SOC 2 Type II | Partial | Audit logging done. Missing: access reviews, pen test |
| HIPAA (healthcare) | Partial | Audit trail done. Missing: BAA, TLS enforcement |
| PCI DSS (payments) | Not applicable | AuthPlex does not store payment data |
| ISO 27001 | Not ready | No ISMS, no risk assessment documentation |
| CCPA (California privacy) | Partial | Same gaps as GDPR |
| OWASP Top 10 | 9 of 10 covered | Missing security headers (CSP, HSTS) |

---

## What AuthPlex Already Has

| Control | Implementation | Standards Satisfied |
|---------|---------------|-------------------|
| Password hashing | bcrypt cost 12 | OWASP, SOC2, GDPR, NIST 800-63 |
| Encryption at rest | AES-256-GCM (configurable key) | GDPR Art. 32, HIPAA, SOC2 |
| Per-tenant data isolation | tenant_id on every table, middleware enforced | GDPR, SOC2 |
| Rate limiting | 20 req/min per IP on /login, /token, /otp/verify, /mfa/verify | OWASP A07, SOC2 |
| No user enumeration | Same error for wrong email and wrong password | OWASP A07 |
| PKCE (S256) | Constant-time compare | OAuth 2.0 Security BCP |
| Refresh token rotation | Family tracking with replay detection | OAuth 2.0 Security BCP |
| Session revocation | Instant delete from Redis | SOC2 (access control) |
| Admin API authentication | API key with constant-time comparison | SOC2 (access control) |
| Soft delete | DeletedAt field, data retained for audit | GDPR (retention period) |
| MFA support | TOTP + SMS OTP, per-tenant policy | SOC2, HIPAA, NIST 800-63B |
| Structured logging | slog, environment-aware (text/JSON) | SOC2 (monitoring) |
| Parameterized SQL | All queries use $1, $2 placeholders | OWASP A03 (injection) |
| Minimal dependencies | 6 external deps, all well-maintained | OWASP A06 (vulnerable components) |
| CORS | Configurable allowed origins | OWASP A05 (misconfiguration) |
| RBAC | Roles + permissions per tenant, wildcard matching, in JWT | SOC2 (access control), HIPAA |
| Audit logging | 25+ event types, query API with filters | SOC2 CC6.1, HIPAA, GDPR Art. 33 |
| mTLS | Mutual TLS for M2M client certificate verification | SOC2 (encryption in transit) |
| OpenTelemetry tracing | Distributed trace context middleware | SOC2 CC7.2 (monitoring) |

---

## OWASP Top 10 Coverage

| # | Vulnerability | Status | AuthPlex Implementation |
|---|--------------|--------|------------------------|
| A01 | Broken Access Control | Covered | Per-tenant isolation, client enforcement, scope validation, admin API key |
| A02 | Cryptographic Failures | Covered | AES-256-GCM at rest, bcrypt passwords, RS256/ES256 JWTs, PKCE S256 |
| A03 | Injection | Covered | Parameterized SQL ($1, $2), no string concatenation in queries |
| A04 | Insecure Design | Covered | Hexagonal architecture, port interfaces, domain logic isolated |
| A05 | Security Misconfiguration | Partial | Sensible defaults, CORS configured. Missing: security headers (CSP, HSTS) |
| A06 | Vulnerable Components | Low risk | 6 dependencies only: pgx, go-redis, testify, x/crypto, env, testcontainers |
| A07 | Auth Failures | Covered | Rate limiting, no user enumeration, MFA, PKCE, refresh rotation |
| A08 | Data Integrity Failures | Covered | JWT signature verification, PKCE, CSRF state for social login |
| A09 | Logging & Monitoring | Covered | Structured logging + audit trail (25+ event types) + OpenTelemetry tracing. Missing: alerting |
| A10 | SSRF | Low risk | Outbound OAuth calls to configured providers only |

---

## GDPR Requirements

| Article | Requirement | Status | What's Needed |
|---------|------------|--------|---------------|
| Art. 15 | Right to access | Missing | `GET /users/{id}/data-export` — return all user data as JSON |
| Art. 17 | Right to erasure | Partial | Soft delete exists. Need hard delete with cascade to sessions, tokens, identities |
| Art. 20 | Right to portability | Missing | Export user data in machine-readable format (JSON/CSV) |
| Art. 25 | Privacy by design | Partial | Encryption exists. Need data minimization policy |
| Art. 30 | Processing records | Missing | Log what data is processed, why, and by whom |
| Art. 32 | Security of processing | Done | AES-256-GCM, bcrypt, TLS via proxy, per-tenant isolation |
| Art. 33 | Breach notification | Missing | Need audit logging + alerting for suspicious activity |
| Art. 7 | Consent management | Missing | Record what user consented to, when, allow withdrawal |
| N/A | DPA (Data Processing Agreement) | Missing | Legal document, not code |

| Fix Priority | Items | Effort |
|-------------|-------|--------|
| High | Data export endpoint, hard delete cascade | 3 days |
| Medium | Consent table, processing records | 3 days |
| Low | DPA template | Legal team |

---

## SOC 2 Type II Requirements

| Category | Requirement | Status | What's Needed |
|----------|------------|--------|---------------|
| CC6.1 | Audit logging | Done | 25+ event types: login, register, OTP, MFA, token, session, tenant, client, role, provider, admin API |
| CC6.2 | Access reviews | Missing | API to list admin access, when granted, by whom |
| CC6.3 | Change management | Partial | Git history exists. Need formal approval process |
| CC6.6 | Encryption in transit | Partial | AuthPlex relies on reverse proxy for TLS |
| CC6.7 | Encryption at rest | Done | AES-256-GCM |
| CC7.1 | Incident response | Missing | Alerting on failed logins, brute force, token replay |
| CC7.2 | Monitoring | Partial | Structured logging + OpenTelemetry tracing. No metrics or dashboards |
| CC7.3 | Backup & recovery | Missing | Relies on Postgres/Redis ops |
| CC8.1 | Penetration testing | Missing | No external security audit |
| CC9.1 | Security policies | Missing | Documentation, not code |

| Fix Priority | Items | Effort |
|-------------|-------|--------|
| ~~Critical~~ | ~~Audit logging (all events to DB)~~ | **Done** |
| High | Alerting on suspicious activity | 2-3 days |
| Medium | Backup procedures documentation | 1 day |
| External | Penetration test | $5K-30K, 1-2 weeks |
| Legal | Security policy documents | Legal team |

---

## HIPAA Requirements

| Requirement | Status | What's Needed |
|-------------|--------|---------------|
| BAA (Business Associate Agreement) | Missing | Legal document |
| Audit trail | Done | 25+ event types, query API with filters |
| Access controls | Done | Admin API key + RBAC (roles, permissions, per-tenant) |
| Encryption in transit | Partial | Need to enforce TLS, reject plain HTTP in production |
| Encryption at rest | Done | AES-256-GCM |
| Automatic logoff | Done | Session TTL (24 hours) |
| Unique user identification | Done | User ID per tenant |
| Emergency access | Missing | Break-glass procedure for locked-out admins |
| Integrity controls | Done | JWT signatures, PKCE, parameterized SQL |

| Fix Priority | Items | Effort |
|-------------|-------|--------|
| ~~Critical~~ | ~~Audit trail~~ | **Done** |
| High | TLS enforcement middleware | 1 day |
| Medium | Emergency access procedure | 2 days |
| Legal | BAA template | Legal team |

---

## Specific Compliance Risks

| # | Risk | Impact | Severity | Fix | Effort |
|---|------|--------|----------|-----|--------|
| ~~1~~ | ~~No audit logging~~ | ~~SOC2 fails~~ | ~~Critical~~ | **Done** — 25+ event types, audit_events table, query API | **Done** |
| 2 | No hard delete | GDPR Art. 17 violation. Fine: up to 4% annual revenue | High | Add `/users/{id}/purge` with cascade delete | 2-3 days |
| 3 | No TLS enforcement | Passwords transmitted plaintext if no proxy. HIPAA violation | High | Middleware to reject HTTP in production | 1 day |
| 4 | No security headers | OWASP A05. Clickjacking, MIME sniffing possible | Medium | Add HSTS, CSP, X-Content-Type-Options, X-Frame-Options | 30 min |
| 5 | Secrets in env vars | Can leak via process listing, crash dumps. SOC2 finding | Medium | Support Vault, AWS Secrets Manager, file-based secrets | 2-3 days |
| 6 | No data export | GDPR Art. 15/20 violation | Medium | `GET /users/{id}/export` returning all user data as JSON | 1 day |
| 7 | No consent management | GDPR Art. 7 violation | Low | Consent table: what, when, withdrawn | 2 days |
| 8 | No pen test | SOC2 requires external validation | External | Hire security firm | $5K-30K |

---

## Deployment Safety Matrix

| Environment | Safe to Deploy? | Conditions |
|-------------|:-:|------------|
| Internal tools | Yes | No regulatory requirement |
| Startup MVP | Yes | Speed over compliance at this stage |
| B2B SaaS (non-regulated) | Yes | Audit logging, RBAC, encryption all in place |
| EU customers (GDPR) | Partial | Add data export + hard delete before handling EU PII |
| Healthcare (HIPAA) | Partial | Audit trail done. Need BAA + TLS enforcement |
| Finance (PCI/SOC2) | Partial | Audit logging done. Need pen test + formal policies |
| Government | No | Need SOC2 + FedRAMP (significant additional work) |

---

## Compliance Roadmap

| Phase | Items | Effort | Unlocks |
|-------|-------|--------|---------|
| ~~Phase 1~~ | ~~Audit logging (all events to DB)~~ | **Done** | ~~SOC2 readiness~~ |
| Phase 2 | Security headers, TLS enforcement, hard delete | 3 days | OWASP Top 10 clean |
| Phase 3 | Data export, consent management | 1 week | GDPR compliance |
| Phase 4 | Secret backend support (Vault / AWS Secrets Manager) | 3 days | SOC2 secret management |
| Phase 5 | External penetration test | 1-2 weeks (external) | SOC2 Type II, customer trust |
| Phase 6 | HIPAA documentation (BAA, policies) | Legal team | HIPAA compliance |

---

## Compliance vs Competitors

| Standard | **AuthPlex** | **Keycloak** | **IdentityServer** | **Cognito** |
|----------|:-:|:-:|:-:|:-:|
| OWASP Top 10 | 9/10 | 10/10 | 7/10 | 10/10 |
| GDPR ready | Partial | Yes | Partial | Yes |
| SOC 2 ready | Partial (audit logging done, needs pen test) | Yes (with Red Hat SSO) | Partial | Certified |
| HIPAA ready | Partial (audit trail done, needs BAA) | Yes (with config) | No | Certified |
| PCI DSS | N/A | Ready | Ready | Certified |
| Pen tested | No | Yes (10+ years) | Yes | Yes |
| Security team | None | Red Hat | Duende | AWS |
| CVE history | None (new) | 10+ years of CVE responses | 8+ years | AWS security team |

---

## Audit Events Schema (Implemented)

| Field | Type | Description |
|-------|------|-------------|
| id | TEXT | Unique event ID |
| tenant_id | TEXT | Which tenant |
| actor_id | TEXT | Who performed the action (user ID or "system") |
| actor_type | TEXT | "user", "admin", "system", "client" |
| action | TEXT | "login_success", "login_failure", "register", "token_issued", "role_assigned", etc. |
| resource_type | TEXT | "user", "client", "tenant", "role", "session" |
| resource_id | TEXT | ID of the affected resource |
| ip_address | TEXT | Client IP |
| user_agent | TEXT | Client user agent |
| details | JSONB | Additional context (e.g., failure reason, old/new values) |
| timestamp | TIMESTAMPTZ | When it happened |

| Event Types | Category |
|-------------|----------|
| login_success, login_failure | Authentication |
| register, password_reset, email_verified | User lifecycle |
| otp_requested, otp_verified, otp_failed | OTP |
| mfa_enrolled, mfa_verified, mfa_failed | MFA |
| token_issued, token_refreshed, token_revoked | Tokens |
| session_created, session_revoked | Sessions |
| tenant_created, tenant_updated, tenant_deleted | Admin |
| client_created, client_updated, client_deleted | Admin |
| role_created, role_assigned, role_revoked | RBAC |
| provider_created, provider_deleted | Social login |
| admin_api_access | Admin API |
