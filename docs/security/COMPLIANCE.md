# AuthPlex Compliance Gap Analysis

**Version:** 1.0  
**Date:** 2026-04-05  
**Scope:** AuthPlex self-hosted multi-tenant IAM engine  
**Legend:** ✅ PASS | ⚠️ PARTIAL | ❌ FAIL

---

## 1. OWASP Application Security Verification Standard (ASVS) Level 2

ASVS Level 2 is the recommended baseline for applications handling sensitive data, including healthcare-adjacent systems.

### V2 — Authentication Verification Requirements

| Req | Description | Status | Notes |
|-----|-------------|--------|-------|
| V2.1.1 | User set passwords are at least 12 characters | ✅ PASS | Configurable minimum enforced in validation |
| V2.1.2 | Passwords of at least 64 characters permitted | ✅ PASS | No truncation in bcrypt pre-hash |
| V2.1.3 | Password truncation not performed | ✅ PASS | Full password passed to bcrypt |
| V2.1.6 | Password change requires current password | ✅ PASS | `/api/v1/auth/change-password` requires old password |
| V2.1.7 | Passwords checked against known-bad passwords | ❌ FAIL | No HaveIBeenPwned API or blocklist integration |
| V2.1.9 | No composition rules (require X uppercase, etc.) | ✅ PASS | Only minimum length enforced |
| V2.1.10 | No periodic password rotation required | ✅ PASS | Compliant with NIST SP 800-63B |
| V2.1.11 | Paste functionality allowed in password fields | ✅ PASS | No client-side restrictions imposed by server |
| V2.1.12 | User can view/unmask password entry | ✅ PASS | No server-side restriction |
| V2.2.1 | Anti-automation controls at authentication | ⚠️ PARTIAL | Rate limiting (20 req/min) but no CAPTCHA |
| V2.2.2 | Weak credential warnings presented | ❌ FAIL | No strength meter or leak check |
| V2.2.3 | Security notifications for credential changes | ⚠️ PARTIAL | Audit log records changes; no email notification |
| V2.3.1 | System-generated initial passwords have sufficient randomness | ✅ PASS | `crypto/rand` used |
| V2.5.1 | OTP secret not revealed post-activation | ✅ PASS | TOTP secret shown only during setup |
| V2.5.2 | Account recovery does not reveal current credential | ✅ PASS | Password reset via token, not email of old password |
| V2.5.3 | Recovery tokens are single-use | ✅ PASS | OTP deleted on use |
| V2.6.1 | TOTP shared secrets stored securely | ✅ PASS | AES-256-GCM encrypted at rest |
| V2.7.1 | OTP with 5-minute TTL minimum | ✅ PASS | 5-minute TTL enforced |
| V2.7.2 | OTP expiry notified to user | ❌ FAIL | No expiry countdown communicated |
| V2.8.3 | TOTP uses RFC 6238 | ✅ PASS | RFC 6238 compliant implementation |
| V2.8.4 | Time-based OTP allows 1-period skew | ✅ PASS | ±1 window tolerance |
| V2.8.5 | TOTP replay prevention within same window | ⚠️ PARTIAL | No server-side used-code tracking per window |
| V2.9.1 | Cryptographic authenticator uses approved algorithms | ✅ PASS | HMAC-SHA1 for TOTP (RFC 6238), SHA-256 for PKCE |

### V3 — Session Management Verification Requirements

| Req | Description | Status | Notes |
|-----|-------------|--------|-------|
| V3.1.1 | URLs do not expose session tokens | ✅ PASS | Tokens in headers only |
| V3.2.1 | New session token generated at authentication | ✅ PASS | New token on every login |
| V3.2.2 | Session tokens have at least 128 bits of entropy | ✅ PASS | `crypto/rand` — 256-bit tokens |
| V3.2.3 | Session tokens stored using secure/HttpOnly cookies if browser | ✅ PASS | Flags set when cookie transport used |
| V3.3.1 | Logout invalidates server-side session | ✅ PASS | Token blacklisted in Redis/in-memory |
| V3.3.2 | Session timeout after inactivity period | ⚠️ PARTIAL | Access token TTL enforced; inactivity extension not configurable |
| V3.3.3 | Authenticated session terminated after max lifetime | ✅ PASS | Refresh token max lifetime enforced |
| V3.4.1 | Cookie-based sessions use SameSite attribute | ✅ PASS | `SameSite=Strict` |
| V3.7.1 | Application validates session tokens consistently | ✅ PASS | Middleware validates on every request |

### V4 — Access Control Verification Requirements

| Req | Description | Status | Notes |
|-----|-------------|--------|-------|
| V4.1.1 | Access control enforced on trusted server side | ✅ PASS | All checks in middleware/handlers, not client |
| V4.1.2 | Access control fails securely (default deny) | ✅ PASS | Missing role = denied |
| V4.1.3 | Principle of least privilege | ✅ PASS | RBAC with scoped permissions |
| V4.1.4 | CORS allows only trusted origins | ⚠️ PARTIAL | CORS configurable but not validated at startup |
| V4.2.1 | Sensitive data not accessible via direct object reference without authorization | ✅ PASS | tenant_id filter on all queries |
| V4.3.1 | Admin interfaces use additional authentication | ✅ PASS | Separate admin API key required |

### V5 — Validation, Sanitization and Encoding

| Req | Description | Status | Notes |
|-----|-------------|--------|-------|
| V5.1.1 | HTTP parameter pollution attacks defended | ✅ PASS | Go's `net/http` takes first value by default |
| V5.1.3 | Inputs validated against allowlist | ⚠️ PARTIAL | UUID formats validated; free-text fields not allowlisted |
| V5.2.3 | Unstructured data sanitized | ✅ PASS | slog escapes structured log fields |
| V5.3.3 | SQL uses parameterized queries | ✅ PASS | All queries use `$1, $2, ...` placeholders |
| V5.3.4 | Data sent to OS uses parametrization | ✅ PASS | No OS command execution |

### V6 — Stored Cryptography

| Req | Description | Status | Notes |
|-----|-------------|--------|-------|
| V6.2.1 | Approved cryptographic algorithms | ✅ PASS | AES-256-GCM, RSA-2048+, ECDSA P-256 |
| V6.2.2 | Random nonce/IV not reused with same key | ✅ PASS | `crypto/rand` IV for each AES-GCM encryption |
| V6.2.3 | Encryption keys not hard-coded | ✅ PASS | Keys from environment/secrets manager |
| V6.2.5 | Outdated algorithms not used (MD5, SHA-1 in non-TOTP context) | ✅ PASS | SHA-256+ everywhere except TOTP (RFC-mandated HMAC-SHA1) |
| V6.3.1 | Random values with sufficient entropy | ✅ PASS | `crypto/rand` throughout |
| V6.4.1 | Asymmetric keys stored securely | ⚠️ PARTIAL | Loaded from env var; no Vault integration enforced |

### V7 — Error Handling and Logging

| Req | Description | Status | Notes |
|-----|-------------|--------|-------|
| V7.1.1 | No sensitive information in log entries | ✅ PASS | Passwords/tokens explicitly excluded from slog fields |
| V7.1.2 | No sensitive information in error responses | ✅ PASS | `AppError` returns codes, not stack traces |
| V7.2.1 | Authentication events logged | ✅ PASS | 25+ audit event types |
| V7.2.2 | Security events have sufficient detail | ✅ PASS | IP, user agent, tenant, user, timestamp |
| V7.3.1 | Logs protected from injection | ✅ PASS | slog structured format prevents CRLF injection |
| V7.3.3 | Log integrity protected | ⚠️ PARTIAL | No log signing or append-only enforcement |

### V8 — Data Protection

| Req | Description | Status | Notes |
|-----|-------------|--------|-------|
| V8.1.1 | Sensitive data not logged | ✅ PASS | No passwords, tokens, or secrets in logs |
| V8.3.1 | Sensitive data not sent in URL query strings | ✅ PASS | Tokens via headers/body only |
| V8.3.2 | Cache-control headers set to prevent sensitive data caching | ⚠️ PARTIAL | Set on OIDC responses; not universally applied |

### V9 — Communication

| Req | Description | Status | Notes |
|-----|-------------|--------|-------|
| V9.1.1 | TLS used for all connections | ⚠️ PARTIAL | TLS via reverse proxy; AuthPlex itself runs HTTP internally — documented requirement |
| V9.1.2 | TLS 1.2+ only | ⚠️ PARTIAL | Reverse proxy configured by operator; AuthPlex does not enforce |
| V9.2.1 | Outbound connections use TLS | ✅ PASS | Webhook delivery uses TLS by default |

### V13 — API and Web Service

| Req | Description | Status | Notes |
|-----|-------------|--------|-------|
| V13.1.1 | All input validated server-side | ✅ PASS | |
| V13.1.3 | API documented and schema-validated | ⚠️ PARTIAL | Docs exist; no OpenAPI schema validation at runtime |
| V13.2.1 | Enabled HTTP methods only accept content in expected format | ✅ PASS | |
| V13.2.5 | REST API CORS configured securely | ⚠️ PARTIAL | Configurable but not audited at startup |

---

## 2. HIPAA Security Rule

AuthPlex does not directly store PHI (Protected Health Information), but it authenticates users and systems that access PHI. As such it is a component of a HIPAA-covered entity's technical safeguards.

### §164.312(a) — Access Control

| Requirement | Status | Code vs Process |
|-------------|--------|-----------------|
| Unique user identification | ✅ PASS | Each user has a UUID; shared accounts unsupported |
| Emergency access procedure | ❌ FAIL | No emergency access bypass documented; requires organizational process |
| Automatic logoff | ⚠️ PARTIAL | Code: access token TTL enforced. Process: define acceptable inactivity timeout per tenant config |
| Encryption/decryption of ePHI | ✅ PASS (Code) | AES-256-GCM on stored secrets; TLS in transit (via proxy) |

**Gaps:**
- Emergency access procedure is a **process gap** — document break-glass procedure using admin API key with dedicated audit trail
- Automatic logoff timeout should be configurable per tenant via admin API

### §164.312(b) — Audit Controls

| Requirement | Status | Code vs Process |
|-------------|--------|-----------------|
| Hardware/software activity audit | ✅ PASS | 25+ audit event types in structured log |
| Review audit logs regularly | N/A (Process) | AuthPlex generates logs; customer must implement review process |
| Audit log retention | ⚠️ PARTIAL | Code: audit events stored in Postgres. Process: define retention period (HIPAA: 6 years minimum) |
| Tamper-evident logs | ⚠️ PARTIAL | Code: Postgres ACID guarantees. Gap: no cryptographic log signing |

**Gaps:**
- Implement log export to append-only storage (AWS CloudTrail, immutable S3 bucket with Object Lock)
- 6-year retention policy is an **organizational process requirement**

### §164.312(c) — Integrity

| Requirement | Status | Code vs Process |
|-------------|--------|-----------------|
| Mechanism to authenticate ePHI | ✅ PASS | JWT signatures ensure token integrity; bcrypt ensures password integrity |
| Verify data not altered in transit | ✅ PASS | TLS provides transport integrity |

### §164.312(d) — Person/Entity Authentication

| Requirement | Status | Code vs Process |
|-------------|--------|-----------------|
| Authentication before granting access | ✅ PASS | Multi-factor authentication supported |
| Verify identity is who they claim | ✅ PASS | TOTP, WebAuthn, SAML, Social Login all supported |

**Note:** HIPAA does not require MFA but recommends it. AuthPlex enables MFA enforcement per tenant — **process gap**: require tenant admin to enable MFA enforcement.

### §164.312(e) — Transmission Security

| Requirement | Status | Code vs Process |
|-------------|--------|-----------------|
| Guard against unauthorized access to ePHI in transit | ✅ PASS | TLS via reverse proxy; HSTS headers set |
| Encryption in transit | ⚠️ PARTIAL | Code: TLS headers set. Process: operator must configure nginx/ALB for TLS 1.2+ |

---

## 3. SOC 2 Type II (Trust Services Criteria)

SOC 2 Type II evaluates whether controls are operating effectively over a period of time (typically 6–12 months). AuthPlex provides technical controls; customers must implement the monitoring and evidence collection processes.

### CC6 — Logical and Physical Access Controls

| Criteria | What AuthPlex Provides | What Customer Must Implement |
|----------|----------------------|------------------------------|
| CC6.1 Restrict logical access | RBAC, tenant isolation, JWT validation | Access provisioning/de-provisioning process; user access reviews |
| CC6.2 Authentication mechanisms | Password + MFA (TOTP, WebAuthn) | Enforce MFA via tenant config; annual credential review |
| CC6.3 Authorization for access | RBAC with roles and permissions | Role assignment approval process; separation of duties |
| CC6.6 Restrict access from outside | Admin key required; rate limiting | Network-level controls (VPC, WAF); IP allowlisting for admin API |
| CC6.7 Restrict transmission | TLS via reverse proxy; HSTS | TLS certificate management; mutual TLS for internal services |
| CC6.8 Prevent unauthorized software | Read-only container filesystem | Image signing (Cosign); container registry scanning |

### CC7 — System Operations

| Criteria | What AuthPlex Provides | What Customer Must Implement |
|----------|----------------------|------------------------------|
| CC7.1 Detect and monitor security events | 25+ audit event types; slog-based structured logging | Centralize logs (CloudWatch, Splunk, Datadog); configure alerts |
| CC7.2 Monitor system components | Health endpoint (`/health`) | Uptime monitoring, CPU/memory alerts |
| CC7.3 Evaluate security events | Audit log queryable per tenant | SIEM integration; security event review SOP |
| CC7.4 Incident response | See `INCIDENT_RESPONSE.md` | Activate IRP; assign incident owner; HIPAA breach notification |
| CC7.5 Identify and remediate | Known gaps documented in `THREAT_MODEL.md` | Track remediation via issue tracker; review quarterly |

### CC8 — Change Management

| Criteria | What AuthPlex Provides | What Customer Must Implement |
|----------|----------------------|------------------------------|
| CC8.1 Authorize changes | All changes via pull request; semantic versioning | Change advisory board; change freeze periods; approval gates |
| CC8.1 Test changes | 80%+ line coverage; E2E tests with Postgres/Redis | Staging environment testing; load testing before production |
| CC8.1 Deploy changes | Docker image; `docker-compose.prod.yml` | Deployment approval process; rollback procedure |

**Evidence artifacts for auditors:**
- Git commit history shows all code changes with author
- PR merge gates enforce test passage before deploy
- Docker image tags are immutable once pushed to registry

### A1 — Availability

| Criteria | What AuthPlex Provides | What Customer Must Implement |
|----------|----------------------|------------------------------|
| A1.1 Performance capacity | Stateless Go service; horizontal scaling | Load balancer; auto-scaling policy; capacity planning |
| A1.2 Recovery procedures | Postgres as source of truth; Redis is cache (optional) | RTO/RPO definitions; automated backups; DR runbook |
| A1.3 Continuity testing | See `docs/RUNBOOK.md` for recovery steps | Annual DR drill; backup restoration test |

**SLA Note:** AuthPlex does not include built-in HA or clustering. Availability is the customer's responsibility to implement using the provided Docker/Kubernetes artifacts.

---

## 4. GDPR Compliance

AuthPlex processes personal data (email addresses, names, session metadata, audit log entries with IP addresses). As a data processor, AuthPlex operators are data controllers; AuthPlex itself provides technical measures.

### Article 5 — Data Minimization

| Requirement | Status | Gap Description |
|-------------|--------|-----------------|
| Collect only necessary data | ⚠️ PARTIAL | User profile stores email, name, optional phone. IP addresses logged in audit log — verify necessity and retention |
| Purpose limitation | ✅ PASS | Data used only for authentication; no marketing/analytics use built in |
| Storage limitation | ⚠️ PARTIAL | No built-in data retention policy or auto-purge. Operator must implement |

**Gap:** Add configurable audit log retention in Postgres (e.g., auto-delete entries older than N days).

### Article 17 — Right to Erasure (Right to be Forgotten)

| Requirement | Status | Gap Description |
|-------------|--------|-----------------|
| Delete user data on request | ⚠️ PARTIAL | `DELETE /api/v1/users/{id}` removes user record. Cascade to: sessions, refresh tokens, TOTP secrets, WebAuthn credentials |
| Delete from backup | ❌ FAIL (Process) | Backup deletion is an organizational process; AuthPlex provides soft-delete + hard-delete API |
| Erasure within 30 days | ⚠️ PARTIAL | API available; no automated erasure workflow |

**Gap:** Implement `DELETE /api/v1/users/{id}?purge=true` that cascades to all related tables and audit log entries (pseudonymization of historical audit entries may be preferable to deletion to maintain log integrity).

### Article 25 — Privacy by Design

| Requirement | Status | Gap Description |
|-------------|--------|-----------------|
| Data protection by default | ✅ PASS | Passwords hashed (bcrypt), secrets encrypted (AES-256-GCM), minimal data collected |
| Technical measures at design time | ✅ PASS | Tenant isolation, RBAC, parameterized SQL built in from inception |
| Controller can demonstrate compliance | ⚠️ PARTIAL | This document exists; no automated DPIA template |

### Article 30 — Records of Processing Activities (RoPA)

| Requirement | Status | Gap Description |
|-------------|--------|-----------------|
| Document processing activities | ❌ FAIL (Process) | AuthPlex does not generate a RoPA. This is the controller's responsibility |
| Include security measures | ✅ PASS | Security measures documented in this file and `HARDENING.md` |

**Gap (Process):** Data controller must create and maintain a RoPA document using AuthPlex as the authentication processor. Template: purpose=user authentication, legal basis=contract, categories=email/name/IP, recipients=none (self-hosted), retention=per policy.

### Article 32 — Technical and Organisational Measures

| Requirement | Status | Gap Description |
|-------------|--------|-----------------|
| Encryption of personal data | ✅ PASS | TLS in transit; AES-256-GCM for secrets at rest |
| Confidentiality and integrity | ✅ PASS | Tenant isolation, RBAC, bcrypt, parameterized SQL |
| Availability and resilience | ⚠️ PARTIAL | Stateless service; resilience depends on deployment (customer responsibility) |
| Regular testing of security | ⚠️ PARTIAL | 812 automated tests; no formal penetration test yet |
| Pseudonymisation | ❌ FAIL | No built-in pseudonymisation of user data or audit log entries |

### Article 33 — Breach Notification (72-hour requirement)

| Requirement | Status | Gap Description |
|-------------|--------|-----------------|
| Detect breach | ⚠️ PARTIAL | Audit log provides detection signals; no automated breach detection |
| Notify supervisory authority within 72 hours | ❌ FAIL (Process) | Organizational process; AuthPlex audit log provides evidence |
| Notify affected individuals | ❌ FAIL (Process) | Operator must implement notification workflow |

**Note:** See `INCIDENT_RESPONSE.md` for breach detection signals and containment steps that feed into GDPR Article 33 notification requirements.

---

## 5. Prioritized Gap Closure Table

| # | Gap | Framework(s) | Priority | Effort | Owner |
|---|-----|--------------|----------|--------|-------|
| 1 | Redis AUTH enforcement at startup | Internal, SOC2 CC6 | **Critical** | Low (1 day) | Code |
| 2 | Admin API key expiry + rotation tooling | Internal, SOC2 CC6 | **Critical** | Medium (3 days) | Code |
| 3 | TOTP same-window replay prevention | ASVS V2.8.5 | High | Low (1 day) | Code |
| 4 | Webhook SSRF protection (IP blocklist) | Internal | High | Low (2 days) | Code |
| 5 | Account lockout after N failed logins | ASVS V2.2.1, HIPAA | High | Medium (2 days) | Code |
| 6 | Password breach check (HaveIBeenPwned) | ASVS V2.1.7 | High | Medium (2 days) | Code |
| 7 | SAML assertion replay prevention | Internal | High | Medium (2 days) | Code |
| 8 | Right to erasure cascade (GDPR Art.17) | GDPR | High | Medium (3 days) | Code |
| 9 | Configurable audit log retention | HIPAA, GDPR Art.5 | Medium | Medium (2 days) | Code |
| 10 | OpenAPI schema validation at runtime | ASVS V13.1.3 | Medium | Medium (3 days) | Code |
| 11 | External penetration test | ASVS V14, SOC2 | Medium | High (2 weeks) | Process |
| 12 | Log signing / append-only export | HIPAA §164.312(b) | Medium | High (1 week) | Code + Process |
| 13 | MFA enforcement policy per tenant | HIPAA §164.312(d) | Medium | Low (1 day) | Code |
| 14 | GDPR breach notification workflow | GDPR Art.33 | Medium | High (2 weeks) | Process |
| 15 | Records of Processing Activities (RoPA) | GDPR Art.30 | Medium | Medium (3 days) | Process |
| 16 | Emergency access break-glass procedure | HIPAA §164.312(a) | Low | Low (1 day) | Process |
| 17 | DR drill documentation and scheduling | SOC2 A1.3 | Low | Medium (3 days) | Process |
| 18 | Pseudonymisation of audit log user data | GDPR Art.32 | Low | High (1 week) | Code |
| 19 | CORS validation at startup | ASVS V4.1.4 | Low | Low (1 day) | Code |
| 20 | Security notification emails to users | ASVS V2.2.3 | Low | Medium (2 days) | Code |

**Legend — Priority:** Critical = fix before production | High = fix within 30 days | Medium = fix within 90 days | Low = fix within 180 days  
**Legend — Owner:** Code = requires AuthPlex code change | Process = requires operator's organizational process
