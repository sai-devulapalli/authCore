# AuthCore Roadmap & Pending Items

## Current State (as of 2026-03-26)

**Modules Complete:** 0–10 + Production Hardening + SDK
**Stats:** ~237 Go files, 720 tests, 85.0% coverage, 35+ endpoints, 40 packages

---

## Completed Items

### Previously Critical — All Resolved

| # | Item | Status |
|---|------|--------|
| 1 | Remaining Postgres repo implementations | **Done** — client, user, refresh, provider, external identity repos |
| 2 | Redis for ephemeral stores | **Done** — session, auth code, device code, blacklist, state, OTP |
| 3 | Scope validation enforcement | **Done** — /authorize + /token validate scopes against client |
| 4 | MFA enforcement in /authorize | **Done** — MFAPolicy on Tenant, challenge-based flow |
| 5 | E2E tests | **Done** — golden path, Docker testcontainers + in-memory variants |

### Previously High Priority — All Resolved

| # | Item | Status |
|---|------|--------|
| 6 | Rate limiting | **Done** — 20 req/min per IP sliding window |
| 7 | Encryption at rest | **Done** — AES-256-GCM with configurable key |
| 8 | Email service + verification | **Done** — SMTP + console senders, auto-verify on register |
| 9 | Password reset flow | **Done** — OTP-based password reset |

### Previously Low Priority — Resolved

| # | Item | Status |
|---|------|--------|
| 17 | mTLS | **Done** — Mutual TLS middleware for M2M |
| 18 | OpenTelemetry | **Done** — Tracing middleware |
| 22 | Audit logging | **Done** — 25+ event types, query API |

### Additional Completed Work

| Feature | Status |
|---------|--------|
| RBAC (roles + permissions in JWT) | **Done** — Full CRUD, wildcard permissions, JWT enrichment |
| Go SDK (embeddable library) | **Done** — pkg/authcore with Register/Login/IssueTokens/VerifyJWT |
| Wrapper SDKs (Java, .NET, Node.js, Python) | **Done** — Typed clients in separate repos |
| Spring Boot test client | **Done** — OAuth2 resource server with JWKS verification |

---

## Pending Items by Priority

### High — Enterprise Features

| # | Item | Effort | Description |
|---|------|--------|-------------|
| 10 | SAML 2.0 | Large | Enterprise SSO — see [SAML analysis](#saml-20-analysis) below |
| 11 | WebAuthn/FIDO2 (Module 7b) | Large | Hardware key / biometric MFA |

### Medium — Feature Parity

| # | Item | Effort | Description |
|---|------|--------|-------------|
| 12 | ID token from social login | Small | Decode provider id_token (marked `// TODO`) |
| 13 | Apple JWT client_secret | Medium | ES256-signed JWT per token exchange request |
| 14 | Refresh token cleanup | Small | Expired/revoked tokens accumulate forever |
| 15 | Key auto-rotation | Small | Currently manual via API |
| 16 | Admin CLI tool | Small | `authcore tenant create --domain example.com` |
| 17 | CORS per-client | Small | Currently global; should be per-client whitelist |
| 18 | Postgres RBAC repos | Medium | Currently in-memory; need Postgres persistence |
| 19 | Audit event auto-logging | Medium | Wire audit events into all services (currently manual) |

### Low — Nice to Have

| # | Item | Effort | Description |
|---|------|--------|-------------|
| 20 | LDAP integration | Medium | Direct AD bind (see [LDAP analysis](#ldap-analysis)) |
| 21 | Admin UI (separate SPA) | Large | Separate companion recommended |
| 22 | JWE (encrypted tokens) | Medium | RFC 7516 |
| 23 | Security audit | External | Zero production deployments, no external review |
| 24 | Dynamic Client Registration (RFC 7591) | Medium | Clients can self-register |
| 25 | Pushed Authorization Requests (PAR) | Medium | RFC 9126 |
| 26 | Security headers middleware | Small | HSTS, CSP, X-Content-Type-Options |
| 27 | Hard delete for GDPR | Small | Cascade delete for right to erasure |
| 28 | Data export endpoint | Small | GDPR Art. 15 compliance |
| 29 | Secret backend (Vault/AWS Secrets Manager) | Medium | External secret management |

---

## Feature Analysis: SAML, LDAP, Admin UI

### SAML 2.0 Analysis

**Verdict: Build it.** Enterprise blocker — banks, hospitals, government require SAML.

**What it requires:**
- XML signing/verification (`encoding/xml` + `crypto/x509`)
- SAML metadata endpoint (`GET /saml/metadata`)
- SAML SSO endpoint (`GET /saml/sso` — receives AuthnRequest)
- SAML ACS endpoint (`POST /saml/acs` — receives Response/Assertion)
- Assertion builder (XML → sign → base64 → POST/redirect binding)
- SP-initiated and IdP-initiated flows
- Certificate management per tenant
- Recommended library: `github.com/crewjam/saml`

**Effort:** 3-4 weeks, ~30 new files

**Pros:**
- #1 enterprise blocker — without SAML, AuthCore is rejected by enterprise procurement
- Original spec requirement
- Competitive parity with Keycloak and Cognito
- Reuses existing tenant isolation and key management

**Cons:**
- XML complexity — canonicalization (C14N) and signature wrapping attacks
- Large attack surface (XXE, XML injection)
- SAML spec is massive with endless edge cases
- Declining protocol (new integrations prefer OIDC)
- Testing requires real SAML SPs (Salesforce, Workday)

**Recommendation:** Use `crewjam/saml` library rather than implementing from scratch. Focus on SP-initiated flow first (most common). IdP-initiated can come later.

---

### LDAP Analysis

**Verdict: Skip for now.** Generic OIDC provider covers Azure AD, which handles 90% of LDAP use cases.

**What it requires:**
- LDAP client adapter (bind, search, authenticate)
- User federation: sync LDAP users → AuthCore, or passthrough auth
- Group/role mapping from LDAP attributes
- Connection pooling, TLS/STARTTLS
- Config per tenant (LDAP URL, bind DN, search base, attribute mapping)
- Library: `github.com/go-ldap/ldap/v3`

**Effort:** 1-2 weeks

**Pros:**
- Active Directory is still #1 corporate directory
- No user migration needed — authenticate against existing LDAP
- Fits headless model (backend protocol, no UI)

**Cons:**
- Niche and shrinking — new orgs use Azure AD (OIDC), not raw LDAP
- AuthCore already supports Generic OIDC — Azure AD exposes OIDC endpoints
- LDAP connections are stateful (pooling, reconnection, timeouts)
- Every LDAP deployment has custom schema — mapping is never clean
- Security surface: LDAP injection, plaintext bind credentials

**Recommendation:** Only build on specific customer demand. For most cases, configure Azure AD as a Generic OIDC provider instead.

---

### Admin UI Analysis

**Verdict: Don't build built-in. Consider separate companion project.**

**Three options:**

| Option | Effort | Description | Fits AuthCore? |
|--------|--------|-------------|---------------|
| **A: API-only** (current) | Done | Developers use curl/Postman | Yes — headless philosophy |
| **B: Admin CLI** | 1 week | `authcore tenant create --domain example.com` | Yes — stays headless |
| **C: Separate SPA** (`authcore-admin` repo) | 2-3 weeks | React dashboard calling management API | Yes — optional companion |
| **D: Built-in UI** | 4-6 weeks | Serve HTML from same binary | **No** — breaks headless |

**Recommended approach:**
1. **Now:** Option B — build an admin CLI tool (small effort, high developer productivity)
2. **Later:** Option C — separate `authcore-admin` React SPA (optional, open-source)
3. **Never:** Option D — built-in UI contradicts the architecture

---

## Deployment Readiness Checklist

### For Local Development ✅
- [x] In-memory storage
- [x] All 35+ endpoints functional
- [x] Register → Login → Authorize → Token → Verify JWT
- [x] Social login flow (with configured provider)
- [x] MFA TOTP enrollment and verification
- [x] OTP login (email + SMS)
- [x] RBAC role management
- [x] Hot reload with `go run`

### For Staging Deployment ✅
- [x] Postgres connection + auto-migrations (11 SQL files)
- [x] Redis for ephemeral stores (6 stores)
- [x] CORS configured
- [x] Admin API protected with API key
- [x] Client enforcement on OAuth flows
- [x] Scope validation
- [x] MFA enforcement
- [x] E2E tests passing
- [x] Rate limiting (20 req/min)
- [x] Encryption at rest (AES-256-GCM)

### For Production Deployment 🟡
- [x] All staging items
- [x] Rate limiting
- [x] Encryption at rest
- [x] Email verification
- [x] Password reset
- [x] Audit logging
- [x] mTLS for M2M
- [x] OpenTelemetry tracing
- [ ] Security audit (external pen test)
- [ ] Load testing
- [ ] Monitoring (metrics, alerts)
- [ ] Backup/restore procedures
- [ ] Incident response playbook
- [ ] Security headers (HSTS, CSP)

---

## Implementation Priority (Recommended Next Steps)

| Phase | Items | Gets you to |
|-------|-------|-------------|
| **Phase 1** (3-4 weeks) | SAML 2.0 | Enterprise-ready |
| **Phase 2** (2 weeks) | WebAuthn/FIDO2 | Full MFA coverage |
| **Phase 3** (1 week) | Security headers, Postgres RBAC repos, audit auto-wiring | Production-hardened |
| **Phase 4** (1 week) | Admin CLI, key auto-rotation, refresh cleanup | Operational tooling |
| **Phase 5** (external) | Penetration test, load test | Certifiable |
