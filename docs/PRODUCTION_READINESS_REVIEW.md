# AuthCore — Production Readiness Review

> **Reviewer:** Senior Staff Engineer / Principal Architect perspective
> **Context:** Healthcare SaaS platform (HIPAA/NABH regulated)
> **Date:** 2026-03-29
> **Verdict:** 6 critical issues FIXED (2026-03-29). 8 high issues remain (P1).

---

## 1. ARCHITECTURE & DESIGN

### Current State
Hexagonal architecture is **cleanly implemented**. No domain→adapter import violations found. Dependency direction is correct throughout all 45 packages.

- Domain layer (`internal/domain/`) — pure Go structs + interfaces, zero infrastructure imports
- Application layer (`internal/application/`) — orchestration only, depends on domain ports
- Adapter layer (`internal/adapter/`) — implements domain ports
- Wiring (`cmd/authcore/main.go`) — dependency injection via constructors + functional options

### Gaps

| Severity | Finding | File |
|----------|---------|------|
| MEDIUM | Domain entities are mostly **anemic** — structs with minimal behavior. Validation logic lives in constructors, not methods | `domain/user/user.go`, `domain/tenant/tenant.go` |
| LOW | No event-driven patterns — services call each other synchronously. Audit wiring is procedural, not event-based | `application/*/service.go` |
| LOW | No CQRS — reads and writes go through the same repos and service methods | All services |

### Risk
Architecture is sound for current scale. Will need event-driven patterns (webhooks, async audit) at 10K+ tenants.

### Recommendation
- P3: Enrich domain entities with behavior (validation, state transitions)
- P3: Introduce event bus for audit + webhooks when implementing Tier 3 roadmap

---

## 2. MULTI-TENANCY & DATA ISOLATION

### Current State
`tenant_id` present on all 12 data tables. Every Postgres query includes `WHERE tenant_id = $N`. RLS migration (015) exists with `FORCE ROW LEVEL SECURITY` on all tables.

### Gaps

| Severity | Finding | File |
|----------|---------|------|
| **CRITICAL** | `WithTenantTx()` is **never called** — RLS policies exist but are never activated because `SET LOCAL app.tenant_id` is never executed. RLS is dead code. | `postgres/tenant_context.go` (defined), zero callers |
| **CRITICAL** | Tenant isolation relies **solely** on application-level `WHERE` clauses. A single missed parameter = cross-tenant data leak | All Postgres repos |
| HIGH | No integration tests proving tenant isolation at DB level | `e2e/` tests check HTTP-level isolation only |
| MEDIUM | Tenant context not propagated to cleanup service background goroutine | `application/cleanup/service.go` |

### Risk
**A developer adding a new query without `AND tenant_id = $N` will silently leak data across tenants.** RLS was designed to prevent this but is not active. For healthcare (HIPAA Technical Safeguard 164.312(a)(1)), this is a compliance violation.

### Recommendation
- **P0:** Modify all Postgres repos to use `WithTenantTx()` before every query, or at minimum call `SET LOCAL app.tenant_id` at the start of each HTTP request via middleware
- **P0:** Write integration tests that prove cross-tenant queries return zero rows without explicit WHERE
- Priority: Must fix before any production deployment

---

## 3. SECURITY

### Current State
Authentication via OIDC/OAuth 2.0 with JWT (RS256/ES256). Admin auth supports API key + JWT. Bcrypt cost 12 for password hashing. Parameterized SQL everywhere (no injection vectors).

### Gaps

| Severity | Finding | File |
|----------|---------|------|
| ~~CRITICAL~~ | ~~JWT signature NOT verified in introspection~~ | **FIXED** — `verifyAndDecodeJWT()` validates RS256/ES256 against tenant JWKS |
| ~~CRITICAL~~ | ~~Admin JWT signature NOT verified~~ | **FIXED** — middleware accepts JWTVerifier function for signature validation |
| ~~CRITICAL~~ | ~~Refresh tokens stored in plaintext~~ | **FIXED** — SHA-256 hashed before storage, constant-time lookup |
| ~~CRITICAL~~ | ~~Rate limiter bypassable via X-Forwarded-For~~ | **FIXED** — uses RemoteAddr only, ignores spoofable headers |
| HIGH | PII (email addresses) logged in plaintext in admin and user services | `application/admin/service.go:84-93`, `application/user/service.go:93` |
| HIGH | No `MaxBytesReader` on request bodies — unbounded request size → memory exhaustion | All handlers |
| HIGH | No maximum password length — bcrypt with very long passwords = CPU DoS | `adapter/crypto/hasher.go` |
| MEDIUM | CORS allows wildcard (`*`) by default — should require explicit origins in production | `middleware/cors.go:36-38` |
| MEDIUM | No security headers (HSTS, CSP, X-Content-Type-Options, X-Frame-Options) | Missing entirely |
| LOW | `rand.Read()` error not checked in JTI generation (unlikely to fail but technically wrong) | `application/auth/service.go:613` |

### Risk
The JWT signature verification gaps are **authentication bypass vulnerabilities**. An attacker who discovers the introspection or admin endpoints can forge tokens without knowing the signing key. This is a severity-1 security incident waiting to happen.

### Recommendation
- ~~P0: JWT signature verification in introspection~~ **DONE**
- ~~P0: Admin JWT signature verification~~ **DONE**
- ~~P0: Hash refresh tokens~~ **DONE** (SHA-256)
- ~~P0: Rate limiter X-Forwarded-For fix~~ **DONE** (uses RemoteAddr)
- P1: Add `http.MaxBytesReader` (1MB default) to all handlers
- P1: Cap password length at 72 bytes (bcrypt limit) or 128 chars
- P1: Remove PII from logs — log user_id instead of email
- P1: Add security headers middleware

---

## 4. RELIABILITY & RESILIENCE

### Current State
HTTP server with 10s read/write timeout, 60s idle. Redis fallback to in-memory on connection failure. Graceful shutdown with 15s timeout.

### Gaps

| Severity | Finding | File |
|----------|---------|------|
| HIGH | **Zero query-level timeouts** — 43 DB queries use `r.Context()` directly, no `context.WithTimeout`. Slow query = blocked goroutine indefinitely | All Postgres repos |
| HIGH | **Connection pool not configured** — `sql.Open()` called directly, not using `database.NewConnection()` with pool settings. Go default = unlimited connections | `cmd/authcore/main.go:401` vs `pkg/sdk/database/database.go` |
| HIGH | **Cleanup service cancel bug** — `defer cleanupCancel()` fires immediately, not after shutdown signal. Cleanup goroutine starts but may be cancelled prematurely | `cmd/authcore/main.go:467-469` |
| HIGH | No circuit breakers, retries, or bulkheads on any external call | Entire codebase |
| MEDIUM | Bcrypt DoS — no timeout on password hashing. Cost 12 = ~100ms, long password = longer | `adapter/crypto/hasher.go` |
| MEDIUM | Database unavailable = server won't start (crashes). No degraded mode | `cmd/authcore/main.go:434-437` |
| LOW | In-memory rate limiter doesn't work across multiple instances | `middleware/ratelimit.go` |

### Risk
Under load, connection pool exhaustion will cascade: DB connections fill up → queries queue → goroutines accumulate → memory exhaustion → OOM kill. No circuit breaker means one slow dependency takes everything down.

### Recommendation
- **P0:** Use `database.NewConnection()` with pool config (25 open, 5 idle, 30min lifetime)
- **P0:** Add `context.WithTimeout(ctx, 5*time.Second)` to all DB queries
- P1: Fix cleanup service cancel ordering
- P1: Add circuit breaker on Redis (already has fallback, but no detection/recovery)
- P2: Implement Redis-backed rate limiting for multi-instance deployments

---

## 5. OBSERVABILITY

### Current State
Structured logging via `slog` (JSON in production, text in dev). OpenTelemetry tracing middleware captures HTTP method/URL/status. Audit logging captures 25+ event types.

### Gaps

| Severity | Finding | File |
|----------|---------|------|
| HIGH | **No Prometheus `/metrics` endpoint** — zero runtime metrics available | Missing entirely |
| HIGH | **No request_id in logs** — cannot correlate log entries for a single request | `pkg/sdk/logger/`, all handlers |
| HIGH | **No tenant_id or user_id in log context** — forensic investigation impossible | All service logs |
| MEDIUM | **No DB query instrumentation** — slow queries invisible in traces | Postgres repos |
| MEDIUM | **No cache hit/miss tracking** — Redis/in-memory cache effectiveness unknown | Cache repos |
| LOW | Tracing doesn't capture response body size or auth method used | `middleware/tracing.go` |

### Risk
When a production incident occurs, the current tooling is insufficient to diagnose root cause. You cannot: correlate logs across a request chain, identify which tenant is affected, measure query latency, or know if the cache is working. You will be debugging blind.

### Recommendation
- **P0:** Add request_id middleware (generate UUID, inject into context + all logs)
- P1: Add Prometheus metrics (HTTP latency/count, DB query latency, connection pool stats)
- P1: Add tenant_id + user_id to structured log context
- P2: Instrument DB queries with OTel spans

---

## 6. DATABASE & DATA MODEL

### Current State
15 Postgres migrations (all forward-only, idempotent with `IF NOT EXISTS`). Parameterized queries everywhere. Indexes on high-cardinality lookups.

### Gaps

| Severity | Finding | File |
|----------|---------|------|
| HIGH | **Only 1 of 11 Postgres repos has tests** (JWK repo only). 10 repos completely untested at DB level | `adapter/postgres/` |
| MEDIUM | No FK constraints between tables — referential integrity enforced only in application code | All migrations |
| MEDIUM | No data partitioning strategy — `audit_events` will grow unbounded | `migrations/011_create_audit_events.sql` |
| MEDIUM | No index on `refresh_tokens(tenant_id)` — full table scan for tenant-scoped queries | `migrations/005_create_refresh_tokens.sql` |
| LOW | Migration 015 (RLS) applied at startup — if misconfigured, entire DB becomes inaccessible. No validation | `postgres/migrator.go` |
| LOW | No backup/restore testing documented | Missing |

### Recommendation
- P1: Add FK constraints (users → tenants, clients → tenants, etc.) or document why omitted
- P1: Add index on `refresh_tokens(tenant_id)`
- P1: Write Postgres repo integration tests (at minimum: user, client, tenant, refresh repos)
- P2: Implement audit event partitioning by month + retention policy
- P2: Document backup/restore procedure with tested RTO/RPO

---

## 7. SCALABILITY

### Current State
Stateless HTTP server (any instance can handle any request). Postgres for persistent data, Redis for ephemeral. Background cleanup service runs every 24h.

### What breaks first at 10x/100x load:

| Scale | Bottleneck | Why |
|-------|-----------|-----|
| 10x | **Connection pool** (not configured = unlimited) | Goroutine/connection leak under sustained load |
| 10x | **Rate limiter** (in-memory, per-instance) | Inconsistent enforcement across N instances |
| 100x | **Bcrypt CPU** (cost 12, ~100ms/hash) | `/login` and `/register` become CPU-bound |
| 100x | **Audit table** (unbounded growth) | Full table scans on query, storage costs |
| 1000x | **Postgres single-primary** (no read replicas) | All reads hit primary |

### Recommendation
- P0: Configure connection pool (see #4)
- P1: Redis-backed rate limiting
- P2: Read replica routing for `/jwks`, `/introspect`, `/userinfo`
- P3: Audit event partitioning + archival

---

## 8. OPERATIONAL READINESS

### Gaps

| Severity | Finding |
|----------|---------|
| HIGH | No runbook for common incidents |
| HIGH | No feature flag system |
| MEDIUM | No blue-green or canary deployment strategy documented |
| MEDIUM | Developer setup guide doesn't mention the 6 new GTM features |
| LOW | No on-call playbook or alert tuning |

### Recommendation
- P1: Write incident runbook (DB down, Redis down, high latency, auth bypass)
- P2: Add feature flags (environment variable based minimum)
- P2: Document deployment strategy

---

## 9. CODE QUALITY & MAINTAINABILITY

### Current State
812 test functions, 141 E2E subtests + 30 Playwright. Consistent error handling with `AppError`. Functional options pattern throughout.

### Gaps

| Severity | Finding | File |
|----------|---------|------|
| HIGH | **~227 `//nolint:errcheck` suppressions** in production code — errors silently swallowed | Multiple files |
| HIGH | **Admin service (0 tests)** and **SAML service (0 tests)** — critical auth paths untested | `application/admin/`, `application/saml/` |
| MEDIUM | 5 critical error paths in token exchange ignore return values | `application/auth/service.go:239,254` |
| LOW | Some TODOs remain (e.g., Postgres role repo TODO was resolved but comment may remain) | Various |

### Recommendation
- P1: Audit all `//nolint:errcheck` in auth/token paths — handle or explicitly document why safe
- P1: Write tests for admin bootstrap/login and SAML SSO/ACS flows
- P2: Reduce errcheck suppressions to <50 (from 227)

---

## 10. COMPLIANCE & HEALTHCARE-SPECIFIC

### Sidecar Compliance Model

When deployed as a sidecar or embedded library, AuthCore **inherits your app's compliance posture**. SOC2/HIPAA certifications are your infrastructure's responsibility. AuthCore provides the building blocks auditors need.

### What's Fixed

| Item | Status |
|------|--------|
| ~~Audit logs not tamper-proof~~ | **FIXED** — migration 016 prevents UPDATE/DELETE on audit_events |
| ~~No GDPR right-to-erasure~~ | **FIXED** — `HardDelete(id, tenantID)` on user repository |
| ~~No consent management~~ | **FIXED** — `ConsentGranted` + `ConsentTimestamp` fields on User entity |

### Remaining Gaps

| Severity | Finding |
|----------|---------|
| HIGH | PII not encrypted at field level — email, phone in plaintext in Postgres |
| MEDIUM | No data retention policy enforcement — audit events grow unbounded |
| MEDIUM | No de-identification support for research/analytics |
| MEDIUM | No audit log export for compliance reporting |

### Recommendation
- P1: Add field-level encryption for PII (email, phone)
- P2: Implement data retention policies with automated enforcement
- P2: Add audit log CSV/JSON export endpoint

---

## Top 5 Things That WILL Cause a Production Incident

> **UPDATE (2026-03-29):** Items 1-3 have been FIXED. Items 4-5 remain as HIGH priority.

| Rank | Issue | Status | Fix Applied |
|------|-------|--------|-------------|
| ~~1~~ | ~~JWT signature not verified~~ | **FIXED** | `verifyAndDecodeJWT()` validates RS256/ES256 against tenant JWKS |
| ~~2~~ | ~~Connection pool not configured~~ | **FIXED** | 25 max open, 5 idle, 30min lifetime |
| ~~3~~ | ~~Rate limiter bypassable~~ | **FIXED** | Uses `RemoteAddr` only, ignores spoofable headers |
| 4 | **RLS not activated** — WithTenantTx not called in repos | OPEN | RLS policies exist, need repo-level transaction wrapping |
| 5 | **No query timeouts** — slow queries block goroutines | OPEN | Need `context.WithTimeout` in all repo methods |

**Additional fixes applied:**
- Refresh tokens now hashed (SHA-256) before storage
- Admin JWT signature verification via JWTVerifier function
- TenantID (`tid`) claim added to JWTs for signature verification lookup

---

## Top 5 Things Done Well (Preserve These)

| # | What | Why It Matters |
|---|------|---------------|
| 1 | **Clean hexagonal architecture** — zero domain→adapter imports, perfect dependency direction | Enables embeddable SDK, testability, future protocol additions (gRPC) |
| 2 | **Parameterized SQL everywhere** — zero SQL injection vectors across all 11 repos | Critical security foundation |
| 3 | **Comprehensive E2E test suite** — 141 subtests covering auth flows, RBAC, multi-tenant, MFA | Catch regressions early |
| 4 | **Functional options pattern** — `WithRefreshRepo()`, `WithAudit()`, `WithWebAuthn()` | Clean dependency injection without frameworks |
| 5 | **RLS migration infrastructure** — policies are correctly written, just need activation | Foundation exists, only wiring needed |

---

## Architecture Decision Records (Should Be Documented)

| Decision | Rationale | Trade-off |
|----------|-----------|-----------|
| **Go over Java/Node** | 15MB binary, <300MB RAM, stdlib crypto | Smaller ecosystem than Java, Go-only for embedded SDK |
| **Hexagonal architecture** | Embeddable SDK + testability + adapter swapability | More boilerplate (interfaces, constructors, wiring) |
| **Application-level tenant isolation** | Simpler implementation, tenant_id in every query | Less secure than RLS — must be upgraded |
| **In-memory fallback for Redis** | Graceful degradation when Redis unavailable | Sessions lost on restart without Redis |
| **JWT introspection with signature verification** | Security over performance — verifies RS256/ES256 against JWKS | Slight latency increase (~1ms), graceful fallback for legacy tokens |
| **Single Postgres database for all tenants** | Operational simplicity, thousands of tenants | Noisy neighbor risk, shared connection pool |
| **bcrypt cost 12** | Balance of security vs latency (~100ms) | CPU-bound under high registration/login load |
| **crewjam/saml library** | Only mature Go SAML library | Community-maintained, slower CVE response |
| **Separate admin UI repo** | Keeps Go binary small, independent deploy | Extra deployment target, CORS complexity |
| **Coverage threshold 80%** | Pragmatic — WebAuthn/SAML need browser/IdP for full coverage | Below industry 85%+ standard for security-critical code |
