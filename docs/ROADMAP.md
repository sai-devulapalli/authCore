# AuthCore — Product Roadmap

> **Last updated:** 2026-03-29
> **Current state:** 249 files | 785 tests | 131 E2E subtests | 83.4% coverage | 39 endpoints | 42 packages

---

## Overview

```
┌─────────────────────────────────────────────────────────────┐
│  🔴 TIER 1 — Must Do NOW (security + operational maturity) │
│  Token versioning, DB tenant isolation, rate limiting,      │
│  admin auth model                                           │
├─────────────────────────────────────────────────────────────┤
│  🟠 TIER 2 — Unlock Enterprise (compliance + provisioning) │
│  SAML 2.0, SCIM, Admin UI                                  │
├─────────────────────────────────────────────────────────────┤
│  🟢 TIER 3 — Differentiate (advanced security + platform)  │
│  Policy engine (ABAC), webhooks, risk-based auth            │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔴 Tier 1: Must Do NOW

### 1.1 Token Versioning (Instant Revocation)

**Problem:** Revoking all tokens for a user/tenant requires waiting for JWT expiry (1h). No way to force-invalidate all tokens issued before a specific point.

**Current state:** JTI-based blacklist (in-memory + Redis). Refresh token family revocation works. No version/generation field for bulk invalidation.

**Design:**

| Component | Change |
|-----------|--------|
| `domain/token/token.go` | Add `TokenVersion int` to Claims |
| `domain/user/user.go` | Add `TokenVersion int` to User |
| `domain/tenant/tenant.go` | Add `TokenVersion int` to Tenant |
| `domain/client/client.go` | Add `TokenVersion int` to Client |
| Postgres migration | `ALTER TABLE` add `token_version INTEGER DEFAULT 1` |
| `application/auth/service.go` | Include `tv` claim in JWTs; on introspect compare JWT `tv` vs current entity version |
| Handler | `POST /tenants/{tid}/users/{uid}/revoke-tokens` — increments user token_version |
| Handler | `POST /tenants/{tid}/revoke-tokens` — increments tenant token_version |

**Revocation flows:**
- **Revoke all user tokens:** Increment `user.TokenVersion` → JWTs with old `tv` rejected
- **Revoke all tenant tokens:** Increment `tenant.TokenVersion` → entire tenant invalidated
- **Revoke single token:** Existing JTI blacklist (unchanged)

**Effort:** Small (1-2 days) | **Files:** ~8 modified, 1 migration

---

### 1.2 Database-Level Tenant Isolation (Row-Level Security)

**Problem:** Tenant isolation is application-only (`WHERE tenant_id = $N`). A missed query or SQL injection = cross-tenant data leak.

**Current state:** `tenant_id` on all tables. Every query includes it. But no Postgres RLS policies.

**Design:**

```sql
-- Per table (users, clients, refresh_tokens, roles, etc.)
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_users ON users
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
```

| Component | Change |
|-----------|--------|
| Migration `013_enable_rls.sql` | Enable RLS + create policies on all 10 tenant-scoped tables |
| All Postgres repos | `SET LOCAL app.tenant_id = $1` before queries |
| Connection pool | `RESET app.tenant_id` per transaction |
| Migration runner | Uses superuser role (bypasses RLS) |

**Tables requiring RLS:** users, clients, refresh_tokens, identity_providers, external_identities, roles, user_role_assignments, audit_events, webauthn_credentials

**Effort:** Medium (3-5 days) | **Files:** 1 migration, ~7 repos modified

---

### 1.3 Multi-Level Rate Limiting

**Problem:** Single-level in-memory rate limiter. Doesn't scale, wrong HTTP status (400 not 429), no per-tenant or per-user limits.

**Current state:** Sliding window per IP, 20 req/min, in-memory only. Applied to /login, /token, /otp/verify, /mfa/verify.

**Design — Rate limit tiers:**

| Tier | Scope | Limit | Window | Endpoints |
|------|-------|-------|--------|-----------|
| Auth | Per IP | 20/min | 1 min | /login, /token, /mfa/verify, /otp/verify |
| Registration | Per IP | 5/min | 1 min | /register |
| API | Per tenant | 1000/min | 1 min | All tenant-scoped |
| Admin | Per API key | 100/min | 1 min | /tenants/* management |
| Global | Per IP | 200/min | 1 min | All (backstop) |

| Component | Change |
|-----------|--------|
| `middleware/ratelimit.go` | Refactor for multi-tier support |
| `adapter/redis/ratelimit.go` | New — Redis `INCR` + `EXPIRE` for distributed limiting |
| `config/config.go` | Add `AUTHCORE_RATE_LIMIT_*` env vars |
| Response | HTTP 429 with `Retry-After` header |

**Fallback:** Redis unavailable → in-memory (current behavior).

**Effort:** Medium (3-4 days) | **Files:** ~5 modified/created

---

### 1.4 Admin Auth Model (Replace API Key)

**Problem:** Single shared API key, no scoping, no expiry, no roles, no audit trail.

**Design — Admin roles:**

| Role | Permissions |
|------|-------------|
| `super_admin` | Full access to all tenants |
| `tenant_admin` | Scoped to specific tenant(s) |
| `readonly` | GET-only |
| `auditor` | Audit logs only |

**Auth flow:**
```
1. Bootstrap: POST /admin/bootstrap { email, password }
   (only works if no admins exist, uses AUTHCORE_ADMIN_API_KEY as bootstrap secret)

2. Login: POST /admin/login { email, password } → admin JWT (1h)
   Claims: { sub, role, tenant_ids, permissions, exp }

3. API calls: Authorization: Bearer <admin-jwt>

4. Backward compat: X-API-Key still works → treated as super_admin
```

| Component | Change |
|-----------|--------|
| `domain/admin/` | New — AdminUser, AdminSession entities |
| `application/admin/service.go` | New — Bootstrap, Login, CRUD |
| `adapter/postgres/migrations/014_create_admin_users.sql` | New table |
| `middleware/admin_auth.go` | Support API key OR admin JWT |
| `handler/admin.go` | New — /admin/bootstrap, /admin/login, /admin/users |

**Effort:** Medium-Large (4-5 days) | **Files:** ~12 new, ~3 modified

---

## 🟠 Tier 2: Unlock Enterprise

### 2.1 SAML 2.0

**Problem:** Enterprise customers require SAML SSO. Without it, AuthCore is rejected by Okta/Azure AD shops.

**Dependency:** `github.com/crewjam/saml`

**Endpoints:**

| Method | Route | Description |
|--------|-------|-------------|
| GET | `/saml/metadata` | SP metadata XML |
| GET | `/saml/sso?provider={id}` | Redirect to IdP |
| POST | `/saml/acs` | Assertion Consumer Service — validate response, link identity, issue code |

**Flow:**
```
Admin configures IdP → User clicks SSO → Redirect to IdP
→ IdP authenticates → POSTs SAML assertion to /saml/acs
→ Validate XML signature → Extract NameID → Link identity → Issue auth code
```

**Effort:** Large (2-3 weeks) | **Files:** ~15 new, ~5 modified

---

### 2.2 SCIM (User Provisioning)

**Problem:** Enterprise IdPs need to auto-provision/deprovision users. Without SCIM, user lifecycle is manual.

**Endpoints (RFC 7644):**

| Method | Route | Description |
|--------|-------|-------------|
| GET | `/scim/v2/Users` | List with filtering (`?filter=userName eq "..."`) |
| POST | `/scim/v2/Users` | Create |
| GET | `/scim/v2/Users/{id}` | Get |
| PUT | `/scim/v2/Users/{id}` | Replace |
| PATCH | `/scim/v2/Users/{id}` | Partial update |
| DELETE | `/scim/v2/Users/{id}` | Deactivate |
| GET | `/scim/v2/ServiceProviderConfig` | Capability discovery |
| GET | `/scim/v2/Schemas` | Schema definitions |

**Key change:** Add `List(ctx, tenantID, filter, limit, offset)` to user repository.

**Effort:** Medium (1-2 weeks) | **Files:** ~10 new, ~4 modified

---

### 2.3 Admin UI

**Status:** Separate repo `authcore-admin` created. Dashboard, Tenant/Client/Provider/Role CRUD, Audit viewer done.

**Remaining:** User management page, SAML config form, SCIM status view, webhook management, CI/CD deployment.

**Effort:** Ongoing (incremental)

---

## 🟢 Tier 3: Differentiate

### 3.1 Policy Engine (ABAC)

**Problem:** RBAC can't express "allow if user.department == resource.department AND time is business hours".

**Design:** JSON-based policy rules evaluated at request time.

```json
{
  "name": "department-access",
  "effect": "allow",
  "rules": [{
    "subjects": { "department": "${user.department}" },
    "resources": { "type": "document", "department": "${user.department}" },
    "actions": ["read", "write"],
    "conditions": { "time": { "after": "09:00", "before": "18:00" } }
  }]
}
```

**Options:** Custom JSON DSL (MVP) → CEL (`google/cel-go`) → Casbin if needed.

**Effort:** Large (2-3 weeks) | **Files:** ~15 new

---

### 3.2 Event Streaming (Webhooks First)

**Problem:** No way to notify external systems of auth events. Must poll audit API.

**Design:**

| Method | Route | Description |
|--------|-------|-------------|
| POST | `/tenants/{tid}/webhooks` | Create subscription (URL, secret, event types) |
| GET | `/tenants/{tid}/webhooks` | List subscriptions |
| DELETE | `/tenants/{tid}/webhooks/{id}` | Delete |

**Payload:** JSON event with HMAC-SHA256 signature in `X-AuthCore-Signature` header.

**Delivery:** Background worker via Redis queue. Retry with exponential backoff (3 attempts).

**Effort:** Medium (1-2 weeks) | **Files:** ~10 new, ~2 modified

---

### 3.3 Risk-Based Auth (Adaptive MFA)

**Problem:** MFA is all-or-nothing. No way to trigger only when risk is elevated.

**Risk signals:**

| Signal | Weight | Description |
|--------|--------|-------------|
| New IP | +30 | Not seen in 30 days |
| New device | +25 | User-Agent not seen before |
| Impossible travel | +50 | >500km from last login in <1h |
| Failed attempts | +20 | >3 failures in 10 min |
| Off-hours | +10 | Outside typical active hours |
| Known IP | -20 | Used >5 times successfully |

**Decision matrix:**

| Score | Action |
|-------|--------|
| 0-30 | Allow (no MFA) |
| 31-60 | Step-up MFA |
| 61-80 | MFA + email alert |
| 81-100 | Block + admin alert |

**Effort:** Large (2-3 weeks) | **Files:** ~12 new, ~3 modified

---

## Implementation Order

```
Phase 1 (Weeks 1-2):   Token versioning + Admin auth model
Phase 2 (Weeks 2-3):   DB tenant isolation (RLS) + Multi-level rate limiting
Phase 3 (Weeks 3-6):   SAML 2.0
Phase 4 (Weeks 5-7):   SCIM + Webhooks (parallelizable with SAML)
Phase 5 (Weeks 7-9):   Policy engine (ABAC)
Phase 6 (Weeks 9-11):  Risk-based auth
Admin UI:               Continuous (pages added as features ship)
```

## Dependency Graph

```
Token versioning ──→ Admin auth model ──→ SAML 2.0 ──→ SCIM
                                                    ↗
DB tenant isolation (RLS) ─────────────────────────

Multi-level rate limiting ─── (independent) ───────

Webhooks ──→ Risk-based auth (uses event signals)
          ↗
ABAC ────
```

## Estimated Total

| Tier | Items | Effort |
|------|-------|--------|
| Tier 1 | 4 features | 2-3 weeks |
| Tier 2 | 3 features | 4-6 weeks |
| Tier 3 | 3 features | 5-8 weeks |
| **Total** | **10 features** | **~11-17 weeks** |
