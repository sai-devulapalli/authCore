# AuthCore — Product Roadmap

> **Last updated:** 2026-03-31
> **Current state:** ~273 files | 812 tests | 141 E2E + 30 Playwright | 80%+ coverage | 49 endpoints | 47 packages | 19 migrations

---

## Overview

```
┌─────────────────────────────────────────────────────────────┐
│  🔴 TIER 1 — DONE ✅                                        │
│  Token versioning, RLS, admin auth, rate limiting,          │
│  JWT sig verification, refresh token hashing                │
├─────────────────────────────────────────────────────────────┤
│  🟠 TIER 2 — DONE ✅                                        │
│  SAML 2.0, Admin UI, webhooks, per-tenant config,           │
│  AI agent auth, per-tenant SMTP. SCIM (pending)             │
├─────────────────────────────────────────────────────────────┤
│  🟢 TIER 3 — Differentiate (next phase)                    │
│  Policy engine (ABAC), risk-based auth                      │
├─────────────────────────────────────────────────────────────┤
│  🔵 TIER 4 — UX & Competitive Edge (new)                   │
│  Magic links, session mgmt, impersonation, passkeys,        │
│  user groups, analytics, auth flow builder                  │
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

### ~~3.2 Event Streaming (Webhooks)~~ — DONE

Implemented: HMAC-SHA256 signed webhook delivery per tenant. 3 endpoints, fire-and-forget from audit service. See `internal/application/webhook/service.go`.

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

## 🔵 Tier 4: UX & Competitive Edge

### 4.1 Magic Link Login (Priority 1)

**Problem:** OTP requires typing a 6-digit code. Magic links are one-click — better UX. Slack, Notion, Linear all use this.

**Design:**
- `POST /magic-link/request` → send email with signed login link
- `GET /magic-link/verify?token=xxx` → validate token, create session, redirect
- Token: JWT with 15-min expiry, single-use (stored in Redis/cache)
- Link format: `https://auth.myapp.com/magic-link/verify?token=eyJ...`

**Effort:** 1-2 days | Reuses existing email sender + token infrastructure

---

### 4.2 Session Management API (Priority 2)

**Problem:** No way to list active sessions, revoke specific sessions, or "sign out everywhere". Enterprise security teams require this.

**Design:**

| Method | Route | Description |
|--------|-------|-------------|
| GET | `/tenants/{tid}/users/{uid}/sessions` | List all active sessions |
| DELETE | `/tenants/{tid}/users/{uid}/sessions/{sid}` | Revoke specific session |
| DELETE | `/tenants/{tid}/users/{uid}/sessions` | Revoke all sessions ("sign out everywhere") |

Each session record: ID, UserID, TenantID, IP, UserAgent, CreatedAt, LastUsedAt, ExpiresAt.

**Effort:** 2-3 days | Extends existing session repository

---

### 4.3 Admin Impersonation (Priority 3)

**Problem:** Support teams need to "see what the user sees" to debug issues. Currently impossible without knowing user's password.

**Design:**
- `POST /admin/impersonate` `{ user_id, tenant_id }` → returns session token for that user
- Only `super_admin` can impersonate
- Audit logged as `EventAdminImpersonation` with admin_id + target user_id
- Impersonated sessions have `impersonated_by` field in session record
- JWT includes `impersonator` claim so downstream APIs can detect impersonation

**Effort:** 2-3 days | Reuses existing session + audit infrastructure

---

### 4.4 Passkey-Only Registration (No Password)

**Problem:** Passwords are dead. Apple, Google, Microsoft all push passkeys. Let users register without ever creating a password.

**Design:**
- `POST /register` accepts `{ email, name }` without password when tenant setting allows
- After registration: immediately start WebAuthn registration flow
- Login: WebAuthn only (no password prompt)
- Tenant setting: `allow_passwordless_registration: true`

**Effort:** 2-3 days | Extends existing WebAuthn + registration flows

---

### 4.5 Token Binding to Device

**Problem:** Stolen JWTs work from any device. Token binding makes them useless if moved.

**Design:**
- Client sends device fingerprint (User-Agent hash + screen size + timezone) during /authorize
- Fingerprint included in JWT as `dfp` claim
- On API calls, server compares request fingerprint vs token fingerprint
- Mismatch → reject with 401 + audit log

**Effort:** 3-5 days

---

### 4.6 User Groups

**Problem:** Assigning roles to individual users doesn't scale. Groups allow "all engineers get editor role".

**Design:**
- `Group` entity: ID, TenantID, Name, Description
- `GroupMembership`: UserID, GroupID, TenantID
- Roles assigned to groups, inherited by members
- JWT `roles` + `permissions` include group-inherited roles

| Method | Route | Description |
|--------|-------|-------------|
| POST/GET | `/tenants/{tid}/groups` | CRUD |
| POST/DELETE | `/tenants/{tid}/groups/{gid}/members/{uid}` | Membership |
| POST/DELETE | `/tenants/{tid}/groups/{gid}/roles/{rid}` | Group roles |

**Effort:** 3-5 days

---

### 4.7 IP Allowlisting per Tenant

**Problem:** Enterprise: "only allow login from our office IP ranges". Currently no IP filtering.

**Design:**
- Add `allowed_ips []string` to TenantSettings (CIDR notation: `10.0.0.0/8`, `203.0.113.0/24`)
- Check client IP against allowlist in /login and /authorize middleware
- Empty list = allow all (default)
- Admin UI: textarea in Settings tab

**Effort:** 1-2 days

---

### 4.8 Account Lockout

**Problem:** Brute force protection beyond rate limiting. Lock account after N failures, auto-unlock after timeout.

**Design:**
- Track failed login attempts per user in cache/Redis
- After `max_login_attempts` (from TenantSettings): lock account
- `lockout_duration` seconds: auto-unlock
- `POST /tenants/{tid}/users/{uid}/unlock` — admin manual unlock
- Audit: `EventAccountLocked`, `EventAccountUnlocked`

**Effort:** 2-3 days | TenantSettings fields already exist

---

### 4.9 Brute Force Intelligence

**Problem:** Track bad actors globally. Share threat intel across tenants.

**Design:**
- Global failed-IP counter (Redis sorted set)
- If IP fails across multiple tenants → auto-block for 24h
- `GET /admin/threats` — list blocked IPs with failure count
- `DELETE /admin/threats/{ip}` — unblock

**Effort:** 3-5 days

---

### 4.10 Login/Signup Analytics

**Problem:** No visibility into auth metrics per tenant. "How many users signed up this week?"

**Design:**
- `GET /tenants/{tid}/analytics` — returns counts from audit events
  ```json
  {
    "registrations_24h": 15,
    "logins_24h": 230,
    "failed_logins_24h": 12,
    "mfa_adoption_rate": 0.45,
    "active_sessions": 89,
    "top_login_methods": ["password", "otp", "google"]
  }
  ```
- Computed from audit_events table (no new storage)
- Admin UI: dashboard cards with sparklines

**Effort:** 3-5 days

---

### 4.11 Tenant Cloning

**Problem:** Onboarding a new customer with similar config to existing one. Manually recreating clients, providers, roles is tedious.

**Design:**
- `POST /tenants/{source_id}/clone` `{ new_id, new_domain }` → copies all config
- Clones: clients (new secrets), providers, roles, settings, webhooks
- Does NOT clone: users, sessions, audit events

**Effort:** 1-2 days

---

### 4.12 Auth Flow Builder

**Problem:** Fixed auth flow (register → login → MFA). Some tenants want: register → email verify → admin approve → MFA. Others want: SSO only, no local registration.

**Design:**
- JSON-based flow definition per tenant stored in TenantSettings:
  ```json
  {
    "registration_flow": ["collect_email", "collect_password", "verify_email"],
    "login_flow": ["password", "mfa_if_required"],
    "require_email_verification": true,
    "allow_registration": true,
    "require_admin_approval": false
  }
  ```
- Services check flow config before proceeding

**Effort:** 1-2 weeks

---

## Implementation Priority

```
Immediate (1 week):
  Magic link login → Session management → Impersonation

Next (2-3 weeks):
  Account lockout → IP allowlisting → Passkey registration

Following (1 month):
  User groups → Analytics → Tenant cloning

Later:
  Token binding → Brute force intel → Auth flow builder
  ABAC policy engine → Risk-based auth
```

## Estimated Total

| Tier | Items | Status | Effort |
|------|-------|--------|--------|
| Tier 1 | 6 features | **DONE** | — |
| Tier 2 | 6 features | **DONE** | — |
| Tier 3 | 2 features | Pending | 4-6 weeks |
| Tier 4 | 12 features | Pending | 6-10 weeks |
| **Total remaining** | **14 features** | | **~10-16 weeks** |
