# AuthCore — Implementation Tracker

> **Last updated:** 2026-03-26
> **Stats:** ~237 files | 720 tests | 85.0% coverage (85% threshold) | 35+ endpoints | 40 packages

---

## Original Requirements Status

| # | Original Requirement | Status | Module | Notes |
|---|---------------------|--------|--------|-------|
| 1 | Headless architecture — no HTML/CSS, API-only | Done | Core | No UI generated anywhere |
| 2 | OIDC & OAuth 2.0 protocol support | Done | 2-3 | All 5 grant types |
| 3 | JWT signed tokens (RS256, ES256) | Done | 2-3 | Stdlib crypto, no external JWT lib |
| 4 | OIDC Discovery (`.well-known/openid-configuration`) | Done | 2 | RFC 8414 compliant |
| 5 | JWKS endpoint | Done | 2 | RFC 7517 compliant |
| 6 | Authorization Code Flow + PKCE | Done | 3 | S256 method |
| 7 | Token Issuance (access_token, id_token) | Done | 3 | + refresh_token in Module 5 |
| 8 | Multi-tenancy (domain-based or header-based) | Done | 4 | Configurable via AUTHCORE_TENANT_MODE |
| 9 | Isolated signing keys per tenant | Done | 4 | RSA-2048 + EC P-256 |
| 10 | Repository pattern (Postgres + SQL Server) | Partial | 0-4 | Postgres: JWK + tenant repos done. SQL Server: migrations placeholder only |
| 11 | Hexagonal architecture (domain/application/adapter) | Done | All | Strict layer separation throughout |
| 12 | No panics — graceful failure with Result[T] | Done | All | Zero panic() in production code |
| 13 | Quality gates: 85% line coverage | Done | All | Threshold at 85%, currently 85.0% |
| 14 | Test triad: 85% unit, 10% functional, 5% e2e | Done | All | Unit: 720 tests. E2E: golden path + in-memory variants |
| 15 | E2E with real Postgres + Redis via testcontainers | Done | E2E | Docker testcontainers + in-memory fallback tests |
| 16 | Structured logging (local/staging/prod levels) | Done | 1 | slog-based, env-aware |
| 17 | No mocks in E2E tests | Done | — | Convention established |
| 18 | 3 environments: local, staging, production | Done | 1+PH | In-memory (local) vs Postgres (staging/prod) |
| 19 | SDK/foundation for common features | Done | 1 | pkg/sdk: errors, logger, httputil, database, health |
| 20 | Iterative module build with checkpoints | Done | All | 10 modules completed sequentially |
| 21 | Sequence diagram for Auth Code + PKCE | Done | docs | In docs/README.md |
| 22 | Docker container / single binary | Done | 0 | ~15MB distroless image |
| 23 | SDK-friendly discovery endpoints | Done | 2 | Any OIDC library auto-configures |
| 24 | Stateless sessions (Redis/distributed cache) | Done | 8+GTM | Server-side sessions in Redis (prod) or in-memory (dev) |
| 25 | SAML 2.0 support | Not done | — | Analysis in docs/ROADMAP.md |
| 26 | mTLS for M2M | Done | 10 | mTLS middleware for client certificate verification |
| 27 | Externalized logs / event streaming | Partial | 1 | Structured logging done, no webhooks/syslog |
| 28 | BYODB (Postgres + SQL Server + CockroachDB) | Partial | 0 | Postgres only. CockroachDB is Postgres-compatible |

---

## Modules Completed

| Module | Name | Status | Files | Tests | Key Deliverables |
|--------|------|--------|-------|-------|-----------------|
| 0 | Scaffold & Quality Gates | Done | ~15 | ~84 | Makefile, CI/CD, golangci-lint, coverage script, Dockerfile, docker-compose |
| 1 | Foundation SDK | Done | ~12 | ~84 | errors/Result[T], AppError/ErrorCode, logger (slog), httputil, database, health, testutil |
| 2 | OIDC Discovery & JWKS | Done | ~23 | ~18 | GET /.well-known/openid-configuration, GET /jwks, RSA/EC keygen, PEM-to-JWK converter |
| 3 | Token Issuance (Auth Code + PKCE) | Done | ~22 | ~15 | GET /authorize (302), POST /token, JWT signing (stdlib), PKCE S256, auth code storage |
| 4 | Multi-Tenancy | Done | ~12 | ~20 | Tenant CRUD, middleware (header/domain), per-tenant keys, shared context helpers |
| 5 | Client Registry + Token Lifecycle | Done | ~25 | ~60 | Client entity (public/confidential), all 5 grant types, refresh rotation + replay detection, device code (RFC 8628), revocation (RFC 7009), introspection (RFC 7662), bcrypt hashing |
| 6 | Social Login | Done | ~20 | ~30 | Google/GitHub/Microsoft/Apple/generic OIDC/OAuth2, outbound OAuth client, identity linking, provider CRUD |
| 7a | MFA — TOTP | Done | ~12 | ~25 | RFC 6238 TOTP, HMAC-SHA1, enroll/confirm/verify, MFA challenge entity |
| 8 | User Authentication | Done | ~18 | ~35 | POST /register, POST /login, POST /logout, GET /userinfo, session management, /authorize session resolution, UserValidator for password grant |
| PH | Production Hardening | Done | ~6 | ~15 | CORS middleware, client enforcement on /authorize + /token, admin API key auth, Postgres auto-migration runner (9 SQL files), pgx driver |
| 9 | OTP + Phone + Password Reset | Done | ~15 | ~25 | POST /otp/request, POST /otp/verify, POST /password/reset, phone field on User, console + SMTP email adapter, console + Twilio SMS adapter |
| 10 | RBAC + Audit + OTel + mTLS | Done | ~20 | ~40 | RBAC (roles, assignments, permissions in JWT), audit logging (25+ event types, query API), OpenTelemetry tracing middleware, mTLS client cert verification |
| SDK | Go SDK (pkg/authcore) | Done | ~5 | ~10 | Embeddable AuthCore as library: Register, Login, IssueTokens, VerifyJWT, MountRoutes, RequireJWT middleware |

---

## All Endpoints (35+ including RBAC/Audit)

| # | Method | Route | Module | Auth | Response |
|---|--------|-------|--------|------|----------|
| 1 | GET | `/.well-known/openid-configuration` | 2 | Tenant | WriteRaw |
| 2 | GET | `/jwks` | 2 | Tenant | WriteRaw |
| 3 | GET | `/authorize` | 3 | Tenant + Session/X-Subject | 302 redirect |
| 4 | GET | `/authorize?provider=...` | 6 | Tenant | 302 to provider |
| 5 | POST | `/token` | 3 | Tenant + Client | WriteRaw |
| 6 | POST | `/device/authorize` | 5 | Tenant | WriteRaw |
| 7 | POST | `/revoke` | 5 | Tenant | 200 OK |
| 8 | POST | `/introspect` | 5 | Tenant | WriteRaw |
| 9 | GET | `/callback` | 6 | None (state has tenant) | 302 redirect |
| 10 | POST | `/mfa/totp/enroll` | 7a | None | WriteJSON |
| 11 | POST | `/mfa/totp/confirm` | 7a | None | WriteJSON |
| 12 | POST | `/mfa/verify` | 7a | None | WriteJSON |
| 13 | POST | `/register` | 8 | Tenant | WriteJSON (201) |
| 14 | POST | `/login` | 8 | Tenant | WriteJSON |
| 15 | POST | `/logout` | 8 | Tenant | WriteJSON |
| 16 | GET | `/userinfo` | 8 | Tenant + Session | WriteRaw |
| 17 | POST | `/otp/request` | 9 | Tenant | WriteJSON |
| 18 | POST | `/otp/verify` | 9 | Tenant | WriteJSON |
| 19 | POST | `/password/reset` | 9 | Tenant | WriteJSON |
| 20 | POST/GET | `/tenants` | 4 | Admin API key | WriteJSON |
| 21 | GET/PUT/DELETE | `/tenants/{id}` | 4 | Admin API key | WriteJSON |
| 22 | POST/GET | `/tenants/{id}/clients` | 5 | Admin API key | WriteJSON |
| 23 | GET/PUT/DELETE | `/tenants/{id}/clients/{cid}` | 5 | Admin API key | WriteJSON |
| 24 | POST/GET | `/tenants/{id}/providers` | 6 | Admin API key | WriteJSON |
| 25 | GET/DELETE | `/tenants/{id}/providers/{pid}` | 6 | Admin API key | WriteJSON |
| 26 | POST/GET | `/tenants/{id}/roles` | 10 | Admin API key | WriteJSON |
| 27 | GET/PUT/DELETE | `/tenants/{id}/roles/{rid}` | 10 | Admin API key | WriteJSON |
| 28 | POST | `/tenants/{id}/users/{uid}/roles/{rid}` | 10 | Admin API key | WriteJSON |
| 29 | DELETE | `/tenants/{id}/users/{uid}/roles/{rid}` | 10 | Admin API key | WriteJSON |
| 30 | GET | `/tenants/{id}/users/{uid}/roles` | 10 | Admin API key | WriteJSON |
| 31 | GET | `/tenants/{id}/users/{uid}/permissions` | 10 | Admin API key | WriteJSON |
| 32 | GET | `/tenants/{id}/audit` | 10 | Admin API key | WriteJSON |
| — | GET | `/health` | 0 | None | WriteRaw |

---

## Features Added Beyond Original Spec

| Feature | Module | Requested By | Status |
|---------|--------|-------------|--------|
| All 5 OAuth grant types (client_creds, refresh, device, password) | 5 | User: "all grant types" | Done |
| Social login (6 provider types) | 6 | User: "I need Social Login" | Done |
| TOTP MFA | 7a | User: "I need MFA/2FA" | Done |
| User authentication (register/login/sessions) | 8 | User: "What about authenticate?" | Done |
| CORS middleware | PH | Identified as production blocker | Done |
| Client enforcement on OAuth flows | PH | Identified as security gap | Done |
| Admin API authentication | PH | Identified as security gap | Done |
| Postgres wiring + auto-migrations | PH | Identified as production blocker | Done |
| OTP signin (email-based) | 9 | User: "signin with OTP" | Done |
| Phone number support | 9 | User: "Signup with phone" | Done |
| SMS OTP (Twilio) | 9 | User: "Need phone + SMS OTP" | Done |
| Password reset via OTP | 9 | User: "Forgot password" | Done |
| SMTP email adapter | 9 | User: "Console + SMTP both" | Done |
| Keycloak/IdentityServer/Cognito comparison | docs | User: "comparison with other servers" | Done |
| SAML/LDAP/Admin UI analysis | docs | User: "is it possible to implement?" | Done |
| Full project documentation | docs | User: "document this" | Done |
| Implementation tracker | docs | User: "save this as a document" | Done |
| Postgres repos (5 remaining) | GTM | User: "Yes" (go-to-market) | Done |
| Redis repos (6 ephemeral stores) | GTM | User: "Yes" (go-to-market) | Done |
| Coverage restoration to 85% | GTM | User: "why coverage changed from 85 to 82?" | Done |
| In-memory repos moved to cache/ | Refactor | Needed for proper test coverage | Done |
| RBAC (roles + permissions in JWT) | 10 | User: "can I integrate RBAC for authorization" | Done |
| Audit logging (25+ event types) | 10 | Production requirement | Done |
| OpenTelemetry tracing middleware | 10 | User: "RBAC, Audit logging, OpenTelemetry tracing, mTLS" | Done |
| mTLS for M2M communication | 10 | User: "mTLS for M2M" | Done |
| Go SDK (embeddable library) | SDK | User: "can it be an SDK?" | Done |
| Java SDK (authcore-java-sdk) | SDK | User: "this should be for java spring boot, .net also right?" | Done |
| .NET SDK (authcore-dotnet-sdk) | SDK | User: "Yes all" | Done |
| Node.js SDK (authcore-js) | SDK | User: "Yes all" | Done |
| Python SDK (authcore-python) | SDK | User: "Yes all" | Done |
| Spring Boot test client | Test | User: "create a client in java springboot for testing" | Done |

---

## Pending Items

### Critical — Blocks Production

| # | Item | Effort | Description |
|---|------|--------|-------------|
| ~~1~~ | ~~Remaining Postgres repos~~ | ~~Medium~~ | **Done** — client, user, refresh, provider, external identity repos |
| ~~2~~ | ~~Redis for ephemeral stores~~ | ~~Medium~~ | **Done** — session, auth code, device code, blacklist, state, OTP repos via Redis |
| ~~3~~ | ~~Scope validation enforcement~~ | ~~Small~~ | **Done** — /authorize + /token validate scopes against client's allowed_scopes |
| ~~4~~ | ~~MFA enforcement in /authorize~~ | ~~Small~~ | **Done** — MFAPolicy on Tenant, /authorize returns challenge when MFA required + user enrolled |
| ~~5~~ | ~~E2E tests~~ | ~~Medium~~ | **Done** — golden path (register→login→authorize→token→JWKS→userinfo), scope validation, client enforcement. Docker + in-memory variants |

### High Priority

| # | Item | Effort |
|---|------|--------|
| ~~6~~ | ~~Rate limiting~~ | ~~Medium~~ | **Done** — sliding window per IP, 20 req/min on /login, /token, /otp/verify, /mfa/verify |
| ~~7~~ | ~~Encryption at rest~~ | ~~Medium~~ | **Done** — AES-256-GCM encryptor with AUTHCORE_ENCRYPTION_KEY config |
| ~~8~~ | ~~Email verification on register~~ | ~~Small~~ | **Done** — auto-sends verification OTP on register, VerificationSent in response |
| 9 | SAML 2.0 | Large |

### Medium Priority

| # | Item | Effort |
|---|------|--------|
| 10 | WebAuthn/FIDO2 (Module 7b) | Large |
| 11 | ID token decode from social login providers | Small |
| 12 | Apple JWT client_secret generation | Medium |
| 13 | Refresh token cleanup (expired accumulation) | Small |
| 14 | Key auto-rotation | Small |
| 15 | Admin CLI tool | Small |
| 16 | SQL Server repository implementations | Medium |

### Low Priority

| # | Item | Effort |
|---|------|--------|
| ~~17~~ | ~~mTLS~~ | ~~Medium~~ | **Done** — mTLS middleware for client certificate verification |
| ~~18~~ | ~~OpenTelemetry traces~~ | ~~Medium~~ | **Done** — Tracing middleware with distributed trace context |
| 19 | LDAP integration | Medium |
| 20 | Admin UI (separate SPA) | Large |
| 21 | JWE (encrypted tokens) | Medium |
| ~~22~~ | ~~Audit logging~~ | ~~Medium~~ | **Done** — 25+ event types, audit domain + repository + query API |
| 23 | Security audit | External |

---

## Standards Compliance

| Standard | Status |
|----------|--------|
| OAuth 2.0 (RFC 6749) | Done — all 5 grant types |
| PKCE (RFC 7636) | Done — S256 |
| OIDC Discovery (RFC 8414) | Done |
| JWKS (RFC 7517) | Done |
| JWT (RFC 7519) | Done — RS256, ES256 |
| Token Revocation (RFC 7009) | Done |
| Token Introspection (RFC 7662) | Done |
| Device Authorization (RFC 8628) | Done |
| TOTP (RFC 6238) | Done |
| HOTP (RFC 4226) | Done — base for TOTP |
| OIDC UserInfo (RFC 5765) | Done |
| SAML 2.0 | Not done |
| WebAuthn / FIDO2 | Not done |
| JWE (RFC 7516) | Not done |
| SCIM (RFC 7644) | Not done |

---

## Configuration Reference

| Variable | Default | Added In |
|----------|---------|----------|
| `AUTHCORE_ENV` | `local` | Module 0 |
| `AUTHCORE_HTTP_PORT` | `8080` | Module 0 |
| `AUTHCORE_DATABASE_DSN` | `postgres://...` | Module 0 |
| `AUTHCORE_DATABASE_DRIVER` | `postgres` | Module 0 |
| `AUTHCORE_REDIS_URL` | `redis://localhost:6379` | Module 0 |
| `AUTHCORE_LOG_LEVEL` | (auto) | Module 1 |
| `AUTHCORE_TENANT_MODE` | `header` | Module 4 |
| `AUTHCORE_ISSUER` | `http://localhost:8080` | Module 4 |
| `AUTHCORE_CORS_ORIGINS` | `*` | Production Hardening |
| `AUTHCORE_ADMIN_API_KEY` | (empty = dev mode) | Production Hardening |
| `AUTHCORE_SMTP_HOST` | (empty) | Module 9 |
| `AUTHCORE_SMTP_PORT` | `587` | Module 9 |
| `AUTHCORE_SMTP_USERNAME` | (empty) | Module 9 |
| `AUTHCORE_SMTP_PASSWORD` | (empty) | Module 9 |
| `AUTHCORE_SMTP_FROM` | `noreply@authcore.local` | Module 9 |
| `AUTHCORE_SMS_PROVIDER` | (empty) | Module 9 |
| `AUTHCORE_SMS_ACCOUNT_ID` | (empty) | Module 9 |
| `AUTHCORE_SMS_AUTH_TOKEN` | (empty) | Module 9 |
| `AUTHCORE_SMS_FROM_NUMBER` | (empty) | Module 9 |
| `AUTHCORE_ENCRYPTION_KEY` | (empty) | Production Hardening |

---

## Database Migrations

| # | File | Table | Module |
|---|------|-------|--------|
| 001 | `001_create_jwk_pairs.sql` | jwk_pairs | 2 |
| 002 | `002_create_tenants.sql` | tenants | 4 |
| 003 | `003_create_clients.sql` | clients | PH |
| 004 | `004_create_users.sql` | users | PH |
| 005 | `005_create_refresh_tokens.sql` | refresh_tokens | PH |
| 006 | `006_create_identity_providers.sql` | identity_providers | PH |
| 007 | `007_create_external_identities.sql` | external_identities | PH |
| 008 | `008_create_mfa.sql` | totp_enrollments, mfa_challenges | PH |
| 009 | `009_add_user_phone.sql` | users (ALTER) | 9 |
| 010 | `010_create_rbac.sql` | roles, user_role_assignments | 10 |
| 011 | `011_create_audit_events.sql` | audit_events | 10 |

---

## Changelog

| Date | Change |
|------|--------|
| 2026-03-26 | Modules 0-7a completed (OIDC, OAuth, Social Login, MFA TOTP) |
| 2026-03-27 | Module 8: User Authentication (register, login, sessions, /userinfo) |
| 2026-03-27 | Production Hardening: CORS, client enforcement, admin auth, Postgres wiring |
| 2026-03-27 | Module 9: OTP authentication, phone support, password reset, SMTP + Twilio |
| 2026-03-27 | Documentation: README, COMPARISON, ROADMAP, IMPLEMENTATION_TRACKER |
| 2026-03-27 | Postgres repos: client, user, refresh_token, provider, external_identity — 7 of 8 persistent tables now have Go repos |
| 2026-03-27 | Redis repos: session, auth_code, device_code, blacklist, state, OTP — 6 ephemeral stores now Redis-backed |
| 2026-03-27 | Coverage fix: moved in-memory repos from cmd/ to cache/, added 50+ tests, restored 85% threshold |
| 2026-03-27 | Architecture: Postgres for persistent data, Redis for ephemeral data, in-memory fallback if Redis unavailable |
| 2026-03-27 | Scope validation: /authorize + /token enforce scopes against client's allowed_scopes, ValidateScopes on Client entity |
| 2026-03-27 | MFA enforcement: MFAPolicy on Tenant, /authorize intercepts when MFA required + user has TOTP enrolled, returns challenge JSON |
| 2026-03-27 | E2E tests: golden path (3 tests), Docker testcontainers variant + in-memory variant, scope + client enforcement tests |
| 2026-03-28 | Rate limiting: sliding window per IP on /login, /token, /otp/verify, /mfa/verify (20 req/min) |
| 2026-03-28 | Encryption at rest: AES-256-GCM encryptor, AUTHCORE_ENCRYPTION_KEY config, EncryptIfConfigured/DecryptIfConfigured helpers |
| 2026-03-28 | Email verification: auto-send OTP on register, VerificationSent field in register response |
| 2026-03-28 | **All 8 go-to-market items complete** |
| 2026-03-28 | RBAC: roles + permissions per tenant, wildcard matching, JWT claims enrichment, full CRUD API |
| 2026-03-28 | Audit logging: 25+ event types, domain + in-memory repository + query API with filters |
| 2026-03-28 | OpenTelemetry: tracing middleware with distributed trace context injection |
| 2026-03-28 | mTLS: mutual TLS middleware for M2M client certificate verification |
| 2026-03-28 | Go SDK: embeddable AuthCore as library (pkg/authcore), Register/Login/IssueTokens/VerifyJWT/MountRoutes |
| 2026-03-28 | Wrapper SDKs: Java, .NET, Node.js, Python — typed clients in separate repositories |
| 2026-03-28 | Spring Boot test client: OAuth2 resource server with JWT verification via JWKS |
| 2026-03-26 | Documentation update: all 13 docs updated to reflect RBAC, audit, OTel, mTLS, SDKs |
