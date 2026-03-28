# AuthCore — Headless Identity & Access Management Engine

AuthCore is a technology-agnostic, headless IAM engine built in Go. It provides centralized authentication and authorization via standard OIDC/OAuth 2.0 protocols, allowing any frontend (React, Vue, Mobile, CLI) and any backend (Node.js, Python, Java, .NET) to integrate using standard libraries.

## Table of Contents

- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [API Reference](#api-reference)
- [Authentication Flows](#authentication-flows)
- [User Authentication](#user-authentication)
- [Multi-Tenancy](#multi-tenancy)
- [Social Login](#social-login)
- [MFA / Two-Factor Authentication](#mfa--two-factor-authentication)
- [Client Registry](#client-registry)
- [Token Lifecycle](#token-lifecycle)
- [Production Hardening](#production-hardening)
- [Configuration](#configuration)
- [Project Structure](#project-structure)
- [Comparison with Alternatives](#comparison-with-alternatives)
- [Development](#development)
- [Production Readiness](#production-readiness)

---

## Architecture

AuthCore follows **Hexagonal Architecture** (Ports & Adapters):

```
┌──────────────────────────────────────────────────────────────┐
│                       HTTP Layer                              │
│  Handlers: authorize, token, jwks, discovery, mfa, user,     │
│            client, provider, device, revoke, introspect,      │
│            rbac, audit, social                                │
│  Middleware: CORS, tenant resolution, admin auth,             │
│             rate limiter, tracing (OTel), mTLS                │
├──────────────────────────────────────────────────────────────┤
│                    Application Layer                          │
│  Services: auth, client, discovery, jwks, mfa, rbac,         │
│            provider, social, tenant, user, audit              │
├──────────────────────────────────────────────────────────────┤
│                      Domain Layer                             │
│  Entities: User, Session, Tenant, Client, KeyPair, Token,    │
│            Claims, IdentityProvider, ExternalIdentity,        │
│            TOTPEnrollment, MFAChallenge, RefreshToken,        │
│            DeviceCode, AuthorizationCode, OTP, Role, AuditEvent│
│  Ports: Repository, Generator, Converter, Signer,            │
│         OAuthClient, UserValidator, PasswordHasher,           │
│         SecretHasher, TokenBlacklist                          │
├──────────────────────────────────────────────────────────────┤
│                     Adapter Layer                             │
│  Crypto: RSA/EC keygen, JWT signing, bcrypt, AES-256-GCM     │
│  Cache: 19 in-memory repos (dev/fallback)                    │
│  Postgres: 7 repos + auto-migration runner (11 SQL files)    │
│  Redis: 7 repos (session, code, device, blacklist, state, OTP)│
│  Email: SMTP + console senders                               │
│  SMS: Twilio + console senders                               │
│  OAuth: outbound HTTP client for social login                │
└──────────────────────────────────────────────────────────────┘
```

### Key Design Principles

- **Headless**: No HTML/CSS. Pure API and protocol endpoints.
- **No panics**: All methods return `Result[T]` or `(T, error)`. Graceful failure only.
- **Polyglot-ready**: Standard JWT claims, OIDC discovery — any library can integrate.
- **Multi-tenant native**: Per-tenant key isolation, clients, providers, MFA policy.
- **Minimal dependencies**: Go stdlib for crypto, HTTP, JSON. Only 6 external deps.

---

## Quick Start

### Prerequisites

- Go 1.25+
- Docker (for Postgres + Redis in production)

### Build & Run

```bash
# Build
make build

# Run in local mode (in-memory storage)
./bin/authcore

# Run in production mode (Postgres required)
AUTHCORE_ENV=production \
AUTHCORE_DATABASE_DSN="postgres://user:pass@localhost:5432/authcore?sslmode=disable" \
AUTHCORE_ADMIN_API_KEY="your-secret-key" \
./bin/authcore
```

### Docker

```bash
# Build image (~15MB)
make docker

# Run with docker-compose (Postgres + Redis)
docker-compose up -d
```

### Verify

```bash
# Health check
curl http://localhost:8080/health

# OIDC Discovery (requires tenant)
curl -H "X-Tenant-ID: default" http://localhost:8080/.well-known/openid-configuration
```

---

## API Reference

### OIDC / OAuth 2.0 Endpoints

All OIDC/OAuth endpoints require tenant resolution (via `X-Tenant-ID` header or domain).

| Method | Endpoint | Description | Response |
|--------|----------|-------------|----------|
| `GET` | `/.well-known/openid-configuration` | OIDC Discovery (RFC 8414) | Raw JSON |
| `GET` | `/jwks` | JSON Web Key Set (RFC 7517) | Raw JSON |
| `GET` | `/authorize` | Authorization endpoint | 302 redirect |
| `GET` | `/authorize?provider=google` | Social login redirect | 302 to provider |
| `POST` | `/token` | Token exchange (all grant types) | Raw JSON |
| `POST` | `/device/authorize` | Device authorization (RFC 8628) | Raw JSON |
| `POST` | `/revoke` | Token revocation (RFC 7009) | 200 OK |
| `POST` | `/introspect` | Token introspection (RFC 7662) | Raw JSON |
| `GET` | `/callback` | Social login callback | 302 redirect |

### User Authentication Endpoints

| Method | Endpoint | Description | Response |
|--------|----------|-------------|----------|
| `POST` | `/register` | User registration | JSON envelope (201) |
| `POST` | `/login` | User login (returns session token) | JSON envelope (200) |
| `POST` | `/logout` | Session invalidation | JSON envelope (200) |
| `GET` | `/userinfo` | OIDC UserInfo (RFC 5765) | Raw JSON |

### OTP Endpoints

| Method | Endpoint | Description | Response |
|--------|----------|-------------|----------|
| `POST` | `/otp/request` | Request OTP (email or SMS, purpose: login/verify/reset) | JSON envelope |
| `POST` | `/otp/verify` | Verify OTP code (passwordless login or email verification) | JSON envelope |
| `POST` | `/password/reset` | Reset password with OTP code | JSON envelope |

### MFA Endpoints

| Method | Endpoint | Description | Response |
|--------|----------|-------------|----------|
| `POST` | `/mfa/totp/enroll` | Enroll TOTP (returns secret + otpauth URI) | JSON envelope |
| `POST` | `/mfa/totp/confirm` | Confirm enrollment with first code | JSON envelope |
| `POST` | `/mfa/verify` | Verify MFA challenge (completes auth) | JSON envelope |

### Management API

Management endpoints require API key authentication (`X-API-Key` or `Authorization: Bearer`). They use the `{data: ...}` JSON envelope.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/tenants` | Create tenant |
| `GET` | `/tenants` | List tenants |
| `GET` | `/tenants/{id}` | Get tenant |
| `PUT` | `/tenants/{id}` | Update tenant |
| `DELETE` | `/tenants/{id}` | Soft-delete tenant |
| `POST` | `/tenants/{id}/clients` | Register OAuth client |
| `GET` | `/tenants/{id}/clients` | List clients |
| `GET` | `/tenants/{id}/clients/{cid}` | Get client |
| `PUT` | `/tenants/{id}/clients/{cid}` | Update client |
| `DELETE` | `/tenants/{id}/clients/{cid}` | Delete client |
| `POST` | `/tenants/{id}/providers` | Register identity provider |
| `GET` | `/tenants/{id}/providers` | List providers |
| `GET` | `/tenants/{id}/providers/{pid}` | Get provider |
| `DELETE` | `/tenants/{id}/providers/{pid}` | Delete provider |
| `POST` | `/tenants/{id}/roles` | Create RBAC role |
| `GET` | `/tenants/{id}/roles` | List roles |
| `GET` | `/tenants/{id}/roles/{rid}` | Get role details |
| `PUT` | `/tenants/{id}/roles/{rid}` | Update role permissions |
| `DELETE` | `/tenants/{id}/roles/{rid}` | Delete role |
| `POST` | `/tenants/{id}/users/{uid}/roles/{rid}` | Assign role to user |
| `DELETE` | `/tenants/{id}/users/{uid}/roles/{rid}` | Revoke role from user |
| `GET` | `/tenants/{id}/users/{uid}/roles` | Get user's assigned roles |
| `GET` | `/tenants/{id}/users/{uid}/permissions` | Get user's flattened permissions |
| `GET` | `/tenants/{id}/audit` | Query audit logs (filter by actor, action, resource) |
| `GET` | `/health` | Health check (no auth required) |

---

## Authentication Flows

### Authorization Code + PKCE (Primary Flow)

```
React SPA                    AuthCore                     Backend API
   │                            │                            │
   │ 1. Generate PKCE pair      │                            │
   │    verifier = random(43)   │                            │
   │    challenge = SHA256(v)   │                            │
   │                            │                            │
   │ 2. GET /authorize          │                            │
   │    ?response_type=code     │                            │
   │    &client_id=my-app       │                            │
   │    &redirect_uri=...       │                            │
   │    &code_challenge=...     │                            │
   │    &code_challenge_method=S256                          │
   │ ────────────────────────►  │                            │
   │                            │                            │
   │ 3. 302 redirect            │                            │
   │    ?code=AUTH_CODE          │                            │
   │ ◄────────────────────────  │                            │
   │                            │                            │
   │ 4. POST /token             │                            │
   │    grant_type=             │                            │
   │      authorization_code   │                            │
   │    &code=AUTH_CODE          │                            │
   │    &code_verifier=...      │                            │
   │ ────────────────────────►  │                            │
   │                            │                            │
   │ 5. {access_token,          │                            │
   │     id_token,              │                            │
   │     refresh_token}         │                            │
   │ ◄────────────────────────  │                            │
   │                            │                            │
   │ 6. API call with Bearer    │                            │
   │ ───────────────────────────────────────────────────────► │
   │                            │ 7. Verify JWT via /jwks    │
   │                            │ ◄────────────────────────  │
   │ 8. Response                │                            │
   │ ◄─────────────────────────────────────────────────────── │
```

### All Supported Grant Types

| Grant Type | Use Case | Example |
|-----------|----------|---------|
| `authorization_code` | Web/mobile apps | SPA with PKCE |
| `client_credentials` | M2M server-to-server | Microservice auth |
| `refresh_token` | Long-lived sessions | Token rotation |
| `urn:ietf:params:oauth:grant-type:device_code` | TV/CLI/IoT | Device without browser |
| `password` | Legacy systems | Deprecated but supported |

### Client Credentials (M2M)

```bash
curl -X POST http://localhost:8080/token \
  -H "X-Tenant-ID: tenant-1" \
  -d "grant_type=client_credentials&client_id=server-app&client_secret=SECRET&scope=api:read"
```

### Refresh Token (with rotation + replay detection)

```bash
curl -X POST http://localhost:8080/token \
  -H "X-Tenant-ID: tenant-1" \
  -d "grant_type=refresh_token&refresh_token=REFRESH_TOKEN&client_id=my-app"
```

Each refresh issues a new token. If a rotated token is reused, the entire token family is revoked (replay detection).

### Device Code (RFC 8628)

```bash
# Step 1: Initiate
curl -X POST http://localhost:8080/device/authorize \
  -H "X-Tenant-ID: tenant-1" \
  -d "client_id=tv-app&scope=openid"

# Step 2: Device polls /token with grant_type=urn:ietf:params:oauth:grant-type:device_code
# Returns "authorization_pending" until user authorizes
```

---

## User Authentication

AuthCore includes built-in user management with registration, login, sessions, and OIDC UserInfo.

### Registration

```bash
curl -X POST http://localhost:8080/register \
  -H "X-Tenant-ID: tenant-1" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "secret123", "name": "Test User"}'

# Response: {"data": {"user_id": "...", "email": "user@example.com"}}
```

### Login

```bash
curl -X POST http://localhost:8080/login \
  -H "X-Tenant-ID: tenant-1" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "secret123"}'

# Response: {"data": {"session_token": "...", "expires_in": 86400}}
```

### Using Sessions with /authorize

```bash
# Session-based authorization (no X-Subject needed)
curl -H "Authorization: Bearer SESSION_TOKEN" \
     "http://localhost:8080/authorize?response_type=code&client_id=my-app&redirect_uri=..."

# Falls back to X-Subject header for headless integrations
# Returns 401 {"error": "login_required"} if no auth present
```

### Subject Resolution Order

1. Session token (`Authorization: Bearer` or `X-Session-Token` header)
2. `X-Subject` header (headless integration fallback)
3. 401 `login_required` (OIDC-compliant error)

### Password Hashing

- Algorithm: bcrypt (cost 12)
- Email normalization: lowercase + trim
- Per-tenant email uniqueness
- No user enumeration: login returns "invalid credentials" for both wrong email and wrong password

---

## Multi-Tenancy

### Tenant Resolution Modes

| Mode | Config | How |
|------|--------|-----|
| Header (default) | `AUTHCORE_TENANT_MODE=header` | `X-Tenant-ID: tenant-1` header |
| Domain | `AUTHCORE_TENANT_MODE=domain` | Request hostname → tenant lookup |

### Tenant Isolation

Each tenant has isolated:
- Signing keys (RSA-2048 or EC P-256)
- Client registry
- Identity providers (social login)
- User store
- MFA policy

### Tenant Management

```bash
# Create tenant (requires admin API key)
curl -X POST http://localhost:8080/tenants \
  -H "X-API-Key: your-admin-key" \
  -H "Content-Type: application/json" \
  -d '{"id": "tenant-1", "domain": "tenant1.example.com", "issuer": "https://tenant1.example.com", "algorithm": "RS256"}'
```

---

## Social Login

AuthCore acts as an OAuth client to external providers. No HTML generated — only 302 redirects.

### Supported Providers

| Provider | Type | Notes |
|----------|------|-------|
| Google | OIDC | Auto-discovery |
| GitHub | OAuth 2.0 | Numeric ID, separate email endpoint |
| Microsoft | OIDC | Azure AD tenant configurable |
| Apple | OIDC | JWT client_secret (partial) |
| Generic OIDC | OIDC | Any provider with discovery URL |
| Generic OAuth 2.0 | OAuth 2.0 | Configurable auth/token/userinfo URLs |

### Setup

```bash
# Register Google provider for a tenant
curl -X POST http://localhost:8080/tenants/tenant-1/providers \
  -H "X-API-Key: your-admin-key" \
  -H "Content-Type: application/json" \
  -d '{"provider_type": "google", "client_id": "GOOGLE_CLIENT_ID", "client_secret": "GOOGLE_SECRET", "scopes": ["openid", "email", "profile"]}'
```

### Flow

```
GET /authorize?provider=google&client_id=my-app&redirect_uri=https://myapp.com/cb&...
  → 302 to Google consent
  → Google redirects to /callback?code=...&state=...
  → AuthCore exchanges code, links identity, issues AuthCore auth code
  → 302 to https://myapp.com/cb?code=AUTHCORE_CODE&state=...
  → POST /token to exchange for AuthCore tokens
```

### Identity Linking

- First login: creates `ExternalIdentity` mapping (Google `sub` → internal UUID)
- Subsequent logins: finds existing mapping, updates profile
- Explicit linking: pass `X-Subject` header to link to existing user

---

## MFA / Two-Factor Authentication

### TOTP Enrollment

```bash
# Step 1: Enroll
curl -X POST http://localhost:8080/mfa/totp/enroll \
  -H "Content-Type: application/json" \
  -d '{"subject": "user-123"}'
# Response: {"data": {"secret": "JBSWY3DPEHPK3PXP", "otpauth_uri": "otpauth://totp/..."}}

# Step 2: User scans QR code with Google Authenticator / Authy

# Step 3: Confirm with first code
curl -X POST http://localhost:8080/mfa/totp/confirm \
  -H "Content-Type: application/json" \
  -d '{"subject": "user-123", "code": "123456"}'
```

### TOTP Implementation

- Algorithm: HMAC-SHA1 (RFC 6238)
- Digits: 6, Period: 30 seconds, Window: ±1 step
- Secret: 20 random bytes, base32 encoded

---

## Client Registry

### Client Types

| Type | Secret | Use Case |
|------|--------|----------|
| `public` | No | SPAs, mobile apps |
| `confidential` | bcrypt hashed (cost 12) | Server-side apps, M2M |

### Client Enforcement

- `/authorize` validates `client_id` exists and `redirect_uri` matches whitelist
- `/token` authenticates confidential clients (client_secret verification) and checks allowed `grant_type`
- Redirect URIs require HTTPS (except `localhost`/`127.0.0.1` for development)

### Registration

```bash
curl -X POST http://localhost:8080/tenants/tenant-1/clients \
  -H "X-API-Key: your-admin-key" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "My SPA",
    "client_type": "public",
    "redirect_uris": ["https://myapp.com/callback"],
    "allowed_scopes": ["openid", "profile", "email"],
    "grant_types": ["authorization_code", "refresh_token"]
  }'
# Response includes client_id (and client_secret for confidential clients — shown once)
```

---

## Token Lifecycle

| Token | Format | Lifetime | Storage |
|-------|--------|----------|---------|
| Access Token | JWT (RS256/ES256) | 1 hour | Stateless |
| ID Token | JWT (RS256/ES256) | 1 hour | Stateless |
| Refresh Token | Opaque | 30 days | Server-side |
| Authorization Code | Opaque | 10 minutes | Server-side |
| Device Code | Opaque | 15 minutes | Server-side |
| Session Token | Opaque | 24 hours | Server-side |

### Revocation (RFC 7009)

```bash
curl -X POST http://localhost:8080/revoke \
  -H "X-Tenant-ID: tenant-1" \
  -d "token=REFRESH_TOKEN&token_type_hint=refresh_token"
```

### Introspection (RFC 7662)

```bash
curl -X POST http://localhost:8080/introspect \
  -H "X-Tenant-ID: tenant-1" \
  -d "token=ACCESS_TOKEN"
# Response: {"active": true, "sub": "user-123", "client_id": "my-app", "exp": 1700000000}
```

---

## Production Hardening

### CORS

Configurable via `AUTHCORE_CORS_ORIGINS`. Supports:
- `*` (allow all — development)
- Comma-separated origins: `https://myapp.com, https://admin.myapp.com`
- Preflight (`OPTIONS`) handled automatically
- Custom headers allowed: `Authorization`, `X-Tenant-ID`, `X-Subject`, `X-Session-Token`

### Admin API Authentication

Management endpoints (`/tenants`, `/clients`, `/providers`) are protected by API key.

```bash
# Via header
curl -H "X-API-Key: your-secret-key" http://localhost:8080/tenants

# Via Bearer
curl -H "Authorization: Bearer your-secret-key" http://localhost:8080/tenants
```

Set via `AUTHCORE_ADMIN_API_KEY`. Empty = no auth (development mode only).

### Client Enforcement

- `/authorize`: validates `client_id` exists, `redirect_uri` matches registered whitelist
- `/token`: authenticates confidential clients via `client_secret`, verifies `grant_type` is allowed for the client
- Constant-time secret comparison via bcrypt

### Database

| Environment | Storage | Migrations |
|-------------|---------|------------|
| `local` | In-memory (data lost on restart) | None |
| `staging` / `production` | Postgres (persistent) | Auto-run on startup |

8 migration files covering: jwk_pairs, tenants, clients, users, refresh_tokens, identity_providers, external_identities, mfa (totp_enrollments + mfa_challenges).

Migration runner uses Go's `embed.FS` with a `schema_migrations` tracking table — each migration runs exactly once.

---

## Configuration

All configuration via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTHCORE_ENV` | `local` | Environment: `local`, `staging`, `production` |
| `AUTHCORE_HTTP_PORT` | `8080` | HTTP server port |
| `AUTHCORE_DATABASE_DSN` | `postgres://authcore:authcore_dev@localhost:5432/authcore?sslmode=disable` | Database connection |
| `AUTHCORE_DATABASE_DRIVER` | `postgres` | `postgres` or `sqlserver` |
| `AUTHCORE_REDIS_URL` | `redis://localhost:6379` | Redis connection |
| `AUTHCORE_TENANT_MODE` | `header` | `header` or `domain` |
| `AUTHCORE_ISSUER` | `http://localhost:8080` | JWT issuer URL |
| `AUTHCORE_CORS_ORIGINS` | `*` | Comma-separated allowed origins |
| `AUTHCORE_ADMIN_API_KEY` | (empty) | API key for management endpoints |

### Logging

| Environment | Level | Format | Traces |
|-------------|-------|--------|--------|
| `local` | Debug | Text (human-readable) | No |
| `staging` | Info | JSON (structured) | Yes |
| `production` | Error | JSON (structured) | Yes |

---

## Project Structure

```
authcore/
├── cmd/authcore/              # Entry point, in-memory repos, server wiring
├── internal/
│   ├── adapter/               # Infrastructure adapters
│   │   ├── cache/             # In-memory repos (14 repos)
│   │   ├── crypto/            # Key generation, JWT signing, bcrypt, TOTP
│   │   ├── http/
│   │   │   ├── handler/       # 14 HTTP handlers
│   │   │   ├── middleware/    # CORS, tenant resolution, admin auth
│   │   │   └── oauth/        # Outbound OAuth client + provider configs
│   │   └── postgres/          # Postgres repos + migration runner + 8 SQL files
│   ├── application/           # Use cases (9 service packages)
│   │   ├── auth/              # Token exchange (5 grant types), revoke, introspect
│   │   ├── client/            # OAuth client CRUD + authentication
│   │   ├── discovery/         # OIDC discovery document
│   │   ├── jwks/              # JWK management
│   │   ├── mfa/               # TOTP enroll/confirm/verify, MFA challenges
│   │   ├── provider/          # Identity provider CRUD
│   │   ├── social/            # Social login orchestration
│   │   ├── tenant/            # Tenant CRUD + resolution
│   │   └── user/              # Registration, login, sessions, UserInfo
│   ├── config/                # Environment-based configuration
│   └── domain/                # Pure business logic (8 domain packages)
│       ├── client/            # Client entity, validation, ports
│       ├── identity/          # IdentityProvider, ExternalIdentity, OAuthState
│       ├── jwk/               # KeyPair, PublicJWK, Set, ports
│       ├── mfa/               # TOTP, MFAChallenge, MFAPolicy
│       ├── oidc/              # DiscoveryDocument
│       ├── shared/            # Tenant context helpers
│       ├── tenant/            # Tenant entity, ports
│       ├── token/             # Claims, AuthCode, RefreshToken, DeviceCode, PKCE
│       └── user/              # User, Session, PasswordHasher
├── pkg/sdk/                   # Reusable SDK (errors, httputil, logger, database, health)
├── pkg/testutil/              # Test assertion helpers
├── docs/                      # This documentation
├── scripts/                   # Coverage enforcement
├── Dockerfile                 # Multi-stage build (~15MB image)
├── docker-compose.yml         # Postgres 16 + Redis 7
└── Makefile                   # Build, test, lint, coverage targets
```

### Stats

| Metric | Value |
|--------|-------|
| Go files | ~237 (source + test) |
| Test assertions | 720 |
| Line coverage | 85.0% (85% threshold) |
| HTTP endpoints | 35+ |
| Packages | 40 |
| External dependencies | 6 (env, testify, x/crypto, pgx, go-redis, testcontainers) |
| SQL migrations | 11 |
| Domain packages | 12 |
| Application services | 11 |

---

## Comparison with Alternatives

### Feature Matrix

| Feature | AuthCore | Keycloak | IdentityServer (Duende) | AWS Cognito |
|---------|---------|---------|------------------------|------------|
| **Language** | Go | Java | .NET | Managed |
| **Docker image** | ~15MB | ~500MB | N/A | N/A |
| **RAM** | <300MB | 512MB–2GB | 200–500MB | N/A |
| **License** | Private | Apache 2.0 | Commercial ($1,500+/yr) | Pay-per-MAU |
| **OIDC/OAuth 2.0** | All 5 grants | All + extensions | All | 3 grants |
| **PKCE** | S256 | S256 + plain | S256 + plain | S256 |
| **Refresh Rotation** | Yes (family tracking) | Yes | Yes | Yes |
| **Device Code** | Yes | Yes | Community | No |
| **Token Revocation** | Yes | Yes | Yes | Via API |
| **Token Introspection** | Yes | Yes | Yes | No |
| **SAML 2.0** | Not yet | Full | Community | Yes |
| **User Registration** | API only | UI + API | No (BYOU) | UI + API |
| **User Login** | API only | UI + API | No (BYOU) | UI + API |
| **Social Login** | 6 providers | 10+ providers | Via plugins | 4 providers |
| **TOTP MFA** | Yes | Yes | Via extensibility | Yes |
| **WebAuthn** | Not yet | Yes | Via extensibility | No |
| **Multi-Tenancy** | Native | Realms (heavy) | Manual | User Pools |
| **Admin UI** | No | Full console | No | AWS Console |
| **LDAP** | No | Yes | No | No |
| **CORS** | Configurable | Per-client | Per-client | Per-pool |
| **Client Enforcement** | Yes | Yes | Yes | Yes |
| **Admin API Auth** | API key | Built-in | N/A | IAM |
| **OTP (Email + SMS)** | Yes (SMTP, Twilio) | Yes | No | Yes (SES, SNS) |
| **RBAC** | Yes (roles + permissions in JWT) | Yes (roles, groups) | Claims-based | Groups only |
| **Audit Logging** | Yes (25+ events) | Yes | No | CloudTrail |
| **Encryption at Rest** | AES-256-GCM | Vault | DPAPI | KMS |
| **mTLS** | Yes | Yes | Yes | No |
| **OpenTelemetry** | Yes | Yes | Custom | X-Ray |
| **Rate Limiting** | Yes (20 req/min) | Yes | No | WAF |
| **Clustering** | Stateless | Infinispan | App-dependent | Managed |

### Cost Comparison (monthly infrastructure)

| Scale | AuthCore | Keycloak | IdentityServer | Cognito |
|-------|---------|---------|----------------|---------|
| 10K users | ~$20 | ~$50 | ~$30 + license | ~$55 |
| 100K users | ~$30 | ~$100 | ~$50 + license | ~$550 |
| 1M users | ~$50 | ~$200 | ~$100 + license | ~$5,500 |

### When to Use What

| Use Case | Best Choice |
|----------|-------------|
| Startup with custom UI, < 100K users | **AuthCore** |
| Enterprise with SAML, LDAP, admin UI | **Keycloak** |
| .NET shop, moderate scale | **IdentityServer** |
| AWS-native, zero ops | **Cognito** |
| Multi-tenant SaaS | **AuthCore** (lighter) or **Keycloak** (more features) |
| Sidecar/edge auth in K8s | **AuthCore** |
| Need production auth today | **Keycloak** or **Cognito** |

---

## Development

### Commands

```bash
make build           # Build binary to ./bin/authcore
make test-unit       # Run unit tests with coverage
make coverage-check  # Enforce 85% coverage threshold
make lint            # Run golangci-lint
make docker          # Build Docker image
make test-func       # Functional tests (requires Docker)
make test-e2e        # E2E tests (requires Docker)
make clean           # Remove build artifacts
```

### Quality Gates

- Line coverage >= 84%
- Exhaustive switch linter (branch coverage)
- Zero `panic()` in non-test code
- `make lint` passes with zero warnings

### Test Triad

- **85% Unit tests**: No external dependencies, mock all ports
- **10% Functional tests**: Real Postgres/Redis via testcontainers (`//go:build functional`)
- **5% E2E tests**: Full server with real infrastructure (`//go:build e2e`)

### Module Build Order (Completed)

1. Module 0: Scaffold & Quality Gates
2. Module 1: Foundation SDK (errors/Result[T], logger, httputil, database, health)
3. Module 2: OIDC Discovery & JWKS
4. Module 3: Token Issuance (Auth Code + PKCE)
5. Module 4: Multi-Tenancy
6. Module 5: Client Registry + All Grant Types + Token Lifecycle
7. Module 6: Social Login
8. Module 7a: TOTP MFA
9. Module 8: User Authentication
10. Production Hardening: CORS, Client Enforcement, Admin Auth, Postgres Wiring
11. Module 9: OTP + Phone + Password Reset
12. Module 10: RBAC + Audit Logging + OpenTelemetry + mTLS
13. Go SDK: Embeddable library (pkg/authcore)

---

## Production Readiness

### What's Ready

- Full OIDC/OAuth 2.0 protocol layer (5 grant types, discovery, JWKS)
- User authentication (register, login, sessions, UserInfo)
- OTP authentication (email + SMS, passwordless login, email verification)
- Password reset via OTP
- Multi-tenant architecture with per-tenant key isolation
- Social login with 6 provider types (Google, GitHub, Microsoft, Apple, generic OIDC/OAuth2)
- TOTP MFA with per-tenant policy enforcement
- RBAC (roles, permissions, wildcard matching, embedded in JWT claims)
- Client registry with scope enforcement on OAuth flows
- Token lifecycle (refresh rotation with replay detection, revocation, introspection)
- Rate limiting (20 req/min per IP sliding window on auth endpoints)
- Encryption at rest (AES-256-GCM with configurable key)
- Audit logging (25+ event types with query API)
- OpenTelemetry tracing middleware
- mTLS for M2M client certificate verification
- CORS middleware with configurable origins
- Admin API authentication (API key)
- Postgres (7 repos) + Redis (7 repos) + in-memory fallback
- Auto-migration runner (11 SQL files)
- Structured logging with environment-aware levels
- Docker deployment (~15MB image)
- E2E tests (Docker testcontainers + in-memory variants)
- Go SDK (embeddable library)
- Wrapper SDKs: Java, .NET, Node.js, Python

### What's Pending

| Priority | Item | Description |
|----------|------|-------------|
| High | SAML 2.0 | Enterprise SSO requirement (3-4 weeks) |
| High | WebAuthn/FIDO2 | Hardware key / biometric MFA (2 weeks) |
| Medium | Postgres RBAC repos | Currently in-memory; need Postgres persistence |
| Medium | Audit event auto-wiring | Wire audit events into all services automatically |
| Medium | Security headers | HSTS, CSP, X-Content-Type-Options |
| Low | LDAP | Direct AD bind (Azure AD OIDC covers most cases) |
| Low | Admin UI | Separate SPA recommended over built-in |
| Low | JWE (encrypted tokens) | RFC 7516 |
| External | Security audit | Penetration test ($5K-30K) |

### Standards Compliance

| Standard | Status |
|----------|--------|
| OAuth 2.0 (RFC 6749) | Implemented (all grant types) |
| PKCE (RFC 7636) | Implemented (S256) |
| OIDC Discovery (RFC 8414) | Implemented |
| JWKS (RFC 7517) | Implemented |
| Token Revocation (RFC 7009) | Implemented |
| Token Introspection (RFC 7662) | Implemented |
| Device Authorization (RFC 8628) | Implemented |
| TOTP (RFC 6238) | Implemented |
| HOTP (RFC 4226) | Implemented (base for TOTP) |
| JWT (RFC 7519) | Implemented (RS256, ES256) |
| OIDC UserInfo (RFC 5765) | Implemented |
| SAML 2.0 | Not implemented |
| WebAuthn / FIDO2 | Not implemented |
| JWE (RFC 7516) | Not implemented |

---

## License

Private project. Not licensed for public use.
