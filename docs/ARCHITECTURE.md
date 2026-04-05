# AuthPlex — Architecture

## System Architecture

```
                              ┌─────────────────────┐
                              │   Client Applications │
                              │  (React, Mobile, CLI) │
                              └──────────┬──────────┘
                                         │
                                    HTTPS/REST
                                         │
                              ┌──────────▼──────────┐
                              │     CORS Middleware   │
                              │   (configurable origins) │
                              └──────────┬──────────┘
                                         │
                    ┌────────────────────┬┴────────────────────┐
                    │                    │                      │
           ┌────────▼───────┐  ┌────────▼────────┐  ┌────────▼────────┐
           │  Tenant Router  │  │  Admin Auth      │  │  Rate Limiter   │
           │  (header/domain)│  │  (API key)       │  │  (20 req/min)   │
           └────────┬───────┘  └────────┬────────┘  └────────┬────────┘
                    │                    │                      │
    ┌───────────────┼────────────────────┼──────────────────────┤
    │               │                    │                      │
    ▼               ▼                    ▼                      ▼
┌─────────┐  ┌───────────┐  ┌──────────────┐  ┌──────────────────────┐
│  OIDC/  │  │   User    │  │  Management  │  │    MFA / OTP         │
│  OAuth  │  │   Auth    │  │     API      │  │                      │
│ Handlers│  │ Handlers  │  │  Handlers    │  │   Handlers           │
└────┬────┘  └─────┬─────┘  └──────┬───────┘  └──────────┬───────────┘
     │             │               │                      │
     └─────────────┴───────────────┴──────────────────────┘
                              │
                    ┌─────────▼──────────┐
                    │  Application Layer  │
                    │                     │
                    │  auth    client     │
                    │  user    tenant     │
                    │  jwks    discovery  │
                    │  mfa     social     │
                    │  rbac    audit      │
                    │  provider           │
                    └─────────┬──────────┘
                              │
                    ┌─────────▼──────────┐
                    │   Domain Layer      │
                    │   (Pure Logic)      │
                    │                     │
                    │  User, Session      │
                    │  Tenant, Client     │
                    │  Token, Claims      │
                    │  KeyPair, MFA       │
                    │  Identity, OTP      │
                    │  Role, AuditEvent   │
                    └─────────┬──────────┘
                              │
              ┌───────────────┼───────────────┐
              │               │               │
    ┌─────────▼─────┐  ┌─────▼──────┐  ┌─────▼──────┐
    │   Postgres     │  │   Redis    │  │   Crypto   │
    │   (Persistent) │  │  (Ephemeral)│  │  (Signing) │
    │                │  │            │  │            │
    │  tenants       │  │  sessions  │  │  RSA-2048  │
    │  users         │  │  auth codes│  │  EC P-256  │
    │  clients*      │  │  device    │  │  bcrypt    │
    │  jwk_pairs     │  │  blacklist │  │  AES-256   │
    │  refresh_tokens│  │  state     │  │  HMAC-SHA1 │
    │  providers     │  │  OTPs      │  │  JWT       │
    │  ext_identities│  │            │  │            │
    └───────────────┘  └────────────┘  └────────────┘
```

## Hexagonal Architecture Layers

### Layer 1: Domain (`internal/domain/`)

Pure business logic. No I/O, no imports from adapter or application layers.

| Package | Entities | Ports (Interfaces) |
|---------|----------|-------------------|
| `user` | User, Session | Repository, SessionRepository, PasswordHasher |
| `tenant` | Tenant, MFAPolicy, SigningConfig | Repository |
| `client` | Client | Repository, SecretHasher |
| `token` | Claims, AuthorizationCode, RefreshToken, DeviceCode | CodeRepository, RefreshTokenRepository, DeviceCodeRepository, TokenBlacklist, Signer, UserValidator |
| `jwk` | KeyPair, PublicJWK, Set | Repository, Generator, Converter |
| `identity` | IdentityProvider, ExternalIdentity, OAuthState | ProviderRepository, ExternalIdentityRepository, StateRepository, OAuthClient |
| `mfa` | TOTPEnrollment, MFAChallenge, MFAPolicy | TOTPRepository, ChallengeRepository |
| `otp` | OTP | Repository, EmailSender, SMSSender |
| `rbac` | Role, UserRoleAssignment | RoleRepository, AssignmentRepository |
| `audit` | Event | Repository |
| `oidc` | DiscoveryDocument | — |
| `shared` | — | TenantFromContext, WithTenant |

### Layer 2: Application (`internal/application/`)

Use cases. Orchestrates domain entities via port interfaces.

| Service | Key Methods |
|---------|------------|
| `auth` | Authorize, Exchange (5 grant types), Revoke, Introspect, InitiateDeviceAuth, AuthorizeDevice |
| `user` | Register, Login, Logout, ResolveSession, GetUserInfo, ValidateCredentials, RequestOTP, VerifyOTP, ResetPassword |
| `client` | Create, Get, Update, Delete, List, Authenticate, ValidateClient |
| `tenant` | Create, Get, Update, Delete, List, Resolve |
| `jwks` | GetJWKS, EnsureKeyPair, RotateKey, GetActiveKeyPair |
| `discovery` | GetDiscoveryDocument |
| `mfa` | EnrollTOTP, ConfirmTOTP, VerifyMFA, CreateChallenge, HasEnrolledMFA |
| `social` | AuthorizeRedirect, HandleCallback |
| `provider` | Create, Get, List, Delete |
| `rbac` | CreateRole, GetRole, ListRoles, UpdateRole, DeleteRole, AssignRole, RevokeRole, GetUserPermissions, GetUserRoles |
| `audit` | LogEvent, Query |

### Layer 3: Adapter (`internal/adapter/`)

Infrastructure implementations of domain ports.

| Adapter | Implements |
|---------|-----------|
| `cache/` | 19 in-memory repositories (dev/fallback) |
| `postgres/` | 7 Postgres repositories + migration runner |
| `redis/` | 7 Redis repositories (session, code, device, blacklist, state, OTP, challenge) |
| `crypto/` | KeyGenerator, JWKConverter, JWTSigner, BcryptHasher, Encryptor |
| `email/` | ConsoleSender (dev), SMTPSender (prod) |
| `sms/` | ConsoleSender (dev), TwilioSender (prod) |
| `http/handler/` | 16 HTTP handlers (+ rbac, audit) |
| `http/middleware/` | CORS, TenantResolver, AdminAuth, RateLimiter, Tracing (OTel), MTLS |
| `http/oauth/` | HTTPOAuthClient (outbound to Google/GitHub/etc) |

## Data Flow

### Request Lifecycle

```
HTTP Request
    │
    ├─► CORS Middleware (add headers, handle preflight)
    │
    ├─► Rate Limiter (check IP, sliding window)
    │
    ├─► Tenant Resolver (X-Tenant-ID header or Host domain)
    │       │
    │       └─► Injects tenant_id into request context
    │
    ├─► Handler (parse request, validate input)
    │       │
    │       └─► Application Service (business logic)
    │               │
    │               ├─► Domain Entity (validation, rules)
    │               │
    │               └─► Port Interface ──► Adapter (Postgres/Redis/Crypto)
    │
    └─► HTTP Response (WriteJSON envelope or WriteRaw for OIDC)
```

### Storage Architecture

```
┌──────────────────────────────────────────────────────┐
│                    AuthPlex Server                     │
├──────────────────────────────────────────────────────┤
│                                                       │
│   Environment = "local"                               │
│   ┌─────────────────────────┐                        │
│   │   All In-Memory         │  (data lost on restart)│
│   └─────────────────────────┘                        │
│                                                       │
│   Environment = "staging" / "production"              │
│   ┌─────────────┐  ┌──────────────┐  ┌────────────┐ │
│   │  Postgres    │  │    Redis     │  │  In-Memory │ │
│   │  (durable)   │  │  (ephemeral) │  │  (fallback)│ │
│   │              │  │              │  │            │ │
│   │  15 tables   │  │  7 stores    │  │  2 stores  │ │
│   │  19 migrations│  │  TTL-based   │  │  TOTP/MFA  │ │
│   └─────────────┘  └──────────────┘  └────────────┘ │
│                                                       │
│   If Redis unavailable → all ephemeral falls back     │
│   to in-memory with warning log                       │
└──────────────────────────────────────────────────────┘
```

## Security Architecture

```
┌──────────────────────────────────────────────┐
│              Security Layers                  │
├──────────────────────────────────────────────┤
│                                               │
│  Transport:  TLS (via reverse proxy)          │
│                                               │
│  CORS:       Configurable allowed origins     │
│                                               │
│  Rate Limit: 20 req/min per IP on             │
│              /login, /token, /otp/verify,     │
│              /mfa/verify                       │
│                                               │
│  Admin Auth: API key (constant-time compare)  │
│              on /tenants, /clients, /providers│
│                                               │
│  Client:     Validate client_id, redirect_uri,│
│              scopes, grant_type               │
│                                               │
│  User Auth:  Session-based (server-side)      │
│              bcrypt password hashing (cost 12) │
│              No user enumeration              │
│                                               │
│  MFA:        Per-tenant policy enforcement    │
│              TOTP (RFC 6238) + SMS OTP        │
│              Challenge-based flow             │
│                                               │
│  Tokens:     JWT signed (RS256/ES256)         │
│              Per-tenant isolated keys         │
│              Refresh token rotation + replay  │
│              detection via family tracking    │
│                                               │
│  Encryption: AES-256-GCM for secrets at rest  │
│                                               │
│  PKCE:       S256 (constant-time compare)     │
│                                               │
│  RBAC:       Per-tenant roles + permissions   │
│              Wildcard matching (posts:*, *)    │
│              Embedded in JWT claims            │
│                                               │
│  mTLS:       Client certificate verification  │
│              for M2M communication             │
│                                               │
│  Audit:      25+ event types logged           │
│              Query API with filters            │
│                                               │
│  Tracing:    OpenTelemetry middleware          │
│              Distributed trace context         │
│                                               │
└──────────────────────────────────────────────┘
```

## Database Schema

All tables use proper SQL types — no `TEXT` for bounded or structured data.

### Type Conventions

| Column Kind | SQL Type | Rationale |
|-------------|----------|-----------|
| Internal primary key | `UUID DEFAULT gen_random_uuid()` | Globally unique, unguessable, DB-generated |
| OAuth client identifier | `VARCHAR(100)` | User-visible, human-readable (e.g. `careos-backend`) |
| FK references to internal PKs | `UUID NOT NULL` | Matches PK type |
| Email addresses | `VARCHAR(254)` | RFC 5321 max |
| Display names | `VARCHAR(200)` | Practical upper bound |
| Algorithm names | `VARCHAR(10)` | e.g. `RS256`, `ES256` |
| IP addresses | `VARCHAR(45)` | IPv6 max |
| Phone numbers | `VARCHAR(30)` | E.164 + formatting |
| Client type / actor type | `VARCHAR(20)–VARCHAR(50)` | Enum-like bounded string |
| URLs, scopes, user agents | `TEXT` | Genuinely unbounded |
| Binary data (keys, hashes) | `BYTEA` | Raw bytes |

### Notable Design Decisions

**`clients` table — dual-column identity:**
```
id        UUID PRIMARY KEY DEFAULT gen_random_uuid()  -- DB-internal
client_id VARCHAR(100) NOT NULL UNIQUE                -- OAuth client_id (public)
```
The `id` UUID is the database PK (used for FK constraints, RLS). The `client_id` is the OAuth 2.0 client identifier visible in tokens and API calls. This allows human-readable client names (`careos-backend`) while preserving UUID-based DB integrity.

**RLS policy UUID casting:**
```sql
USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
```
`current_setting()` returns `TEXT`; `nullif(..., '')` converts empty string to NULL before casting, so an unset session variable safely matches no rows.

### Migrations

| # | File | Creates |
|---|------|---------|
| 001 | `001_create_jwk_pairs.sql` | `jwk_pairs` |
| 002 | `002_create_tenants.sql` | `tenants` |
| 003 | `003_create_clients.sql` | `clients` (id UUID + client_id VARCHAR) |
| 004 | `004_create_users.sql` | `users` |
| 005 | `005_create_refresh_tokens.sql` | `refresh_tokens` |
| 006 | `006_create_identity_providers.sql` | `identity_providers` |
| 007 | `007_create_external_identities.sql` | `external_identities` |
| 008 | `008_create_mfa.sql` | `totp_enrollments`, `mfa_challenges` |
| 009 | `009_add_user_phone.sql` | ALTER `users` |
| 010 | `010_create_rbac.sql` | `roles`, `user_role_assignments` |
| 011 | `011_create_audit_events.sql` | `audit_events` |
| 012 | `012_create_webauthn_credentials.sql` | `webauthn_credentials` |
| 013 | `013_add_token_version.sql` | ALTER `users`, `tenants`, `clients` |
| 014 | `014_create_admin_users.sql` | `admin_users` |
| 015 | `015_enable_rls.sql` | RLS policies on 12 tables |
| 016 | `016_audit_immutability.sql` | Audit append-only rules |
| 017 | `017_add_foreign_keys.sql` | FK constraints |
| 018 | `018_add_tenant_settings.sql` | ALTER `tenants` |
| 019 | `019_create_webhooks.sql` | `webhooks` |
