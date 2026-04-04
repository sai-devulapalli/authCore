# AuthPlex — Comprehensive E2E Test Plan

> **Scope:** All 39 HTTP endpoints, all grant types, all MFA methods, all social providers, RBAC, audit, cleanup, key rotation.
> **Environment:** Real Postgres + Redis via Docker testcontainers. No mocks.
> **Tags:** `//go:build e2e`

---

## 1. OIDC Discovery & JWKS

### 1.1 Discovery Document
- [ ] `GET /.well-known/openid-configuration` returns valid JSON with all required fields
- [ ] Discovery includes `authorization_endpoint`, `token_endpoint`, `jwks_uri`, `userinfo_endpoint`
- [ ] Discovery `issuer` matches configured `AUTHPLEX_ISSUER`
- [ ] Discovery `grant_types_supported` includes all 5 grant types
- [ ] Discovery `response_types_supported` includes `code`
- [ ] Discovery `subject_types_supported` includes `public`
- [ ] Discovery returns tenant-scoped issuer when `X-Tenant-ID` header differs
- [ ] Discovery without tenant header returns 400

### 1.2 JWKS
- [ ] `GET /jwks` returns valid JWKS JSON with `keys` array
- [ ] JWKS contains RSA key with `kty`, `n`, `e`, `kid`, `alg`, `use`
- [ ] JWKS contains EC key when tenant uses ES256
- [ ] JWKS includes both active and recently-rotated keys (grace period)
- [ ] JWKS with `?tenant_id=X` query param returns tenant-specific keys
- [ ] JWKS without tenant defaults to `default` or header-based resolution

---

## 2. User Authentication

### 2.1 Registration
- [ ] `POST /register` with valid email/password/name returns 201 + `user_id`
- [ ] Register sends verification OTP email (verify via console sender logs)
- [ ] Register with duplicate email on same tenant returns 409 Conflict
- [ ] Register with same email on different tenant succeeds (tenant isolation)
- [ ] Register with missing email returns 400
- [ ] Register with missing password returns 400
- [ ] Register with missing name returns 400
- [ ] Register without `X-Tenant-ID` header returns 400
- [ ] Register with phone number stores phone on user
- [ ] Register with invalid tenant ID returns 404

### 2.2 Login
- [ ] `POST /login` with correct credentials returns session token + expires_in
- [ ] Login with wrong password returns 401
- [ ] Login with nonexistent email returns 401
- [ ] Login rate limiting: 21st request within 1 minute returns 429
- [ ] Login on wrong tenant returns 401 (tenant isolation)
- [ ] Login creates a session that can be used for `/userinfo`

### 2.3 Session & UserInfo
- [ ] `GET /userinfo` with valid session token returns user profile (sub, email, name)
- [ ] UserInfo with expired session returns 401
- [ ] UserInfo without session token returns 401
- [ ] UserInfo returns `email_verified: true` after email verification
- [ ] UserInfo returns phone fields when user has phone

### 2.4 Logout
- [ ] `POST /logout` with valid session invalidates the session
- [ ] After logout, `/userinfo` with same token returns 401
- [ ] Logout without session token returns 401

---

## 3. OTP Authentication

### 3.1 Email OTP
- [ ] `POST /otp/request` with `purpose: "login"` sends OTP to email
- [ ] `POST /otp/verify` with correct code creates session
- [ ] OTP verify with wrong code returns 400
- [ ] OTP verify with expired code (>5 min) returns 400
- [ ] OTP verify rate limiting: 21st request returns 429
- [ ] OTP request for nonexistent user returns 404

### 3.2 SMS OTP
- [ ] OTP request with `phone` field sends SMS (verify via console sender)
- [ ] OTP verify via phone creates session

### 3.3 Email Verification
- [ ] `POST /otp/request` with `purpose: "verify"` sends verification OTP
- [ ] Verifying email OTP marks user as `email_verified: true`

### 3.4 Password Reset
- [ ] `POST /otp/request` with `purpose: "reset"` sends reset OTP
- [ ] `POST /password/reset` with valid OTP changes password
- [ ] Password reset with wrong OTP returns 400
- [ ] After reset, login with old password fails
- [ ] After reset, login with new password succeeds

---

## 4. OAuth 2.0 Authorization Code Flow + PKCE

### 4.1 Basic Auth Code Flow
- [ ] `GET /authorize` with valid params returns 302 redirect with `code` and `state`
- [ ] `POST /token` with `grant_type=authorization_code` + valid code returns access_token, id_token, refresh_token
- [ ] Token response includes `token_type: "Bearer"` and `expires_in`
- [ ] Access token is a valid JWT with `sub`, `iss`, `aud`, `exp`, `iat`, `jti`
- [ ] ID token includes `sub`, `email`, `name` claims

### 4.2 PKCE (S256)
- [ ] Authorize with `code_challenge` + `code_challenge_method=S256` succeeds
- [ ] Token exchange with correct `code_verifier` succeeds
- [ ] Token exchange with wrong `code_verifier` returns 400
- [ ] Token exchange without `code_verifier` when challenge was set returns 400

### 4.3 Auth Code Edge Cases
- [ ] Authorize with invalid `client_id` returns 400
- [ ] Authorize with invalid `redirect_uri` (not registered) returns 400
- [ ] Authorize with invalid `scope` (not in client's allowed_scopes) returns 400
- [ ] Authorize with invalid `response_type` returns 400
- [ ] Code can only be used once (replay protection)
- [ ] Expired code (>5 min) returns 400
- [ ] Token exchange with wrong `client_secret` returns 401
- [ ] Token exchange with wrong `redirect_uri` returns 400

### 4.4 Session-Based Authorization
- [ ] Authorize with valid session cookie resolves subject automatically
- [ ] Authorize with `X-Subject` header resolves subject (dev mode)
- [ ] Authorize without subject and without session returns 401

---

## 5. Client Credentials Grant

- [ ] `POST /token` with `grant_type=client_credentials` returns access_token (no refresh)
- [ ] Client credentials with wrong secret returns 401
- [ ] Client credentials with public client returns 400
- [ ] Access token has `sub` = client_id
- [ ] Only scopes allowed for the client are included

---

## 6. Refresh Token Grant

### 6.1 Basic Refresh
- [ ] `POST /token` with `grant_type=refresh_token` returns new access_token + new refresh_token
- [ ] New refresh token replaces old one (rotation)
- [ ] Old refresh token is invalidated after rotation

### 6.2 Replay Detection
- [ ] Using a rotated (old) refresh token revokes the entire token family
- [ ] After family revocation, even the latest refresh token is invalid

### 6.3 Revocation
- [ ] `POST /revoke` with refresh token invalidates it
- [ ] `POST /revoke` with access token JTI blacklists it
- [ ] Revoked token cannot be used for refresh

---

## 7. Device Authorization Grant (RFC 8628)

- [ ] `POST /device/authorize` returns `device_code`, `user_code`, `verification_uri`, `expires_in`, `interval`
- [ ] Polling `POST /token` with `grant_type=urn:ietf:params:oauth:grant-type:device_code` returns `authorization_pending`
- [ ] After user authorizes via user_code, polling returns access_token
- [ ] After user denies, polling returns `access_denied`
- [ ] Expired device code returns `expired_token`
- [ ] Polling faster than `interval` returns `slow_down`

---

## 8. Password Grant

- [ ] `POST /token` with `grant_type=password` + valid credentials returns access_token
- [ ] Password grant with wrong password returns 401
- [ ] Password grant with nonexistent user returns 401

---

## 9. Token Introspection (RFC 7662)

- [ ] `POST /introspect` with valid access token returns `active: true` + claims
- [ ] Introspect with expired token returns `active: false`
- [ ] Introspect with revoked token returns `active: false`
- [ ] Introspect with invalid token returns `active: false`
- [ ] Introspect includes `sub`, `scope`, `client_id`, `exp`, `iat`

---

## 10. Multi-Tenancy

### 10.1 Tenant Isolation
- [ ] Users on tenant A cannot login on tenant B
- [ ] Clients on tenant A are not visible on tenant B
- [ ] Tokens issued for tenant A are invalid on tenant B
- [ ] JWKS returns different keys for different tenants

### 10.2 Tenant Resolution
- [ ] Header mode: `X-Tenant-ID` header resolves tenant
- [ ] Domain mode: `Host` header resolves tenant by domain
- [ ] Missing tenant header returns 400 on tenant-scoped endpoints

### 10.3 Per-Tenant Key Isolation
- [ ] Each tenant gets its own RSA/EC signing key pair
- [ ] Token from tenant A cannot be verified with tenant B's JWKS

---

## 11. Social Login

### 11.1 OAuth Flow
- [ ] `GET /authorize?provider=google` redirects to Google auth URL with correct params
- [ ] `GET /callback` with valid state + code exchanges tokens and issues AuthPlex code
- [ ] Callback with invalid state returns 400
- [ ] Callback with expired state returns 400
- [ ] State is consumed (replay protection) — reusing state returns 400

### 11.2 Identity Linking
- [ ] First social login creates external identity + internal subject
- [ ] Second login with same provider reuses existing internal subject
- [ ] Same user can link multiple providers
- [ ] Provider subject isolation: same email on different providers creates different links

### 11.3 ID Token Decode
- [ ] When userinfo endpoint fails, id_token is decoded for user claims
- [ ] ID token signature is validated against provider's JWKS
- [ ] Invalid id_token signature falls back gracefully (no crash)

### 11.4 Provider-Specific
- [ ] Google: discovery URL auto-configures endpoints
- [ ] GitHub: numeric user ID converted to string
- [ ] Apple: JWT client_secret generated with ES256 for token exchange
- [ ] Apple: `ExtraConfig` with `apple_team_id`, `apple_key_id`, `apple_private_key` used
- [ ] Generic OIDC: discovery URL fetches endpoints dynamically
- [ ] Generic OAuth2: manual auth/token/userinfo URLs used

---

## 12. MFA — TOTP (RFC 6238)

### 12.1 Enrollment
- [ ] `POST /mfa/totp/enroll` returns base32 secret + otpauth:// URI
- [ ] Enroll with already-confirmed enrollment returns 409
- [ ] Enroll replaces unconfirmed enrollment

### 12.2 Confirmation
- [ ] `POST /mfa/totp/confirm` with valid TOTP code confirms enrollment
- [ ] Confirm with wrong code returns 400
- [ ] Confirm with already-confirmed enrollment returns 409

### 12.3 MFA Challenge Flow
- [ ] When tenant MFA policy is `required` and user has enrolled:
  - `/authorize` returns MFA challenge instead of redirect
  - `POST /mfa/verify` with correct TOTP completes auth flow and returns code
  - `/mfa/verify` with wrong TOTP returns 400
  - `/mfa/verify` with expired challenge returns 400
  - `/mfa/verify` with already-verified challenge returns 400
- [ ] When MFA policy is `optional` and user is NOT enrolled: `/authorize` proceeds normally
- [ ] When MFA policy is `none`: `/authorize` never triggers MFA

### 12.4 TOTP Verification Details
- [ ] TOTP accepts code from current time window (30s)
- [ ] TOTP accepts code from ±1 time window (clock drift tolerance)
- [ ] TOTP rejects code from ±2 time windows
- [ ] Rate limiting on `/mfa/verify`: 21st request returns 429

---

## 13. MFA — WebAuthn/FIDO2

### 13.1 Registration
- [ ] `POST /mfa/webauthn/register/begin` returns credential creation options + session_id
- [ ] Options contain `rp.id`, `rp.name`, `user.id`, `user.name`, `challenge`
- [ ] `POST /mfa/webauthn/register/finish` with valid attestation stores credential
- [ ] Register finish with expired session returns 400
- [ ] Register finish with invalid attestation returns 400
- [ ] Register without WebAuthn configured returns 400
- [ ] Register with missing subject returns 400

### 13.2 Authentication
- [ ] `POST /mfa/webauthn/login/begin` returns assertion options + challenge_id
- [ ] Login begin with no credentials registered returns 404
- [ ] `POST /mfa/webauthn/login/finish` with valid assertion verifies credential
- [ ] Login finish updates sign count on credential
- [ ] Login finish with expired session returns 400
- [ ] Login finish with invalid assertion returns 400

### 13.3 MFA Challenge Integration
- [ ] When tenant MFA methods include `webauthn` and user has WebAuthn credential:
  - `/authorize` returns challenge with `methods: ["webauthn"]`
  - `/mfa/verify` with `method: "webauthn"` dispatches to WebAuthn verification
- [ ] `HasEnrolledMFA` returns true when user has either TOTP or WebAuthn

---

## 14. Client Registry

### 14.1 CRUD
- [ ] `POST /tenants/{id}/clients` creates client with generated ID + secret
- [ ] `GET /tenants/{id}/clients` lists clients (paginated)
- [ ] `GET /tenants/{id}/clients/{cid}` returns client (no secret)
- [ ] `PUT /tenants/{id}/clients/{cid}` updates client fields
- [ ] `DELETE /tenants/{id}/clients/{cid}` soft-deletes client

### 14.2 Client Types
- [ ] Confidential client requires secret on token exchange
- [ ] Public client does not require secret
- [ ] Public client cannot use `client_credentials` grant

### 14.3 Scope Enforcement
- [ ] Token request with scope not in client's `allowed_scopes` returns 400
- [ ] Token issued only contains scopes that are both requested and allowed
- [ ] Authorize with invalid scope returns 400

### 14.4 Grant Type Enforcement
- [ ] Token request with grant type not in client's `allowed_grant_types` returns 400
- [ ] Client with only `authorization_code` cannot use `client_credentials`

### 14.5 Redirect URI Enforcement
- [ ] Authorize with redirect_uri not in client's `redirect_uris` returns 400
- [ ] Token exchange with redirect_uri mismatch returns 400

---

## 15. Tenant Management

### 15.1 CRUD
- [ ] `POST /tenants` creates tenant with signing key auto-provisioned
- [ ] `GET /tenants` lists tenants with pagination (`offset`, `limit`, `total`)
- [ ] `GET /tenants/{id}` returns tenant details
- [ ] `PUT /tenants/{id}` updates domain/issuer
- [ ] `DELETE /tenants/{id}` soft-deletes (sets `deleted_at`)

### 15.2 Validation
- [ ] Create with empty ID returns 400
- [ ] Create with empty domain returns 400
- [ ] Create with invalid algorithm returns 400
- [ ] Create with duplicate ID returns 409

### 15.3 Algorithm Support
- [ ] Tenant with RS256 gets RSA-2048 key pair
- [ ] Tenant with ES256 gets EC P-256 key pair
- [ ] Tokens signed with correct algorithm per tenant

---

## 16. RBAC

### 16.1 Role CRUD
- [ ] Create role with name + permissions
- [ ] List roles for tenant
- [ ] Update role permissions
- [ ] Delete role

### 16.2 User Role Assignment
- [ ] Assign role to user
- [ ] List user's roles
- [ ] Get user's flattened permissions
- [ ] Remove role from user

### 16.3 Permission Wildcards
- [ ] Permission `posts:*` matches `posts:read`, `posts:write`, `posts:delete`
- [ ] Permission `*` matches everything
- [ ] Exact permission `posts:read` only matches `posts:read`

### 16.4 JWT Claims Enrichment
- [ ] Access token includes `roles` claim with user's role names
- [ ] Access token includes `permissions` claim with flattened permissions
- [ ] User with no roles has empty `roles`/`permissions` claims

---

## 17. Audit Logging

### 17.1 Event Recording
- [ ] `login_success` event logged on successful login
- [ ] `login_failure` event logged on failed login
- [ ] `register` event logged on user registration
- [ ] `token_issued` event logged on token issuance
- [ ] `token_revoked` event logged on token revocation
- [ ] `tenant_created` event logged on tenant creation
- [ ] `client_created` event logged on client creation
- [ ] `role_assigned` event logged on role assignment
- [ ] `mfa_enrolled` event logged on MFA enrollment
- [ ] `admin_api_access` event logged on management API access

### 17.2 Query API
- [ ] `GET /tenants/{id}/audit` returns events with pagination
- [ ] Filter by `action` query param
- [ ] Filter by `actor_id` query param
- [ ] Filter by `resource_type` query param
- [ ] Filter by `resource_id` query param
- [ ] Pagination with `offset` and `limit`
- [ ] Events include `ip_address`, `user_agent`, `timestamp`

---

## 18. Admin API Authentication

- [ ] Management endpoints without API key return 401
- [ ] Management endpoints with wrong API key return 401
- [ ] `Authorization: Bearer <key>` header accepted
- [ ] `X-API-Key: <key>` header accepted
- [ ] When `AUTHPLEX_ADMIN_API_KEY` is empty (dev mode), auth is skipped
- [ ] Constant-time comparison (timing attack protection — verify no early return)

---

## 19. Rate Limiting

- [ ] `/login` rate limited at 20 req/min per IP
- [ ] `/token` rate limited at 20 req/min per IP
- [ ] `/otp/verify` rate limited at 20 req/min per IP
- [ ] `/mfa/verify` rate limited at 20 req/min per IP
- [ ] Rate limit returns 429 with `Retry-After` header
- [ ] Sliding window resets after 1 minute
- [ ] Different IPs have independent rate limits

---

## 20. CORS

- [ ] Preflight `OPTIONS` request returns correct CORS headers
- [ ] `Access-Control-Allow-Origin` matches configured `AUTHPLEX_CORS_ORIGINS`
- [ ] `Access-Control-Allow-Methods` includes GET, POST, PUT, DELETE, OPTIONS
- [ ] `Access-Control-Allow-Headers` includes Content-Type, Authorization, X-Tenant-ID, X-API-Key
- [ ] Wildcard `*` origin works in dev mode
- [ ] Specific origins work in production mode

---

## 21. Encryption at Rest

- [ ] When `AUTHPLEX_ENCRYPTION_KEY` is set, sensitive fields are encrypted in storage
- [ ] Data is decrypted correctly when retrieved
- [ ] Without encryption key, data is stored in plaintext
- [ ] Wrong encryption key fails to decrypt (graceful error)

---

## 22. Token Lifecycle — Cleanup & Rotation

### 22.1 Refresh Token Cleanup
- [ ] Background service deletes revoked tokens older than retention period (7 days)
- [ ] Background service deletes expired tokens older than retention period
- [ ] Active (non-revoked, non-expired) tokens are NOT deleted
- [ ] Cleanup runs on startup and every 24 hours

### 22.2 Key Auto-Rotation
- [ ] Keys older than `AUTHPLEX_KEY_ROTATION_DAYS` (default 90) are rotated
- [ ] Rotated key is deactivated but kept for verification during grace period
- [ ] New key is generated and becomes active
- [ ] JWKS serves both old and new keys during grace period
- [ ] Inactive keys older than 30 days are cleaned up
- [ ] Tokens signed with old key are still verifiable via JWKS (grace period)

---

## 23. mTLS

- [ ] When mTLS middleware is enabled, requests with valid client certificate proceed
- [ ] Requests without client certificate return 401
- [ ] Requests with invalid/expired certificate return 401
- [ ] Certificate CN/SAN can be used for client identification

---

## 24. OpenTelemetry Tracing

- [ ] Tracing middleware adds trace ID to request context
- [ ] Response includes `X-Trace-ID` header (or similar)
- [ ] Spans are created for each HTTP request
- [ ] Child spans created for database/service calls

---

## 25. Health Check

- [ ] `GET /health` returns 200 with `{"status": "UP"}`
- [ ] Health check does not require authentication
- [ ] Health check does not require tenant header

---

## 26. Go SDK (pkg/authplex)

- [ ] `authplex.New()` creates embeddable AuthPlex instance
- [ ] `Register()` creates a user
- [ ] `Login()` returns session
- [ ] `IssueTokens()` generates access + ID tokens
- [ ] `VerifyJWT()` validates a token against tenant's keys
- [ ] `MountRoutes()` registers all HTTP endpoints on a mux
- [ ] `RequireJWT()` middleware rejects unauthenticated requests

---

## 27. Golden Path E2E Flows

### 27.1 Full Authentication Flow
```
1. Create tenant (RS256)
2. Create confidential client (auth_code + refresh_token)
3. Register user
4. Login user → session token
5. Authorize (with session) → auth code
6. Exchange code → access_token + refresh_token
7. Verify JWKS contains signing key
8. Introspect access_token → active: true
9. Refresh token → new tokens
10. Revoke refresh token
11. Introspect → active: false
12. UserInfo → user profile
13. Logout
```

### 27.2 MFA-Protected Flow
```
1. Create tenant with MFA policy: required, methods: ["totp"]
2. Create client
3. Register + login user
4. Enroll TOTP
5. Confirm TOTP with valid code
6. Authorize → MFA challenge
7. Verify MFA with TOTP → auth code
8. Exchange code → tokens
```

### 27.3 Social Login Flow
```
1. Create tenant
2. Create identity provider (mock provider for E2E)
3. Authorize with provider param → redirect to provider
4. Callback with code → identity linked + AuthPlex code issued
5. Exchange code → tokens with social user's claims
```

### 27.4 Multi-Tenant Isolation Flow
```
1. Create tenant A (RS256)
2. Create tenant B (ES256)
3. Register user on tenant A
4. Verify user cannot login on tenant B
5. Create client on tenant A
6. Verify client not visible on tenant B
7. Issue token on tenant A
8. Verify token invalid on tenant B's JWKS
```

### 27.5 RBAC Flow
```
1. Create tenant + client + user
2. Create role "admin" with permissions ["users:*", "posts:*"]
3. Create role "viewer" with permissions ["posts:read"]
4. Assign "admin" role to user
5. Login + authorize + token exchange
6. Verify access_token has roles=["admin"] and permissions=["users:*", "posts:*"]
7. Assign "viewer" role too
8. New token has both roles and merged permissions
9. Remove "admin" role
10. New token only has "viewer" permissions
```

### 27.6 Device Code Flow
```
1. Create tenant + client (with device_code grant)
2. POST /device/authorize → device_code + user_code
3. Poll POST /token → authorization_pending
4. Authorize device (user enters user_code)
5. Poll POST /token → access_token
```

### 27.7 Password Reset Flow
```
1. Register user with email
2. Request password reset OTP
3. Reset password with OTP + new password
4. Login with old password → 401
5. Login with new password → success
```

---

## 28. Error Handling & Edge Cases

### 28.1 Invalid JSON
- [ ] POST with invalid JSON body returns 400 with clear error message
- [ ] POST with empty body returns 400
- [ ] POST with wrong Content-Type returns 400

### 28.2 Method Not Allowed
- [ ] GET on POST-only endpoints returns 400/405
- [ ] POST on GET-only endpoints returns 400/405

### 28.3 Not Found
- [ ] Nonexistent tenant returns 404
- [ ] Nonexistent client returns 404
- [ ] Nonexistent role returns 404
- [ ] Unknown URL path returns 404

### 28.4 Concurrent Operations
- [ ] Concurrent token exchanges with same code — only first succeeds
- [ ] Concurrent user registrations with same email — only first succeeds
- [ ] Concurrent refresh token rotations — replay detection triggers

### 28.5 Large Payloads
- [ ] Very long redirect_uri list (100+ URIs) handled correctly
- [ ] Very long scope string handled correctly
- [ ] Very large permission set on role handled correctly

### 28.6 Special Characters
- [ ] Tenant ID with special characters (hyphens, dots) works
- [ ] Email with `+` alias works
- [ ] Redirect URI with query parameters works
- [ ] State parameter with special characters preserved in redirect

---

## 29. Database & Persistence

### 29.1 Postgres
- [ ] All 12 migrations run successfully on fresh database
- [ ] Migrations are idempotent (running twice doesn't error)
- [ ] All 7 Postgres repos persist and retrieve data correctly
- [ ] Connection pool handles concurrent requests

### 29.2 Redis
- [ ] Session storage with TTL auto-expiry
- [ ] Auth code storage with TTL (5 min)
- [ ] Device code storage with TTL
- [ ] Token blacklist with TTL
- [ ] OAuth state storage with TTL
- [ ] OTP storage with TTL
- [ ] Redis unavailable → graceful fallback to in-memory

---

## 30. Docker & Deployment

- [ ] `make docker` builds image successfully
- [ ] Docker image size < 20MB
- [ ] Container starts with required env vars
- [ ] Container connects to external Postgres + Redis
- [ ] Health check returns UP after startup
- [ ] Graceful shutdown on SIGTERM (15s timeout)
- [ ] In-memory mode works without Postgres/Redis

---

## Test Matrix: Grant Types x Client Types

| Grant Type | Public Client | Confidential Client |
|-----------|---------------|-------------------|
| authorization_code | PKCE required, no secret | Secret required |
| client_credentials | Not allowed (400) | Secret required |
| refresh_token | Allowed | Allowed |
| device_code | Allowed | Allowed |
| password | Allowed | Allowed |

## Test Matrix: MFA Policy x Enrollment

| MFA Policy | No MFA Enrolled | TOTP Enrolled | WebAuthn Enrolled | Both Enrolled |
|-----------|----------------|---------------|-------------------|---------------|
| none | Pass through | Pass through | Pass through | Pass through |
| optional | Pass through | Challenge | Challenge | Challenge (both methods) |
| required | Block (must enroll) | Challenge | Challenge | Challenge (both methods) |

## Test Matrix: Token Types x Operations

| Operation | Access Token | Refresh Token | ID Token |
|----------|-------------|---------------|----------|
| Introspect | active: true/false | active: true/false | N/A |
| Revoke | Blacklist by JTI | Revoke + family | N/A |
| Verify (JWKS) | Signature valid | N/A | Signature valid |
| Refresh | N/A | Issue new pair | N/A |
| UserInfo | Required | N/A | N/A |
