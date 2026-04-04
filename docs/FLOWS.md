# AuthPlex — Authentication Flows

## 1. User Registration + Email Verification

```
Client App                        AuthPlex                         Email Service
    │                                │                                  │
    │  POST /register                │                                  │
    │  {email, password, name}       │                                  │
    │ ──────────────────────────────►│                                  │
    │                                │                                  │
    │                                │  1. Validate email format        │
    │                                │  2. Check email uniqueness       │
    │                                │  3. Hash password (bcrypt)       │
    │                                │  4. Store user                   │
    │                                │  5. Generate 6-digit OTP         │
    │                                │  6. Store OTP (5 min TTL)        │
    │                                │                                  │
    │                                │  Send verification OTP ─────────►│
    │                                │                                  │
    │  {user_id, email,              │                                  │
    │   verification_sent: true}     │                                  │
    │ ◄──────────────────────────────│                                  │
    │                                │                                  │
    │  POST /otp/verify              │                                  │
    │  {email, code: "123456"}       │                                  │
    │ ──────────────────────────────►│                                  │
    │                                │  7. Verify OTP code              │
    │                                │  8. Mark email_verified = true   │
    │                                │  9. Create session               │
    │                                │                                  │
    │  {session_token, expires_in}   │                                  │
    │ ◄──────────────────────────────│                                  │
```

## 2. Login (Email + Password)

```
Client App                        AuthPlex
    │                                │
    │  POST /login                   │
    │  {email, password}             │
    │ ──────────────────────────────►│
    │                                │
    │                                │  1. Find user by email
    │                                │  2. Check user active
    │                                │  3. Verify password (bcrypt)
    │                                │  4. Create session (24h TTL)
    │                                │
    │  {session_token, expires_in}   │
    │ ◄──────────────────────────────│
```

## 3. Login via OTP (Passwordless)

```
Client App                        AuthPlex                         Email/SMS
    │                                │                                │
    │  POST /otp/request             │                                │
    │  {email, purpose: "login"}     │                                │
    │ ──────────────────────────────►│                                │
    │                                │  1. Find user by email          │
    │                                │  2. Generate OTP                │
    │                                │  3. Store OTP (5 min TTL)       │
    │                                │  4. Send via email/SMS ────────►│
    │                                │                                │
    │  {message: "OTP sent"}         │                                │
    │ ◄──────────────────────────────│                                │
    │                                │                                │
    │  POST /otp/verify              │                                │
    │  {email, code: "123456"}       │                                │
    │ ──────────────────────────────►│                                │
    │                                │  5. Verify OTP                  │
    │                                │  6. Create session              │
    │                                │                                │
    │  {session_token, expires_in}   │                                │
    │ ◄──────────────────────────────│                                │
```

## 4. Authorization Code + PKCE (Primary OAuth Flow)

```
SPA / Mobile                     AuthPlex                         Resource API
    │                                │                                │
    │  1. Generate PKCE pair         │                                │
    │     verifier = random(43)      │                                │
    │     challenge = SHA256(v)      │                                │
    │                                │                                │
    │  GET /authorize                │                                │
    │  ?response_type=code           │                                │
    │  &client_id=my-app             │                                │
    │  &redirect_uri=https://...     │                                │
    │  &code_challenge=...           │                                │
    │  &code_challenge_method=S256   │                                │
    │  &scope=openid profile         │                                │
    │  Authorization: Bearer <session>                                │
    │ ──────────────────────────────►│                                │
    │                                │                                │
    │                                │  2. Resolve session → user      │
    │                                │  3. Validate client_id          │
    │                                │  4. Validate redirect_uri       │
    │                                │  5. Validate scopes             │
    │                                │  6. Check MFA policy            │
    │                                │  7. Generate auth code          │
    │                                │  8. Store code (10 min TTL)     │
    │                                │                                │
    │  302 redirect_uri?code=AUTH    │                                │
    │ ◄──────────────────────────────│                                │
    │                                │                                │
    │  POST /token                   │                                │
    │  grant_type=authorization_code │                                │
    │  &code=AUTH_CODE               │                                │
    │  &code_verifier=original       │                                │
    │  &client_id=my-app             │                                │
    │ ──────────────────────────────►│                                │
    │                                │                                │
    │                                │  9. Consume code (atomic)       │
    │                                │  10. Verify PKCE (S256)         │
    │                                │  11. Validate client match      │
    │                                │  12. Sign JWT (RS256/ES256)     │
    │                                │                                │
    │  {access_token, id_token,      │                                │
    │   refresh_token, expires_in}   │                                │
    │ ◄──────────────────────────────│                                │
    │                                │                                │
    │  API call                      │                                │
    │  Authorization: Bearer <AT>    │                                │
    │ ──────────────────────────────────────────────────────────────►│
    │                                │                                │
    │                                │  GET /jwks                     │
    │                                │ ◄─────────────────────────────│
    │                                │ ─────────────────────────────►│
    │                                │                                │
    │                                │  13. Verify JWT signature       │
    │  Response                      │      using JWKS public key     │
    │ ◄────────────────────────────────────────────────────────────── │
```

## 5. Authorization Code + PKCE + MFA

```
SPA                              AuthPlex
    │                                │
    │  GET /authorize (with session) │
    │ ──────────────────────────────►│
    │                                │
    │                                │  Tenant MFA = "required"
    │                                │  User has TOTP enrolled
    │                                │
    │  200 JSON:                     │
    │  {mfa_required: true,          │
    │   challenge_id: "ch-123",      │
    │   methods: ["totp"],           │
    │   expires_in: 300}             │
    │ ◄──────────────────────────────│
    │                                │
    │  (User enters TOTP code)       │
    │                                │
    │  POST /mfa/verify              │
    │  {challenge_id: "ch-123",      │
    │   method: "totp",              │
    │   code: "123456"}              │
    │ ──────────────────────────────►│
    │                                │
    │                                │  Verify TOTP code
    │                                │  Complete original authorize
    │                                │  Issue auth code
    │                                │
    │  {code: "AUTH_CODE",           │
    │   state: "original_state"}     │
    │ ◄──────────────────────────────│
    │                                │
    │  POST /token (normal exchange) │
    │ ──────────────────────────────►│
```

## 6. Social Login (Google Example)

```
SPA                   AuthPlex                    Google                    SPA
 │                       │                           │                       │
 │  GET /authorize       │                           │                       │
 │  ?provider=google     │                           │                       │
 │  &client_id=my-app    │                           │                       │
 │  &redirect_uri=...    │                           │                       │
 │ ─────────────────────►│                           │                       │
 │                       │                           │                       │
 │                       │  1. Lookup Google provider │                       │
 │                       │  2. Generate CSRF state    │                       │
 │                       │  3. Store state (10 min)   │                       │
 │                       │                           │                       │
 │  302 → Google OAuth   │                           │                       │
 │ ◄─────────────────────│                           │                       │
 │                       │                           │                       │
 │ ──────────────────────────────────────────────────►│                       │
 │                       │                           │                       │
 │            (User consents on Google)              │                       │
 │                       │                           │                       │
 │                       │  GET /callback             │                       │
 │                       │  ?code=GOOGLE_CODE         │                       │
 │                       │  &state=CSRF               │                       │
 │                       │ ◄─────────────────────────│                       │
 │                       │                           │                       │
 │                       │  4. Validate CSRF state    │                       │
 │                       │  5. Exchange code with Google                      │
 │                       │ ─────────────────────────►│                       │
 │                       │  {access_token, id_token} │                       │
 │                       │ ◄─────────────────────────│                       │
 │                       │  6. Fetch user info        │                       │
 │                       │  7. Link external identity │                       │
 │                       │  8. Issue AuthPlex code    │                       │
 │                       │                           │                       │
 │  302 → redirect_uri?code=AUTHPLEX_CODE            │                       │
 │ ◄─────────────────────│                           │                       │
 │                       │                           │                       │
 │  POST /token (exchange AuthPlex code)             │                       │
 │ ─────────────────────►│                           │                       │
```

## 7. Client Credentials (M2M)

```
Backend Service                  AuthPlex
    │                                │
    │  POST /token                   │
    │  grant_type=client_credentials │
    │  &client_id=server-app         │
    │  &client_secret=SECRET         │
    │  &scope=api:read               │
    │ ──────────────────────────────►│
    │                                │
    │                                │  1. Authenticate client (bcrypt)
    │                                │  2. Validate grant type allowed
    │                                │  3. Validate scopes
    │                                │  4. Sign access_token (JWT)
    │                                │     (no id_token, no refresh)
    │                                │
    │  {access_token, token_type,    │
    │   expires_in}                  │
    │ ◄──────────────────────────────│
```

## 8. Refresh Token (with Rotation)

```
Client                           AuthPlex
    │                                │
    │  POST /token                   │
    │  grant_type=refresh_token      │
    │  &refresh_token=RT_OLD         │
    │  &client_id=my-app             │
    │ ──────────────────────────────►│
    │                                │
    │                                │  1. Lookup refresh token
    │                                │  2. Check not rotated (replay?)
    │                                │  3. Check not revoked
    │                                │  4. Check not expired
    │                                │  5. Mark old token as rotated
    │                                │  6. Issue NEW refresh token
    │                                │     (same family_id)
    │                                │  7. Sign new access + id tokens
    │                                │
    │  {access_token, id_token,      │
    │   refresh_token: RT_NEW}       │
    │ ◄──────────────────────────────│
    │                                │
    │                                │
    │  ⚠ If RT_OLD is reused:       │
    │  POST /token                   │
    │  refresh_token=RT_OLD          │
    │ ──────────────────────────────►│
    │                                │
    │                                │  REPLAY DETECTED!
    │                                │  Revoke entire token family
    │                                │
    │  400 {error: "token reused"}   │
    │ ◄──────────────────────────────│
```

## 9. Device Code Flow (RFC 8628)

```
Smart TV / CLI                   AuthPlex                         User's Phone
    │                                │                                │
    │  POST /device/authorize        │                                │
    │  {client_id, scope}            │                                │
    │ ──────────────────────────────►│                                │
    │                                │                                │
    │  {device_code: "DEV123",       │                                │
    │   user_code: "ABCD-1234",      │                                │
    │   verification_uri: "...",     │                                │
    │   expires_in: 900,             │                                │
    │   interval: 5}                 │                                │
    │ ◄──────────────────────────────│                                │
    │                                │                                │
    │  Display: "Go to /device/verify│                                │
    │  Enter code: ABCD-1234"        │                                │
    │                                │                                │
    │  (TV polls every 5 seconds)    │    User enters code ──────────►│
    │  POST /token                   │                                │
    │  grant_type=device_code        │    POST /device/authorize      │
    │  &device_code=DEV123           │    {user_code, subject}        │
    │ ──────────────────────────────►│ ◄──────────────────────────────│
    │                                │                                │
    │  {error: "authorization_pending"}                               │
    │ ◄──────────────────────────────│                                │
    │                                │                                │
    │  ... (user authorizes) ...     │                                │
    │                                │                                │
    │  POST /token (poll again)      │                                │
    │ ──────────────────────────────►│                                │
    │                                │                                │
    │  {access_token, id_token,      │                                │
    │   refresh_token}               │                                │
    │ ◄──────────────────────────────│                                │
```

## 10. Password Reset via OTP

```
Client                           AuthPlex                         Email
    │                                │                               │
    │  POST /otp/request             │                               │
    │  {email, purpose: "reset"}     │                               │
    │ ──────────────────────────────►│                               │
    │                                │  1. Find user by email         │
    │                                │  2. Generate OTP               │
    │                                │  3. Send OTP ─────────────────►│
    │                                │                               │
    │  {message: "OTP sent"}         │                               │
    │ ◄──────────────────────────────│                               │
    │                                │                               │
    │  POST /password/reset          │                               │
    │  {email, code, new_password}   │                               │
    │ ──────────────────────────────►│                               │
    │                                │  4. Verify OTP                 │
    │                                │  5. Hash new password          │
    │                                │  6. Update user                │
    │                                │                               │
    │  {status: "password_reset"}    │                               │
    │ ◄──────────────────────────────│                               │
```

## 11. Tenant + Client Setup (Admin)

```
Admin                            AuthPlex
    │                                │
    │  POST /tenants                 │
    │  X-API-Key: admin-key          │
    │  {id, domain, issuer, alg}     │
    │ ──────────────────────────────►│  Create tenant
    │ ◄──────────────────────────────│
    │                                │
    │  POST /tenants/{id}/clients    │
    │  X-API-Key: admin-key          │
    │  {client_name, client_type,    │
    │   redirect_uris, scopes,       │
    │   grant_types}                 │
    │ ──────────────────────────────►│  Register OAuth client
    │                                │
    │  {client_id, client_secret}    │  (secret shown once for
    │ ◄──────────────────────────────│   confidential clients)
    │                                │
    │  POST /tenants/{id}/providers  │
    │  X-API-Key: admin-key          │
    │  {provider_type: "google",     │
    │   client_id, client_secret}    │
    │ ──────────────────────────────►│  Configure social login
    │ ◄──────────────────────────────│
```
