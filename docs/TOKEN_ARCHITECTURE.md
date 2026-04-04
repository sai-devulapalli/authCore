# AuthPlex — Token Architecture

## Token Types & Storage

| Token/Data | Where Stored | TTL | Format | Purpose |
|-----------|-------------|-----|--------|---------|
| **Session token** | Server-side (Redis in prod, in-memory in dev) | 24 hours | Opaque string | Prove user is logged into AuthPlex |
| **JWT access_token** | **Client-side only** — never stored on server | 1 hour | Signed JWT (RS256/ES256) | Authorize API calls to your services |
| **JWT id_token** | **Client-side only** — never stored on server | 1 hour | Signed JWT (RS256/ES256) | User identity claims for your frontend |
| **Refresh token** | Server-side (Postgres in prod, in-memory in dev) | 30 days | Opaque string | Get new JWT when access_token expires |
| **Auth code** | Server-side (Redis in prod) | 10 minutes | Opaque string | One-time code exchanged for tokens |
| **OTP code** | Server-side (Redis in prod) | 5 minutes | 6-digit number | One-time password for email/SMS verification |
| **Signing keys** | Server-side (Postgres) | Permanent until rotated | RSA-2048 or EC P-256 | Sign JWTs |

---

## Session Token vs JWT — When Each Is Used

```
┌─────────────────────────────────────────────────────────────────┐
│                        USER JOURNEY                              │
│                                                                   │
│  Phase 1: AUTHENTICATION          Phase 2: AUTHORIZATION         │
│  "Who are you?"                   "What can you access?"         │
│                                                                   │
│  ┌──────────────┐                 ┌──────────────────┐           │
│  │ Session Token │                 │ JWT access_token  │           │
│  │ (server-side) │                 │ (stateless)       │           │
│  └──────┬───────┘                 └────────┬─────────┘           │
│         │                                   │                     │
│  Used for:                         Used for:                      │
│  • /authorize                      • Calling YOUR APIs            │
│  • /userinfo                       • Calling ANY service          │
│  • Any AuthPlex endpoint           • Machine-to-machine           │
│    that needs to know              • Passed in Authorization      │
│    "who is logged in"                header to resource servers   │
│                                                                   │
│  Lives: AuthPlex only              Lives: Your app + your APIs   │
│  Stored: Redis (server)            Stored: NOWHERE on server     │
│  Revokable: YES (instant)          Revokable: NO (expires in 1h)│
└─────────────────────────────────────────────────────────────────┘
```

---

## Phase 1: Session Token (Talking to AuthPlex)

The session token is created when a user authenticates with AuthPlex (login, OTP verify). It proves "this user is logged in" and is used exclusively for AuthPlex endpoints.

```
User                          Your Frontend                    AuthPlex
 │                                │                               │
 │  Enter email + password        │                               │
 │ ─────────────────────────────► │                               │
 │                                │  POST /login                  │
 │                                │ ──────────────────────────────►│
 │                                │  ◄── {session_token: "abc"}   │
 │                                │                               │
 │                                │  Store session_token          │
 │                                │  (memory or cookie)           │
 │                                │                               │
 │                                │  GET /authorize (PKCE)        │
 │                                │  Authorization: Bearer abc  ◄── session_token
 │                                │ ──────────────────────────────►│
 │                                │  ◄── 302 redirect with code   │
 │                                │                               │
 │                                │  POST /token (exchange code)  │
 │                                │ ──────────────────────────────►│
 │                                │  ◄── {access_token: JWT,      │
 │                                │       id_token: JWT,           │
 │                                │       refresh_token: "xyz"}    │
 │                                │                               │
 │                                │  Session token's job is DONE  │
 │                                │  Now use JWT for everything    │
```

**Session token endpoints:**
- `GET /authorize` — proves who the user is before issuing auth code
- `GET /userinfo` — returns user profile claims
- `POST /logout` — deletes the session

---

## Phase 2: JWT (Talking to Your APIs)

The JWT access_token is self-contained — your API verifies it locally using AuthPlex's public keys (JWKS), without ever calling AuthPlex.

```
Your Frontend                    Your Backend API               AuthPlex
 │                                │                               │
 │  GET /api/orders               │                               │
 │  Authorization: Bearer <JWT> ◄── access_token                 │
 │ ──────────────────────────────►│                               │
 │                                │                               │
 │                                │  Verify JWT signature         │
 │                                │  via /jwks (cached) ─────────►│  (one-time fetch)
 │                                │  ◄─────────────────────────── │
 │                                │                               │
 │                                │  Read claims from JWT:        │
 │                                │    sub = user ID              │
 │                                │    aud = client ID            │
 │                                │    exp = still valid?         │
 │                                │                               │
 │  ◄── {orders: [...]}           │  ✅ No call to AuthPlex       │
 │                                │     JWT is self-contained     │
```

**JWT is used for:**
- Any API call from your frontend to your backend
- Microservice-to-microservice calls
- Any resource server that needs to verify the user's identity

---

## JWT Token Structure

### Access Token (decoded from a real AuthPlex response)

```
┌─────────── Header ───────────┐
│ {                             │
│   "alg": "RS256",            │  ← Signing algorithm
│   "typ": "JWT",              │  ← Token type
│   "kid": "BqBw3X_U0_..."    │  ← Key ID (matches JWKS endpoint)
│ }                             │
├─────────── Claims ───────────┤
│ {                             │
│   "iss": "https://authplex", │  ← Issuer
│   "sub": "gvMjYJoa...",     │  ← Subject (user ID)
│   "aud": ["5_CoH-nr..."],   │  ← Audience (client ID)
│   "exp": 1774646411,        │  ← Expires at (Unix timestamp)
│   "iat": 1774642811,        │  ← Issued at
│   "jti": "jtTwthHC..."      │  ← Unique token ID
│ }                             │
├─────────── Signature ────────┤
│ RS256(                        │
│   base64url(header) + "." +  │
│   base64url(claims),         │
│   tenant_private_key         │  ← Verified via /jwks public key
│ )                             │
└──────────────────────────────┘
```

### ID Token

Same structure as access_token but includes additional OIDC claims:
- `nonce` — replay protection (from authorize request)
- Can include `email`, `name`, `email_verified` (if profile scope requested)

### How JWT Verification Works (any language)

```
Your API receives: Authorization: Bearer eyJhbG...

Step 1: Decode header → get "kid" (key ID)
Step 2: Fetch GET /jwks?tenant_id=my-tenant → find key matching "kid"
        (cache this — keys rarely change)
Step 3: Verify RS256 signature using public key from JWKS
Step 4: Check "exp" > now (token not expired)
Step 5: Check "iss" = "https://authplex" (correct issuer)
Step 6: Check "aud" contains your client_id (token is for you)
Step 7: Read "sub" = user ID → your app knows who this is
```

---

## Comparison Table

| | **Session Token** | **JWT (access_token)** |
|--|-------------------|----------------------|
| **When created** | On login, OTP verify | On /token exchange (PKCE) |
| **Who uses it** | Your frontend → AuthPlex only | Your frontend → your APIs |
| **What it proves** | "This user is logged into AuthPlex" | "This user is authorized to access resources" |
| **Stored on server** | Yes (Redis, 24h TTL) | No (stateless — never stored) |
| **Contains claims** | No (opaque ID) | Yes (sub, aud, exp, iss, jti) |
| **Can be revoked** | Yes (delete from Redis, instant) | No (wait for 1h expiry, or use blacklist) |
| **Verified by** | AuthPlex Redis lookup | Any service via JWKS public key |
| **Lifetime** | 24 hours | 1 hour |
| **Sent as** | `Authorization: Bearer <session>` to AuthPlex | `Authorization: Bearer <JWT>` to your APIs |
| **If stolen** | Revoke immediately via /logout | Attacker has access for up to 1 hour |
| **Offline verification** | No (needs Redis) | Yes (only needs cached JWKS) |

---

## Why Both? Why Not Just JWT?

| Scenario | Session Token | JWT |
|----------|:------------:|:---:|
| User clicks "Logout" | Deleted instantly from Redis | Can't be revoked — valid for up to 1 hour |
| Admin force-logs out a user | Delete session → immediate | Requires blacklist check on every request |
| /authorize needs to know who is logged in | Fast Redis lookup | Would need to verify signature + trust claims |
| Mobile app calls your API offline | N/A | JWT verified locally, no network needed |
| Microservice A calls Microservice B | N/A | JWT self-contained, no AuthPlex hop |
| User changes password | Revoke all sessions immediately | Old JWTs still valid until expiry |
| Horizontal scaling | Redis shared across instances | No shared state needed |

**Session = instant revocation for AuthPlex's own endpoints.**
**JWT = zero-network-hop authorization for your application's APIs.**

---

## Complete Flow (end to end)

```
Step 1: POST /login
        → session_token (stored in Redis, 24h)

Step 2: GET /authorize + session_token
        → auth code (stored in Redis, 10min)

Step 3: POST /token + auth code + PKCE verifier
        → access_token (JWT, 1h)
        → id_token (JWT, 1h)
        → refresh_token (stored in Postgres, 30d)

Step 4: GET /api/your-resource + access_token (JWT)
        → Your API verifies JWT via JWKS
        → Returns data (AuthPlex not involved)

Step 5: Access token expires (1 hour)
        → POST /token + refresh_token
        → New access_token (JWT)
        → New refresh_token (rotation)

Step 6: POST /logout
        → Session deleted from Redis (instant)
        → Refresh token revoked in Postgres
        → Access token still valid until expiry (1h max)
```

---

## Storage Architecture

```
CLIENT SIDE                          SERVER SIDE (AuthPlex)
(browser / mobile)
                                     ┌──────────────────────────────┐
┌──────────────────┐                 │  Redis (ephemeral, TTL-based) │
│                  │                 │                                │
│  access_token    │  ← JWT         │  sessions      (24h TTL)     │
│  id_token        │  ← JWT         │  auth codes    (10m TTL)     │
│  refresh_token   │  ← opaque      │  device codes  (15m TTL)     │
│  session_token   │  ← opaque      │  OTP codes     (5m TTL)      │
│                  │                 │  OAuth state   (10m TTL)     │
│  (stored in      │                 │  blacklist     (token TTL)   │
│   memory,        │                 │                                │
│   localStorage,  │                 └──────────────────────────────┘
│   secure cookie, │
│   or keychain)   │                 ┌──────────────────────────────┐
│                  │                 │  Postgres (persistent)        │
└──────────────────┘                 │                                │
                                     │  users                        │
  JWTs are NEVER stored              │  tenants                      │
  on the server — they               │  clients                      │
  are self-contained                 │  signing keys (JWKS)         │
  and signed                         │  refresh tokens (30d)        │
                                     │  identity providers           │
                                     │  external identities          │
                                     │                                │
                                     └──────────────────────────────┘
```

---

## Refresh Token Rotation (Security)

```
Time 0:  POST /token → access_token_1 + refresh_token_1 (family: F1)

Time 1h: access_token_1 expires
         POST /token + refresh_token_1
         → access_token_2 + refresh_token_2 (family: F1)
         → refresh_token_1 marked as "rotated"

Time 2h: access_token_2 expires
         POST /token + refresh_token_2
         → access_token_3 + refresh_token_3 (family: F1)
         → refresh_token_2 marked as "rotated"

ATTACK:  Attacker tries to reuse refresh_token_1
         → AuthPlex detects: token already rotated!
         → REVOKE ENTIRE FAMILY F1
         → All tokens (refresh_token_2, refresh_token_3) invalidated
         → User must re-login
```

This is called **refresh token rotation with replay detection** — if any old refresh token is reused, the entire chain is revoked as a security measure.
