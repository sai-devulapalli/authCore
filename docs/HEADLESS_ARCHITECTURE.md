# AuthCore — Headless Architecture

> **Headless** = No built-in UI. Pure API and protocol endpoints. Your frontend, your UX, your brand.

---

## What "Headless" Means

```
Traditional IAM (Keycloak, Auth0):
┌─────────────────────────────────────────┐
│         IAM Server                       │
│  ┌──────────────────────────────────┐   │
│  │  Built-in Login UI (HTML/CSS/JS) │   │  ← You get THEIR login page
│  │  Built-in Register UI            │   │  ← You customize via themes
│  │  Built-in Consent Screen         │   │  ← Limited control
│  │  Built-in Account Management     │   │
│  └──────────────────────────────────┘   │
│  ┌──────────────────────────────────┐   │
│  │  API Layer (OIDC/OAuth)          │   │
│  └──────────────────────────────────┘   │
└─────────────────────────────────────────┘

Headless IAM (AuthCore):
┌──────────────────────────┐
│       AuthCore Server     │
│  ┌────────────────────┐  │
│  │  API Layer ONLY     │  │  ← Pure JSON endpoints
│  │  (OIDC/OAuth/REST)  │  │  ← No HTML, no CSS, no JS
│  └────────────────────┘  │
│                           │
│  No UI. Zero templates.   │
│  No themes to customize.  │
│  No iframes to embed.     │
└──────────────────────────┘
         │
         │ HTTP/JSON
         ▼
┌──────────────────────────┐
│     YOUR Frontend         │
│                           │
│  React / Vue / Svelte     │  ← You build the ENTIRE UX
│  Mobile (Swift / Kotlin)  │  ← Native login screens
│  CLI (Go / Rust)          │  ← Terminal-based auth
│  Desktop (Electron)       │  ← Desktop app login
│                           │
│  100% YOUR design.        │
│  100% YOUR brand.         │
│  100% YOUR control.       │
└──────────────────────────┘
```

---

## Why Headless?

### Problems with Built-in UIs

| Problem | Impact |
|---------|--------|
| **Theme limitations** | Can't match your brand perfectly. Always looks "auth provider-ish" |
| **Iframe security** | Embedding login in iframes has clickjacking risks |
| **Redirect UX** | Users leave your app → login page → redirect back. Jarring |
| **Mobile mismatch** | Web-based login pages don't feel native on iOS/Android |
| **A/B testing** | Can't A/B test the login flow without forking the auth server |
| **Accessibility** | Stuck with the provider's accessibility implementation |
| **Bundle size** | Auth server ships HTML/CSS/JS assets you don't need |
| **Attack surface** | XSS in the auth server's UI = credential theft |

### What Headless Solves

| Benefit | How |
|---------|-----|
| **Total UX control** | You build login/register with YOUR components, YOUR design system |
| **No redirects** | Login happens in YOUR app. No leaving your domain |
| **Native mobile** | Call API directly from Swift/Kotlin. No WebViews |
| **A/B testing** | Test different login flows like any other page |
| **Zero vendor branding** | Users never see "Powered by X" |
| **Smaller attack surface** | No server-side HTML rendering = no XSS in auth |
| **Framework agnostic** | React, Vue, Svelte, HTMX, vanilla JS — all work the same |

---

## Architecture Layers

```
┌───────────────────────────────────────────────────────────┐
│                     Client Layer                           │
│  Your frontend calls AuthCore APIs directly                │
│                                                            │
│  React App    Mobile App    CLI Tool    Backend Service    │
│  (browser)    (native)      (terminal)  (server-to-server)│
└──────────┬────────────┬─────────┬────────────┬────────────┘
           │            │         │            │
           ▼            ▼         ▼            ▼
┌───────────────────────────────────────────────────────────┐
│                  Protocol Layer (HTTP)                      │
│                                                            │
│  OIDC Endpoints          User Endpoints      MFA Endpoints │
│  /.well-known/oidc       POST /register      POST /mfa/*   │
│  GET /jwks               POST /login         POST /otp/*   │
│  GET /authorize          POST /logout                      │
│  POST /token             GET /userinfo       WebAuthn      │
│  POST /revoke                                POST /mfa/    │
│  POST /introspect        Management API       webauthn/*   │
│  POST /device/authorize  POST /tenants                     │
│                          POST /clients                     │
│                          POST /roles                       │
│                          GET /audit                        │
├───────────────────────────────────────────────────────────┤
│                  Application Layer                         │
│                                                            │
│  AuthService      UserService      MFAService              │
│  ClientService    TenantService    RBACService              │
│  SocialService    ProviderService  AuditService             │
│  DiscoveryService JWKSService      CleanupService           │
├───────────────────────────────────────────────────────────┤
│                    Domain Layer                            │
│                                                            │
│  User  Tenant  Client  Token  KeyPair  Role  AuditEvent   │
│  Session  RefreshToken  DeviceCode  AuthorizationCode      │
│  IdentityProvider  ExternalIdentity  TOTPEnrollment        │
│  MFAChallenge  WebAuthnCredential  OTP                     │
│                                                            │
│  Repository Ports  (interfaces — no implementation here)   │
├───────────────────────────────────────────────────────────┤
│                   Adapter Layer                            │
│                                                            │
│  Postgres (7 repos)    Redis (7 repos)    Cache (20 repos) │
│  Crypto (JWT, bcrypt)  Email (SMTP)       SMS (Twilio)     │
│  OAuth (HTTP client)   Middleware (CORS, rate limit, etc)   │
└───────────────────────────────────────────────────────────┘
```

---

## Hexagonal Architecture (Ports & Adapters)

AuthCore uses **hexagonal architecture** — the reason it can be headless, embeddable, and testable.

```
                    ┌─────────────────────┐
                    │    Domain Layer      │
                    │                     │
                    │  Pure business logic │
                    │  No I/O, no HTTP    │
                    │  No dependencies    │
                    │                     │
                    │  User.Validate()    │
                    │  Token.IsExpired()  │
                    │  Role.HasPerm()     │
                    └─────────┬───────────┘
                              │
                    ┌─────────▼───────────┐
                    │  Application Layer   │
                    │                     │
                    │  Use cases          │
                    │  Orchestration      │
                    │  Calls domain +     │
                    │  port interfaces    │
                    └──┬──────────────┬───┘
                       │              │
              ┌────────▼────┐   ┌─────▼──────────┐
              │  Port: In   │   │  Port: Out      │
              │             │   │                  │
              │ HTTP Handler│   │ user.Repository  │
              │ gRPC Handler│   │ token.Blacklist  │
              │ CLI Command │   │ jwk.Repository   │
              │ SDK function│   │ email.Sender     │
              └─────────────┘   └────────┬─────────┘
                                         │
                                ┌────────▼─────────┐
                                │  Adapters (Out)   │
                                │                   │
                                │ Postgres repos    │
                                │ Redis repos       │
                                │ In-memory repos   │
                                │ SMTP sender       │
                                │ Twilio sender     │
                                └───────────────────┘
```

### Why This Matters

| Property | Enabled by hexagonal architecture |
|----------|----------------------------------|
| **Headless** | HTTP handlers are just one adapter — swap for gRPC, CLI, or SDK |
| **Embeddable** | The Go SDK calls application services directly, skipping HTTP |
| **Testable** | Swap Postgres for in-memory repos — 791 tests run without Docker |
| **Swappable** | Replace Postgres with CockroachDB, or Redis with Memcached — zero business logic changes |
| **Multi-protocol** | Add gRPC or GraphQL alongside REST without touching domain/application layers |

---

## How Clients Integrate

### Pattern 1: Direct API Calls (Most Common)

Your frontend calls AuthCore directly. No SDK required.

```
┌─────────────┐         ┌──────────────┐         ┌─────────────┐
│  React App  │ ──API──►│   AuthCore   │ ──SQL──►│  Postgres   │
│  (browser)  │◄──JSON──│   (:8080)    │◄────────│             │
└─────────────┘         └──────────────┘         └─────────────┘
```

```javascript
// Login — just a fetch call
const resp = await fetch('https://auth.myapp.com/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', 'X-Tenant-ID': 'my-tenant' },
  body: JSON.stringify({ email, password })
});
const { data } = await resp.json();
sessionStorage.setItem('session', data.session_token);
```

### Pattern 2: OIDC Auto-Configuration (Zero SDK)

Any OIDC library in any language can auto-configure by pointing at the discovery endpoint.

```
┌──────────────────┐         ┌──────────────┐
│  Spring Boot     │ ──OIDC──│   AuthCore   │
│  (auto-config)   │◄────────│   (:8080)    │
└──────────────────┘         └──────────────┘
```

```yaml
# Spring Boot — zero AuthCore SDK needed
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: https://auth.myapp.com
          # Spring auto-discovers /.well-known/openid-configuration
          # Downloads JWKS, validates JWTs — fully automatic
```

```csharp
// ASP.NET — zero AuthCore SDK needed
builder.Services.AddAuthentication()
    .AddJwtBearer(o => o.Authority = "https://auth.myapp.com");
```

### Pattern 3: Wrapper SDK (Typed API Client)

For convenience. Available in Java, .NET, Node.js, Python.

```
┌─────────────┐    ┌──────────────┐    ┌──────────────┐
│  Your Code  │───►│  AuthCore    │───►│   AuthCore   │
│             │    │  SDK (HTTP)  │    │   Server     │
└─────────────┘    └──────────────┘    └──────────────┘
```

```python
from authcore_sdk import AuthCore
auth = AuthCore(base_url="https://auth.myapp.com", tenant_id="my-tenant")
user = auth.register("user@example.com", "secret", "Jane")
session = auth.login("user@example.com", "secret")
```

### Pattern 4: Embedded Go SDK (No Server)

AuthCore runs inside your Go application. No HTTP, no separate process.

```
┌─────────────────────────────────┐
│         Your Go App              │
│                                  │
│  auth := authcore.New(cfg, db)   │
│  auth.User.Register(ctx, req)    │  ← Direct function call
│  auth.Auth.VerifyJWT(token)      │  ← No network hop
│                                  │
│  ┌───────────────────────────┐  │
│  │  AuthCore (library mode)  │  │
│  │  Same code as server      │  │
│  │  Different entry point    │  │
│  └───────────────────────────┘  │
└─────────────────────────────────┘
```

---

## What AuthCore Does NOT Have

| Feature | Why not |
|---------|---------|
| Login page | You build it. Your design, your UX |
| Registration form | You build it. You control the fields |
| Password reset UI | You build it. Email template is yours |
| Consent screen | Not needed — you control scopes at the client level |
| Account settings page | You build it. Call `/userinfo` + update APIs |
| Admin dashboard HTML | Separate React SPA (`authcore-admin` repo) |
| Email templates | Your email service, your templates. AuthCore sends raw OTP codes |
| Hosted login page | No redirect-based login. Auth stays in YOUR app |
| Theme engine | No themes. You ARE the theme |
| Branding settings | No branding. It's YOUR brand everywhere |

---

## Comparison: Headless vs Full-Stack IAM

| Aspect | **AuthCore (Headless)** | **Keycloak (Full-Stack)** | **Auth0 (Hosted)** |
|--------|:----------------------:|:------------------------:|:------------------:|
| Login UI | You build | Built-in (FreeMarker) | Hosted page (Universal Login) |
| UX control | 100% | Theme customization | Limited CSS customization |
| Mobile | Native API calls | WebView redirect | WebView redirect |
| Image size | 15MB | 500MB+ | N/A (SaaS) |
| User sees | Your domain only | `/auth/realms/...` URL | `login.auth0.com` domain |
| A/B testing | Standard tools | Not possible | Limited |
| Branding | Zero vendor presence | "Powered by Keycloak" possible | Auth0 branding on free tier |
| Time to customize | Hours (just build forms) | Days (learn theme engine) | Hours (CSS only) |
| Time to integrate | Hours (call APIs) | Minutes (redirect-based) | Minutes (redirect-based) |

### The Tradeoff

**Full-stack IAM** gives you a working login page in 5 minutes. But customizing it to match your brand takes days, and it never feels truly "yours".

**Headless IAM** requires you to build the login UI. But you have **complete control** from day one, and it's indistinguishable from the rest of your app.

---

## Request/Response Flow

Every interaction follows the same pattern — JSON in, JSON out.

### Registration

```
Client                          AuthCore
  │                                │
  │  POST /register                │
  │  X-Tenant-ID: acme            │
  │  {email, password, name}      │
  │──────────────────────────────►│
  │                                │  → hash password (bcrypt)
  │                                │  → store user
  │                                │  → send verification OTP
  │  201 Created                   │
  │  {data: {user_id, email}}     │
  │◄──────────────────────────────│
```

### Login → Session → API Call

```
Client                          AuthCore                Your API
  │                                │                       │
  │  POST /login                   │                       │
  │  {email, password}            │                       │
  │──────────────────────────────►│                       │
  │  {session_token}              │                       │
  │◄──────────────────────────────│                       │
  │                                │                       │
  │  GET /authorize               │                       │
  │  Authorization: Bearer sess   │                       │
  │──────────────────────────────►│                       │
  │  302 → ?code=ABC              │                       │
  │◄──────────────────────────────│                       │
  │                                │                       │
  │  POST /token                   │                       │
  │  {code=ABC, verifier}         │                       │
  │──────────────────────────────►│                       │
  │  {access_token (JWT)}          │                       │
  │◄──────────────────────────────│                       │
  │                                │                       │
  │  GET /api/data                 │                       │
  │  Authorization: Bearer JWT     │                       │
  │────────────────────────────────────────────────────►│
  │                                │                       │  → verify JWT
  │                                │                       │    (JWKS cached)
  │  200 {data}                    │                       │
  │◄────────────────────────────────────────────────────│
```

### No UI Involved Anywhere

Every step is an API call. Your frontend decides:
- What the login form looks like
- Where to show errors
- How to handle MFA challenges
- What happens after login (redirect, SPA navigation, etc.)

---

## Multi-Tenant Isolation

```
┌─────────────────────────────────────────────────────────────┐
│                        AuthCore                              │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │  Tenant: acme │  │ Tenant: corp │  │ Tenant: dev  │     │
│  │               │  │              │  │              │     │
│  │ Users: 1,200  │  │ Users: 50    │  │ Users: 5     │     │
│  │ Clients: 3    │  │ Clients: 1   │  │ Clients: 1   │     │
│  │ Keys: RSA     │  │ Keys: EC     │  │ Keys: RSA    │     │
│  │ MFA: required │  │ MFA: none    │  │ MFA: optional│     │
│  │ Providers:    │  │ Providers:   │  │ Providers:   │     │
│  │  Google, SAML │  │  Azure AD    │  │  GitHub      │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
│                                                              │
│  Same binary. Same database. Isolated by tenant_id.          │
│  Thousands of tenants on a single instance.                  │
└─────────────────────────────────────────────────────────────┘
```

Resolution: `X-Tenant-ID: acme` header or subdomain (`acme.auth.myapp.com`).

---

## When to Choose Headless

**Choose AuthCore (headless) when:**
- You're building a product with custom auth UX
- You have a frontend team that owns the login experience
- You need multi-tenant SaaS with per-tenant branding
- You want auth to feel native on mobile (no WebViews)
- You want to A/B test auth flows
- You need <300MB RAM and ~15MB Docker image

**Choose full-stack IAM when:**
- You need a working login page in 5 minutes
- You don't have frontend developers
- Brand customization is "nice to have", not critical
- You need SAML IdP with a built-in login form
- You're okay with the vendor's UX paradigm
