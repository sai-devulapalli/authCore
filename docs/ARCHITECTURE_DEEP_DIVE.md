# AuthCore vs Keycloak vs IdentityServer vs Cognito — Architecture Deep Dive

> A detailed analysis of internals, feature trade-offs, and when each wins or loses.

---

## 0. Why Go? The Language Decision

Before comparing products, the language choice shapes everything — deployment model, performance profile, developer experience, and ecosystem. Here's why Go was chosen over Java, .NET, Node.js, Rust, and Python.

### The Candidates

| Language | IAM Precedent | Runtime | Binary | Concurrency Model |
|----------|--------------|---------|--------|--------------------|
| **Go** | None (greenfield) | Native binary | Static, ~15MB | Goroutines (M:N scheduling) |
| **Java** | Keycloak, Spring Security | JVM (HotSpot/GraalVM) | ~500MB with JRE | Threads (Project Loom for virtual threads) |
| **.NET** | IdentityServer, Duende | CLR (.NET runtime) | ~200MB with runtime | async/await + ThreadPool |
| **Node.js** | Passport.js, Auth0 actions | V8 engine | ~150MB with node_modules | Event loop (single-threaded) |
| **Rust** | None major | Native binary | ~5MB | Async (tokio) + threads |
| **Python** | Django auth, Authlib | CPython interpreter | ~200MB with venv | GIL-limited threading / asyncio |

### Why Go Won

**1. Single static binary — deploy anywhere**

```
Go:    scp authcore server:/opt/ && ./authcore     ← done
Java:  Install JRE → configure classpath → java -jar  ← 3 steps
.NET:  Install .NET runtime → dotnet run               ← 2 steps
Node:  Install Node → npm install → node index.js      ← 3 steps
```

A single `authcore` binary with zero runtime dependencies. Copy it to any Linux/macOS/Windows machine and run. No JVM, no .NET runtime, no node_modules. This is critical for:
- **Sidecar deployment** — 15MB image fits in any K8s pod
- **Edge deployment** — runs on ARM, Raspberry Pi, IoT gateways
- **Air-gapped environments** — no package manager needed

**2. Minimal resource footprint**

```
Idle memory comparison:
  Go (AuthCore):     ~50MB
  Java (Keycloak):   ~512MB (JVM heap + metaspace)
  .NET (Duende):     ~200MB (CLR + JIT)
  Node.js:           ~80MB (V8 heap)

Docker image:
  Go:    15MB  (distroless/static)
  Java:  500MB (JRE + dependencies)
  .NET:  200MB (.NET runtime + app)
  Node:  150MB (node + node_modules)
```

For a multi-tenant IAM service that may run as a sidecar alongside every microservice, memory matters. 50MB idle vs 512MB is the difference between deploying 100 sidecars on a single node vs 10.

**3. Goroutine concurrency — perfect for auth workloads**

Auth workloads are I/O-bound: accept HTTP request → query database → hash password → sign JWT → respond. Go's goroutines handle this naturally:

```go
// Each HTTP request gets its own goroutine (~4KB stack)
// 10,000 concurrent connections = ~40MB of goroutine stacks
// vs Java: 10,000 threads = ~10GB of thread stacks (1MB each)

func (h *Handler) HandleLogin(w http.ResponseWriter, r *http.Request) {
    user, err := h.repo.GetByEmail(ctx, email)  // blocks goroutine, not OS thread
    if err != nil { ... }
    hash := bcrypt.CompareHashAndPassword(...)   // CPU-bound, runs on OS thread
    token := h.signer.Sign(claims)               // fast
    httputil.WriteJSON(w, 200, token)
}
```

Go's scheduler multiplexes thousands of goroutines onto a small number of OS threads. No thread pool tuning, no async/await boilerplate, no callback hell.

**4. stdlib crypto — no third-party security dependencies**

```go
// AuthCore's JWT signing uses ONLY Go stdlib:
import (
    "crypto/rsa"
    "crypto/ecdsa"
    "crypto/sha256"
    "crypto/x509"
    "encoding/base64"
)
// Zero third-party JWT libraries
// Zero third-party OIDC libraries
// Every crypto operation is Go stdlib — audited, maintained by the Go team
```

In security-critical code, every dependency is a risk. Java IAM servers typically depend on:
- Nimbus JOSE+JWT
- Bouncy Castle
- Apache HttpClient
- Jackson JSON

Each is a potential CVE vector. AuthCore depends on Go's stdlib crypto (maintained by Google's security team) plus exactly 3 external packages: `env` (config), `testify` (testing), `x/crypto` (bcrypt). That's it.

**5. Compilation speed + type safety**

```
Full build time:
  Go:    ~5 seconds (AuthCore, 268 files)
  Java:  ~30-60 seconds (Keycloak, thousands of files)
  .NET:  ~10-20 seconds (typical project)
  Rust:  ~2-5 minutes (fresh build)

Type safety:
  Go:    Static types, compile-time interface checks
  Java:  Static types, generics
  .NET:  Static types, generics
  Node:  Dynamic (TypeScript adds types but not enforced at runtime)
  Python: Dynamic (type hints are optional, not enforced)
```

Go compiles fast enough for the edit-compile-test loop to feel instant. Static typing catches interface mismatches at compile time — if a Postgres repo doesn't implement `user.Repository`, the build fails immediately.

**6. Hexagonal architecture fits Go's interface system**

```go
// Port (domain layer — no implementation)
type UserRepository interface {
    Create(ctx context.Context, user User) error
    GetByEmail(ctx context.Context, email, tenantID string) (User, error)
}

// Adapter 1: Postgres (production)
type PostgresUserRepo struct{ db *sql.DB }
func (r *PostgresUserRepo) Create(ctx context.Context, user User) error { ... }

// Adapter 2: In-memory (testing)
type InMemoryUserRepo struct{ users map[string]User }
func (r *InMemoryUserRepo) Create(ctx context.Context, user User) error { ... }

// Both satisfy the interface — swappable at compile time
var _ UserRepository = (*PostgresUserRepo)(nil)    // compile-time check
var _ UserRepository = (*InMemoryUserRepo)(nil)     // compile-time check
```

Go's implicit interface satisfaction (no `implements` keyword) makes hexagonal architecture natural. Any struct that has the right methods automatically satisfies the interface. This is why AuthCore has 20 in-memory repos and 7 Postgres repos — they're interchangeable without any framework.

### Why Not the Others

**Why not Java?**

| Consideration | Java | Go | Verdict |
|--------------|------|-----|---------|
| JVM startup | 10-30 seconds | <1 second | Go wins for sidecar/edge |
| Memory | 512MB+ minimum | 50MB idle | Go wins by 10x |
| Docker image | 500MB | 15MB | Go wins by 33x |
| Ecosystem | Massive (Spring, Quarkus) | Smaller but sufficient | Java wins for ecosystem |
| Crypto libraries | Bouncy Castle (third-party) | stdlib (built-in) | Go wins for security |
| Concurrency | Thread pools / virtual threads | Goroutines (native) | Go wins for simplicity |
| Build time | 30-60 seconds | 5 seconds | Go wins by 10x |
| Deployment | JRE required | Single binary | Go wins |

Java was rejected primarily for **weight**. An IAM sidecar that uses 512MB RAM and takes 30 seconds to start is not viable for edge/sidecar deployment. Keycloak already exists in Java — there's no point building a lighter Keycloak in the same language.

**Why not .NET?**

| Consideration | .NET | Go | Verdict |
|--------------|------|-----|---------|
| Cross-platform | Good (since .NET 6) | Excellent (native compilation) | Tie |
| Runtime | CLR required (~200MB) | None (static binary) | Go wins |
| Linux-native feel | Good but Windows heritage | Born for Linux/containers | Go wins slightly |
| IAM precedent | IdentityServer/Duende | None | .NET wins |
| License | MIT (.NET runtime) | BSD (Go) | Tie |

.NET was rejected because it still carries **runtime weight** and has a Windows-centric heritage. IdentityServer already owns the "embedded .NET auth" space — competing there makes no sense.

**Why not Node.js?**

| Consideration | Node.js | Go | Verdict |
|--------------|---------|-----|---------|
| Single-threaded event loop | Bottleneck on CPU (bcrypt) | Multi-core native | Go wins |
| Type safety | TypeScript (optional) | Built-in | Go wins |
| Dependency count | 100s of npm packages | 3 external deps | Go wins massively |
| node_modules | ~150MB for typical project | 0 (compiled in) | Go wins |
| bcrypt performance | Blocks event loop or uses worker threads | Runs on goroutine, OS thread handles CPU | Go wins |

Node.js was rejected because auth is **CPU-intensive** (bcrypt hashing, JWT signing). Node's single-threaded event loop becomes a bottleneck under load. Also, the npm dependency tree is a security nightmare for auth-critical code.

**Why not Rust?**

| Consideration | Rust | Go | Verdict |
|--------------|------|-----|---------|
| Binary size | ~5MB | ~15MB | Rust wins slightly |
| Performance | Faster (no GC) | Fast enough (GC pauses <1ms) | Rust wins slightly |
| Safety | Memory-safe, no GC | Memory-safe, GC | Tie (both safe) |
| Development speed | Slow (borrow checker, steep learning curve) | Fast (simple language, fast compilation) | Go wins significantly |
| Ecosystem maturity | Young for web services | Mature (net/http, database/sql) | Go wins |
| Hiring | Very hard to find Rust developers | Easy to find Go developers | Go wins |

Rust was tempting for the performance edge but rejected for **development velocity**. AuthCore was built iteratively (12 modules, 268 files, 812 tests) in a short timeframe. Rust's borrow checker and steeper learning curve would have slowed development by 2-3x for marginal performance gains that don't matter in I/O-bound auth workloads.

**Why not Python?**

Python was never a serious candidate. Auth servers need:
- High concurrency (GIL prevents this)
- Fast crypto operations (CPython is slow)
- Type safety (dynamic typing is risky for security code)
- Small deployment (Python + venv = 200MB+)

Python is excellent for SDKs/clients, not for the server itself.

### The Result

| Metric | AuthCore (Go) |
|--------|---------------|
| Binary | 15MB static, zero dependencies |
| Docker image | 15MB (distroless) |
| Idle RAM | ~50MB |
| Startup | <1 second |
| Build | ~5 seconds |
| External deps | 3 (env, testify, x/crypto) + go-webauthn |
| Crypto | 100% stdlib |
| Concurrency | Goroutines (thousands of concurrent requests, ~4KB each) |
| Files | 268 Go files, 812 tests |
| Coverage | 80%+ coverage + 141 E2E |

Go was chosen because AuthCore needed to be **small enough to be a sidecar, fast enough for auth workloads, simple enough to audit, and safe enough for security-critical code**. No other language satisfies all four constraints simultaneously.

---

## 1. Architectural Philosophy

### AuthCore — Hexagonal, Headless, Go

```
Design: Ports & Adapters (hexagonal)
Language: Go 1.25
Binary: Single static binary, ~15MB Docker image
State: Stateless HTTP server + external Postgres/Redis
UI: None — pure API. You build the frontend.
```

**Core principle:** The domain layer has zero dependencies on HTTP, databases, or any infrastructure. Business logic is framework-free Go code. Adapters (Postgres, Redis, HTTP handlers) are interchangeable.

**Pros:**
- Tiny footprint — runs on a Raspberry Pi, perfect as K8s sidecar
- Every line is auditable — ~249 Go files, no generated code, no magic
- 80%+ test coverage + 141 E2E tests — confidence in correctness
- Embeddable — the Go SDK runs AuthCore as a library, zero network hop
- Multi-tenant by design — tenant_id on every table, not bolted on
- Fast compilation — full build in ~5 seconds

**Cons:**
- No production deployments yet — zero battle scars
- No security audit — untested against real attackers
- Headless means YOU build every UI screen
- Go-only for the embedded SDK — other languages need HTTP
- Small community (single developer) — no ecosystem of plugins

---

### Keycloak — Full-Stack, Java, Batteries Included

```
Design: Monolithic + SPI plugin system
Language: Java (Quarkus since v20, formerly WildFly)
Binary: ~500MB Docker image, requires JVM
State: Infinispan cache (distributed) + database
UI: Full admin console + themed login pages
```

**Core principle:** Everything out of the box. Login pages, admin console, user federation, protocol support, themes — all built in. Extend via Java SPI plugins.

**Pros:**
- Production-proven — 10+ years, thousands of deployments, CNCF incubating
- SAML 2.0 + LDAP + Kerberos — enterprise-ready day one
- Beautiful admin console — manage everything via UI
- Extensive SPI system — Java plugins for custom authenticators, user storage, protocol mappers
- Active security team — CVEs are found and fixed quickly
- Realm export/import — easy backup and migration
- Infinispan clustering — built-in distributed caching

**Cons:**
- Heavy — 512MB-2GB RAM typical. JVM startup time 10-30 seconds
- Complex clustering — Infinispan configuration is notoriously difficult
- Realm overhead — each tenant (realm) duplicates significant config in memory
- Theme engine limitations — FreeMarker templates are powerful but complex
- Upgrade pain — major version upgrades often break custom SPIs and themes
- No embedded mode — always a separate server
- Java skills required for any customization

---

### IdentityServer (Duende) — .NET Library, Embedded

```
Design: Library/middleware in your ASP.NET app
Language: C# (.NET 6+)
Binary: NuGet package, runs inside your app
State: Your app's database (via EF Core)
UI: None built-in (you build Razor Pages)
```

**Core principle:** Auth IS your application. Not a separate service — a library inside your .NET app. You own the data layer, the UI, and the token pipeline.

**Pros:**
- Deep .NET integration — DI, middleware, EF Core, Razor Pages all native
- Full control of the data layer — use your existing database
- Customizable token pipeline — `IProfileService`, `IResourceOwnerPasswordValidator`
- No separate deployment — auth is part of your app
- Protocol-correct — originally written by the OAuth spec implementors

**Cons:**
- **.NET only** — if you're not a .NET shop, it's irrelevant
- **Commercial license** — $1,500/yr starter, $12,000/yr enterprise. Free for dev/OSS only
- **No admin API** — no built-in management endpoints. You build everything
- **No admin UI** — Duende sells one separately
- **No user management** — bring your own user store, registration, login
- **No MFA** — bring your own
- **No social login** — you wire up `IAuthenticationHandler` yourself
- Single-language lock-in — can't use from Java, Python, Go

---

### AWS Cognito — Managed SaaS, Zero Infrastructure

```
Design: Fully managed AWS service
Language: N/A (black box)
Binary: N/A (SaaS)
State: DynamoDB (managed by AWS)
UI: Hosted UI (customizable CSS) or your own
```

**Core principle:** Zero infrastructure management. AWS handles servers, scaling, patching, security. You configure via Console/SDK and call APIs.

**Pros:**
- Zero ops — no servers, no databases, no patches
- SOC2/HIPAA compliant out of the box
- Free tier — 50K MAU at $0
- Lambda triggers — customize every auth step with serverless functions
- Hosted UI — working login page in minutes
- AWS integration — IAM, SES, SNS, CloudWatch all native

**Cons:**
- **Vendor lock-in** — deeply tied to AWS. Migration is painful
- **Expensive at scale** — $5,500/mo at 1M MAU, $25,500 at 10M
- **Limited customization** — Hosted UI is CSS-only, not truly custom
- **No GitHub/Microsoft social login** — only Google, Facebook, Apple, SAML
- **No token introspection** — can't introspect tokens server-side
- **No device code flow** — no IoT/TV auth
- **User Pool limits** — 1,000 pools per AWS account
- **Cold start latency** — Lambda triggers add 100-500ms on first call
- **No self-hosting** — if AWS goes down, your auth goes down

---

## 2. Feature-by-Feature Deep Dive

### 2.1 OAuth 2.0 / OIDC Protocol Layer

| Capability | AuthCore | Keycloak | IdentityServer | Cognito | Notes |
|-----------|----------|----------|----------------|---------|-------|
| Auth Code + PKCE | Full | Full | Full | Full | Table stakes |
| Client Credentials | Full | Full | Full | Full | M2M auth |
| Refresh Token Rotation | Family tracking + replay detection | Yes | Yes | Yes | AuthCore's replay detection revokes entire family |
| Device Code (RFC 8628) | Full | Full | Add-on | **No** | IoT/TV apps need this |
| Token Introspection | Full | Full | Full | **No** | Cognito forces local JWT validation only |
| Token Revocation | JTI blacklist + refresh revoke | Full | Full | API only | AuthCore has both access + refresh revocation |
| SAML 2.0 | Yes (SP mode, crewjam/saml) | Full IdP + SP | Add-on | SP only | AuthCore supports SP; IdP mode not yet |
| PAR | **No** | Yes | Yes | **No** | Pushed Authorization Requests (security improvement) |
| CIBA | **No** | Yes | **No** | **No** | Backchannel auth (rare use case) |

**Winner:** Keycloak (most complete). AuthCore is close but missing SAML.

**AuthCore's edge:** Refresh token replay detection with family-wide revocation — if a rotated token is reused, the entire chain is invalidated. This prevents token theft attacks.

---

### 2.2 Multi-Factor Authentication

| Capability | AuthCore | Keycloak | IdentityServer | Cognito |
|-----------|----------|----------|----------------|---------|
| TOTP (authenticator apps) | RFC 6238, ±1 window drift | Full | Custom | Full |
| WebAuthn/FIDO2 | go-webauthn library, 4 endpoints | Full | Custom | **No** |
| SMS OTP | Twilio + console sender | SPI-based | **No** | SNS |
| Email OTP | SMTP + console sender | Built-in | **No** | SES |
| Recovery Codes | **No** | Yes | **No** | **No** |
| Per-tenant MFA policy | required/optional/none per tenant | Per-realm | Custom | Per-pool |
| MFA challenge in /authorize | Intercepts auth flow, returns challenge | Seamless (built into login page) | Custom | Managed |
| Adaptive MFA | **Roadmap** | Via extensions | **No** | Advanced Security ($0.05/MAU) |

**Winner:** Keycloak (most options). AuthCore is strong with TOTP + WebAuthn + OTP.

**AuthCore's edge:** MFA is API-driven. The `/authorize` endpoint returns a challenge JSON when MFA is required — your frontend handles the UX. No redirect to a separate MFA page. No iframes.

**AuthCore's gap:** No recovery codes (users locked out if they lose authenticator). No adaptive MFA (risk-based — on roadmap).

---

### 2.3 Multi-Tenancy

| Capability | AuthCore | Keycloak | IdentityServer | Cognito |
|-----------|----------|----------|----------------|---------|
| Model | tenant_id column, same DB | Realm = separate config | Manual | User Pool = separate entity |
| Max tenants | Thousands (single DB query) | Hundreds (JVM memory per realm) | Depends | 1,000 per account |
| Tenant creation | API call (<1ms) | API/UI (seconds, memory allocation) | Code change | API call |
| Per-tenant keys | Automatic (RSA/EC, auto-rotation) | Automatic | Manual | Managed |
| Per-tenant MFA | Yes | Yes | Manual | Yes |
| Per-tenant providers | Yes | Yes | Manual | Yes |
| Isolation | Application-level (WHERE tenant_id=) | Full realm isolation | N/A | Full pool isolation |
| Cross-tenant SSO | **No** | Yes (realm-to-realm) | Manual | **No** |

**Winner:** AuthCore for scale (thousands of tenants, lightweight). Keycloak for features (cross-tenant SSO).

**AuthCore's edge:** Creating a tenant is a simple INSERT — no memory allocation, no config duplication. A single AuthCore instance can serve thousands of tenants because they share the same database tables, filtered by tenant_id.

**AuthCore's gap:** Application-level isolation only. DB-level RLS is on Tier 1 roadmap. No cross-tenant SSO.

---

### 2.4 User Management

| Capability | AuthCore | Keycloak | IdentityServer | Cognito |
|-----------|----------|----------|----------------|---------|
| Registration | POST /register (API) | UI + API | **None** (BYO) | UI + API + Hosted |
| Login | POST /login (API) | UI + API + themes | **None** (BYO) | UI + API + Hosted |
| Password hashing | bcrypt cost 12 | pbkdf2/bcrypt/argon2 | Configurable | SRP |
| Email verification | Auto-OTP on register | Built-in link | **None** | Built-in |
| Password reset | OTP-based | Email link | **None** | Email/SMS |
| Phone support | Phone field + SMS OTP | Phone field | **None** | Phone + SNS |
| User search/list | **Not yet** (roadmap) | Full | Depends on store | API |
| Self-service profile | **No** | Full (change password, manage sessions, devices) | **None** | Limited |
| User federation | **No** | LDAP, AD, Kerberos | **None** | SAML federation |
| Import/export | **No** | JSON realm export | **None** | CSV import |

**Winner:** Keycloak (most complete). Cognito for managed simplicity.

**AuthCore's edge:** API-only registration/login means your frontend controls the entire UX. Password hashing uses bcrypt at cost 12 (strong but fast enough).

**AuthCore's gap:** No user list/search endpoint (SCIM on roadmap). No self-service account management. No LDAP federation.

---

### 2.5 Administration

| Capability | AuthCore | Keycloak | IdentityServer | Cognito |
|-----------|----------|----------|----------------|---------|
| Admin UI | Separate React SPA (authcore-admin) | Beautiful built-in console | Sold separately by Duende | AWS Console |
| Admin API | REST (47 endpoints, JWT-based admin auth + API key) | REST + Java Client + CLI | **None** | AWS SDK/CLI |
| Admin CLI | **Roadmap** | kcadm.sh (powerful) | dotnet CLI | AWS CLI |
| Admin auth | API key (JWT-based on roadmap) | Username/password + optional 2FA | N/A | IAM policies |
| Admin roles | **Roadmap** (super_admin, tenant_admin, readonly, auditor) | Fine-grained admin permissions | N/A | IAM policies |
| Audit logging | 25+ event types, query API | Admin events + login events | **No** | CloudTrail |

**Winner:** Keycloak (built-in console + CLI + fine-grained admin roles).

**AuthCore's edge:** 30+ REST management endpoints are fully functional. Separate admin UI means it can be deployed independently (CDN, Vercel). Audit logging with query API gives full visibility.

**AuthCore's gap:** API key auth is single-level (no scoping). JWT-based admin roles with tenant_admin scoping is on Tier 1 roadmap.

---

### 2.6 Security Posture

| Capability | AuthCore | Keycloak | IdentityServer | Cognito |
|-----------|----------|----------|----------------|---------|
| Security audit history | **None** | 10+ years of CVE responses | Duende advisories | AWS compliance |
| Encryption at rest | AES-256-GCM | Vault integration | DPAPI/Azure KV | KMS |
| Rate limiting | Per-IP sliding window | Brute force detection + IP blocking | **No** | WAF |
| CORS | Global (per-client on roadmap) | Per-client | Per-client | Per-pool |
| Constant-time comparison | Yes (admin auth) | Yes | Yes | N/A |
| User enumeration prevention | Yes (same error for all) | Configurable | Custom | Yes |
| Token rotation | Family tracking + replay detection | Yes | Yes | Yes |
| mTLS | Client certificate verification | Full | Full | **No** |
| CSP headers | **No** (roadmap) | Yes | Custom | N/A |
| DB-level isolation | **No** (roadmap — Postgres RLS) | Realm-level | N/A | DynamoDB |

**Winner:** Cognito (compliance certifications). Keycloak (battle-tested security).

**AuthCore's risk:** No security audit means unknown vulnerabilities. Mitigated by: 80%+ test coverage, hexagonal architecture (small attack surface), stdlib crypto (no third-party JWT libraries), and open-source review.

---

### 2.7 Operational Overhead

| Metric | AuthCore | Keycloak | IdentityServer | Cognito |
|--------|----------|----------|----------------|---------|
| Docker image | 15MB | 500MB+ | N/A | N/A |
| RAM (idle) | ~50MB | ~512MB | ~200MB | N/A |
| RAM (1K concurrent) | ~150MB | ~1GB | ~400MB | N/A |
| Startup time | <1 second | 10-30 seconds | 2-5 seconds | N/A |
| Horizontal scaling | Stateless, add instances | Infinispan clustering (complex) | Depends on host | Auto |
| Database | Postgres (12 migrations) | Postgres/MySQL/Oracle (100+ migrations) | Any via EF Core | Managed |
| Config complexity | 23 env vars | Hundreds of realm settings | .NET DI config | Console clicks |
| Upgrade process | Replace binary | Re-test themes + SPIs | NuGet update | Managed |

**Winner:** AuthCore (smallest, fastest, simplest). Cognito (zero ops).

**AuthCore's edge:** A single AuthCore binary + Postgres + Redis uses ~500MB total RAM. Keycloak alone uses that much. Startup in <1 second vs 10-30 seconds for JVM warmup.

---

### 2.8 Extensibility

| Extension | AuthCore | Keycloak | IdentityServer | Cognito |
|----------|----------|----------|----------------|---------|
| Custom authenticator | Implement Go interface | Java SPI (hot-deploy) | .NET middleware | Lambda |
| Custom user store | `user.Repository` port | User Federation SPI | `IUserStore` | Lambda |
| Custom claims | Modify `Claims` struct | Protocol mappers (UI) | `IProfileService` | Lambda |
| Custom provider | `OAuthClient` interface | IdP SPI | `IAuthenticationHandler` | OIDC only |
| Plugin hot-reload | **No** (compile-time) | **Yes** (runtime JAR) | **No** (compile-time) | **Yes** (Lambda) |
| Extension language | Go only | Java only | C# only | Any (Lambda) |
| Webhooks | **Roadmap** | Admin events + SPI | **No** | Lambda triggers |

**Winner:** Keycloak (hot-deploy Java SPIs, most extension points). Cognito (any language via Lambda).

**AuthCore's trade-off:** Compile-time extensibility via Go interfaces. Safer (type-checked) but requires recompilation. No runtime plugin loading.

---

## 3. Cost at Scale

| MAU | AuthCore | Keycloak | IdentityServer | Cognito |
|-----|----------|----------|----------------|---------|
| 1K | $15/mo | $30/mo | $150/mo | $5/mo |
| 10K | $20/mo | $50/mo | $155/mo | $55/mo |
| 100K | $30/mo | $100/mo | $175/mo | $550/mo |
| 1M | $50/mo | $200/mo | $1,100/mo | $5,500/mo |
| 10M | $100/mo | $400/mo | $1,200/mo | $25,500/mo |

**Cheapest at scale:** AuthCore and Keycloak (infrastructure-only cost, no per-MAU fees).

**Most expensive:** Cognito at scale ($0.0055/MAU after 50K free tier). IdentityServer has fixed license cost regardless of scale.

---

## 4. Summary: Strengths & Weaknesses

### AuthCore

| Strength | Weakness |
|----------|----------|
| Tiny footprint (15MB, <300MB RAM) | No production track record |
| Headless — total UX control | No SAML IdP mode (SP done) |
| Native multi-tenancy (thousands) | No security audit |
| Embeddable Go SDK | Go-only for embedded mode |
| Automatic key rotation + cleanup | No LDAP federation |
| 80%+ coverage + 141 E2E tests | No admin CLI (roadmap) |
| 5 language SDKs | No Prometheus metrics |

### Keycloak

| Strength | Weakness |
|----------|----------|
| Battle-tested (10+ years) | Heavy (500MB+, 512MB-2GB RAM) |
| SAML + LDAP + Kerberos | Complex clustering (Infinispan) |
| Beautiful admin console | Upgrade breakage (themes, SPIs) |
| Hot-deploy Java plugins | Realm overhead (memory per tenant) |
| CNCF incubating | 10-30 second startup |

### IdentityServer

| Strength | Weakness |
|----------|----------|
| Deep .NET integration | .NET only |
| Full token pipeline control | Commercial license ($1,500+/yr) |
| Embedded in your app | No admin API/UI |
| Protocol-correct implementation | No user management |

### Cognito

| Strength | Weakness |
|----------|----------|
| Zero ops (fully managed) | Vendor lock-in (AWS) |
| SOC2/HIPAA compliant | Expensive at scale |
| Free 50K MAU tier | Limited customization |
| Lambda extensibility | No GitHub/Microsoft social login |
| AWS ecosystem integration | No token introspection |

---

## 5. Decision Matrix

| If you need... | Choose |
|---------------|--------|
| Custom login UX, multi-tenant SaaS | **AuthCore** |
| Production-ready with SAML + LDAP now | **Keycloak** |
| Embedded auth in .NET app | **IdentityServer** |
| Zero infrastructure, AWS-native | **Cognito** |
| Smallest possible deployment | **AuthCore** (15MB) |
| Battle-tested security | **Keycloak** (10+ years) |
| Cheapest at 1M+ users | **AuthCore** or **Keycloak** |
| Compliance certifications | **Cognito** (SOC2/HIPAA) |
| WebAuthn + TOTP + OTP | **AuthCore** or **Keycloak** |
| Any-language extensibility | **Cognito** (Lambda) |
| Embeddable library mode | **AuthCore** (Go SDK) or **IdentityServer** (.NET) |

---

## 6. Who Should NOT Use AuthCore

AuthCore is not the right choice for everyone. Here are the scenarios where you should use something else — and what to use instead.

### You need SAML 2.0 today

**Scenario:** Your enterprise customers use Okta, Azure AD, or ADFS and require SAML SSO for employee login. Their IT department won't approve OIDC-only providers.

**Problem:** AuthCore has no SAML support (Tier 2 roadmap — weeks away, not available today).

**Use instead:** Keycloak (full SAML IdP + SP) or Cognito (SAML SP).

---

### You need production auth in under an hour

**Scenario:** You're building an MVP, demo, or hackathon project. You need login working today — not tomorrow. You don't have time to build login/register UI screens.

**Problem:** AuthCore is headless — you must build every UI screen yourself. No hosted login page, no pre-built forms, no redirect-based login flow.

**Use instead:** Auth0 (hosted login page in 10 minutes), Cognito (Hosted UI), or Keycloak (themed login pages out of the box).

---

### You need compliance certifications right now

**Scenario:** Your customer's procurement team requires SOC2 Type II, HIPAA BAA, or FedRAMP certification. They need a signed compliance report before signing the contract.

**Problem:** AuthCore has zero compliance certifications and no security audit history. No CVE track record. Built by a single developer.

**Use instead:** Cognito (SOC2, HIPAA, FedRAMP), Auth0 (SOC2, HIPAA), or Keycloak with Red Hat SSO (FIPS 140-2).

---

### You don't have frontend developers

**Scenario:** Your team is backend-only (Java, .NET, Python). Nobody knows React/Vue/HTML. You need auth but can't build the UI.

**Problem:** Headless = you build the UI. If you can't build forms, buttons, and error handling, AuthCore gives you nothing visible to users.

**Use instead:** Keycloak (full admin console + themed login pages — zero frontend code needed), Cognito (Hosted UI), or Auth0 (Universal Login).

---

### You need LDAP / Active Directory federation

**Scenario:** Your company has 10,000 employees in Active Directory. Users must log in with their corporate AD credentials. No migration — AD is the source of truth.

**Problem:** AuthCore has no LDAP or AD federation. Users must be in AuthCore's database.

**Use instead:** Keycloak (LDAP + AD + Kerberos federation built-in), or Azure AD / Entra ID directly.

---

### You're locked into a non-Go ecosystem

**Scenario:** Your entire platform is Java Spring Boot or .NET. You want auth embedded in your app process, not as a separate service. Your team doesn't know Go.

**Problem:** The embedded Go SDK only works in Go applications. For Java/.NET, AuthCore runs as a separate HTTP service — adding a network hop and operational complexity.

**Use instead:** Spring Security (Java, embedded), IdentityServer/Duende (.NET, embedded), or Keycloak (Java, can run as sidecar).

---

### You need a battle-tested security track record

**Scenario:** You're building for banking, healthcare, or government. Your security team requires an auth solution with published CVE history, penetration test reports, and a dedicated security response team.

**Problem:** AuthCore has zero production deployments, zero published CVEs (because none have been looked for), no penetration test, and a single maintainer.

**Use instead:** Keycloak (10+ years, CNCF, active security team), Auth0 (dedicated security team, bug bounty program), or Cognito (AWS security team).

---

### You need real-time user management UI for non-technical admins

**Scenario:** Your customer success team needs to manage users — reset passwords, lock accounts, view login history — through a polished admin dashboard. They're not developers.

**Problem:** AuthCore's admin UI (`authcore-admin`) is functional but basic. It covers tenant/client/role CRUD and audit logs. There's no user management page, no account lock/unlock, no session viewer, no "reset user password" button.

**Use instead:** Keycloak (polished admin console with full user management), Auth0 (beautiful dashboard), or Cognito (AWS Console).

---

### You need more than 5 social login providers

**Scenario:** Your app needs Facebook, Twitter/X, LinkedIn, WeChat, Line, and Spotify login. Breadth of social providers matters.

**Problem:** AuthCore supports 6 provider types (Google, GitHub, Microsoft, Apple, generic OIDC, generic OAuth2). No Facebook, Twitter, LinkedIn, or regional providers.

**Use instead:** Auth0 (50+ social connections), Keycloak (20+ built-in + custom SPI), or Firebase Auth (broad social support).

---

### Compliance in Sidecar Mode

When AuthCore runs as a **sidecar** (same pod/host as your app), compliance certifications are **your app's responsibility**, not AuthCore's:

```
┌──────────────────────────────────────┐
│      Your App (SOC2/HIPAA certified) │
│                                       │
│  ┌──────────┐     ┌───────────────┐  │
│  │ AuthCore │◄───►│ Your Service  │  │
│  │ (sidecar)│     │               │  │
│  └──────────┘     └───────────────┘  │
│                                       │
│  YOUR infrastructure = YOUR certs     │
└──────────────────────────────────────┘
```

| Concern | Who owns it? | Why |
|---------|-------------|-----|
| SOC2/HIPAA certification | **Your app** | AuthCore is a component inside your certified infra |
| TLS termination | **Your infra** | Load balancer/nginx handles TLS |
| Encryption at rest | **Your DB** | RDS/EBS encryption — your config |
| Penetration test | **Your app scope** | AuthCore tested as part of your pentest |
| Network isolation | **Your infra** | VPC, security groups — your setup |
| Backup/DR | **Your infra** | DB snapshots — your ops |

AuthCore provides the **building blocks** your compliance auditor needs:
- Audit logging (tamper-proof, 25+ events, auto-wired)
- Encryption at rest (AES-256-GCM)
- JWT signature verification (RS256/ES256)
- Refresh token hashing (SHA-256)
- Row-Level Security on all tenant tables
- RBAC with JWT claims
- Consent fields on User entity
- GDPR right-to-erasure (HardDelete)
- Admin auth with role-based access (super_admin, tenant_admin, readonly, auditor)

**The "no compliance certifications" gap only applies if you sell AuthCore as a standalone SaaS (like Auth0). As a sidecar or embedded library, it inherits your app's compliance posture** — just like bcrypt, PostgreSQL, or any other library doesn't need separate certification.

---

### Summary: Use AuthCore When...

| Your situation | AuthCore? | Better alternative |
|---------------|-----------|-------------------|
| Building custom auth UX for SaaS | **Yes** | — |
| Sidecar in your certified infrastructure | **Yes** | — (compliance is on your app) |
| Need SAML IdP mode (not just SP) | No (SP only) | Keycloak |
| Need login page in 1 hour | No | Auth0, Cognito |
| Need standalone SaaS with own SOC2 cert | No | Cognito, Auth0 |
| No frontend developers on team | No | Keycloak |
| Corporate LDAP/AD is source of truth | No | Keycloak |
| All-Java or all-.NET shop wanting embedded auth | No | Spring Security, Duende |
| Bank/government requiring CVE track record | No | Keycloak, Auth0 |
| Non-technical admins managing users daily | No | Keycloak, Auth0 |
| Need 20+ social login providers | No | Auth0 |
| Multi-tenant SaaS, <300MB RAM, custom UX | **Yes** | — |
| Go team wanting embedded auth library | **Yes** | — |
| Edge/sidecar deployment (15MB image) | **Yes** | — |
