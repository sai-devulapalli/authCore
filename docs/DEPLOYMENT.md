# AuthCore — Deployment Architecture & SDK Strategy

## Deployment Models

AuthCore can be deployed in 4 ways depending on your scale and architecture:

---

### Model 1: Standalone Service (Most Common)

```
                    ┌──────────────┐
                    │  Load Balancer │
                    │  (nginx/ALB)  │
                    └──────┬───────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
       ┌──────▼─────┐ ┌───▼──────┐ ┌──▼────────┐
       │ AuthCore-1 │ │AuthCore-2│ │AuthCore-3 │
       │  (:8080)   │ │ (:8080)  │ │ (:8080)   │
       └──────┬─────┘ └────┬─────┘ └─────┬─────┘
              │            │              │
              └────────────┼──────────────┘
                    ┌──────┴──────┐
                    │             │
              ┌─────▼────┐ ┌─────▼────┐
              │ Postgres  │ │  Redis   │
              │ (primary) │ │ (cluster)│
              └──────────┘ └──────────┘
```

**When**: Default choice for most teams.
**Scale**: 1K–1M users. Add more AuthCore instances behind load balancer.
**Infra**: 2–10 AuthCore instances + 1 Postgres + 1 Redis.
**Cost**: ~$50–200/month.

```yaml
# docker-compose.yml (production)
version: '3.8'
services:
  authcore:
    image: authcore:latest
    deploy:
      replicas: 3
    ports: ["8080:8080"]
    environment:
      AUTHCORE_ENV: production
      AUTHCORE_DATABASE_DSN: postgres://user:pass@postgres:5432/authcore?sslmode=require
      AUTHCORE_REDIS_URL: redis://redis:6379
      AUTHCORE_ADMIN_API_KEY: ${ADMIN_KEY}
      AUTHCORE_ENCRYPTION_KEY: ${ENCRYPTION_KEY}
      AUTHCORE_CORS_ORIGINS: https://myapp.com
      AUTHCORE_SMTP_HOST: smtp.sendgrid.net
      AUTHCORE_SMS_PROVIDER: twilio

  postgres:
    image: postgres:16-alpine
    volumes: ["pgdata:/var/lib/postgresql/data"]

  redis:
    image: redis:7-alpine
```

---

### Model 2: Sidecar (Kubernetes)

```
┌──────────────────────────────────────┐
│           Kubernetes Pod              │
│                                       │
│  ┌──────────┐     ┌───────────────┐  │
│  │ AuthCore │◄───►│ Your Service  │  │
│  │ (sidecar)│     │               │  │
│  │ :8080    │     │ :3000         │  │
│  │ ~15MB    │     │               │  │
│  │ <300MB   │     │               │  │
│  └──────────┘     └───────────────┘  │
│                                       │
└──────────────────────────────────────┘
         │                   │
    ┌────▼────┐        ┌────▼────┐
    │Postgres │        │  Redis  │
    │ (shared)│        │(shared) │
    └─────────┘        └─────────┘
```

**When**: Microservices in Kubernetes. Each service gets its own AuthCore sidecar.
**Why**: ~15MB image, <300MB RAM. Negligible overhead.
**Advantage**: No network hop for JWT verification — localhost only.

```yaml
# k8s deployment
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
      - name: your-service
        image: your-service:latest
        ports: [{containerPort: 3000}]

      - name: authcore
        image: authcore:latest
        ports: [{containerPort: 8080}]
        resources:
          requests: {memory: "128Mi", cpu: "100m"}
          limits: {memory: "256Mi", cpu: "500m"}
        env:
        - name: AUTHCORE_ENV
          value: production
        - name: AUTHCORE_DATABASE_DSN
          valueFrom: {secretKeyRef: {name: authcore-secrets, key: database-dsn}}
```

---

### Model 3: Edge Auth (API Gateway)

```
                    ┌──────────────┐
                    │  API Gateway  │
Internet ──────────►│ (Kong/Envoy) │
                    │              │
                    │ ┌──────────┐ │
                    │ │ AuthCore │ │  ← Plugin or sidecar in gateway
                    │ │ (verify) │ │
                    │ └──────────┘ │
                    └──────┬───────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
       ┌──────▼─────┐ ┌───▼──────┐ ┌──▼────────┐
       │ Service A  │ │Service B │ │Service C  │
       │ (orders)   │ │(payments)│ │(inventory)│
       └────────────┘ └──────────┘ └───────────┘

       All services trust JWT — no individual auth needed
```

**When**: API gateway already exists. AuthCore handles all auth at the edge.
**Advantage**: Backend services don't need any auth code — just read JWT claims.

---

### Model 4: Embedded Library (SDK — see below)

```
┌───────────────────────────────┐
│     Your Go Application       │
│                                │
│  import "github.com/authcore"  │
│                                │
│  authcore.Init(config)         │
│  router.Use(authcore.Middleware)│
│  authcore.Register(email, pass)│
│  authcore.Login(email, pass)   │
│  authcore.VerifyJWT(token)     │
│                                │
│  No separate process.          │
│  No network hop.               │
│  Just a Go library.            │
└───────────────────────────────┘
         │
    ┌────▼────┐
    │Postgres │
    └─────────┘
```

**When**: Go applications that want auth embedded, not as a separate service.
**This is the SDK model — read below.**

---

## Cloud-Specific Deployments

### AWS

```
┌─────────────────────────────────────────────┐
│                    AWS                        │
│                                               │
│  Route 53 ──► ALB ──► ECS Fargate (AuthCore) │
│                           │           │       │
│                     ┌─────▼────┐ ┌────▼─────┐ │
│                     │   RDS    │ │ElastiCache│ │
│                     │(Postgres)│ │  (Redis)  │ │
│                     └──────────┘ └──────────┘ │
│                                               │
│  SES (email) ◄── AuthCore                     │
│  SNS (SMS)   ◄── AuthCore (instead of Twilio) │
└─────────────────────────────────────────────┘
```

**Cost**: ~$80/month (t3.small Fargate + RDS db.t3.micro + ElastiCache t3.micro)

### GCP

```
Cloud Run (AuthCore) ──► Cloud SQL (Postgres) + Memorystore (Redis)
```

**Cost**: ~$50/month (pay-per-request Cloud Run)

### Azure

```
Container Apps (AuthCore) ──► Azure Database for PostgreSQL + Azure Cache for Redis
```

### Self-Hosted (Bare Metal / VPS)

```bash
# Single server — good for <10K users
docker-compose up -d    # AuthCore + Postgres + Redis
# Total RAM: ~500MB (AuthCore 256MB + Postgres 128MB + Redis 64MB)
```

---

## Can AuthCore Be an SDK?

**Yes.** The hexagonal architecture makes this straightforward. Here's how:

### Current Architecture (Service)

```
HTTP Request → Handler → Application Service → Domain → Adapter (Postgres/Redis)
```

### SDK Architecture (Library)

```
Your Code → authcore.Service.Login() → Domain → Adapter (your DB or embedded)
```

The **application services** are already pure Go with injected ports. They don't depend on HTTP. The SDK would expose these services directly.

---

### What an AuthCore SDK Would Look Like

#### Go SDK

```go
package main

import (
    "github.com/authcore/sdk"
    "github.com/authcore/sdk/postgres"
    "github.com/authcore/sdk/redis"
)

func main() {
    // Initialize with your own database
    db := postgres.Connect("postgres://...")
    cache := redis.Connect("redis://...")

    auth := sdk.New(sdk.Config{
        Issuer:        "https://myapp.com",
        EncryptionKey: "hex-encoded-32-bytes",
        SessionTTL:    24 * time.Hour,
        AccessTTL:     1 * time.Hour,
    }, db, cache)

    // Use directly in your code (no HTTP, no separate process)
    user, err := auth.Register(ctx, sdk.RegisterRequest{
        Email:    "user@example.com",
        Password: "secret",
        Name:     "User",
        TenantID: "my-tenant",
    })

    session, err := auth.Login(ctx, sdk.LoginRequest{
        Email:    "user@example.com",
        Password: "secret",
        TenantID: "my-tenant",
    })

    // Generate JWT for your APIs
    tokens, err := auth.IssueTokens(ctx, sdk.TokenRequest{
        Subject:  user.ID,
        ClientID: "my-app",
        TenantID: "my-tenant",
        Scope:    "openid profile",
    })

    // Verify JWT (no network call — uses in-memory JWKS cache)
    claims, err := auth.VerifyJWT(tokens.AccessToken)

    // Mount as HTTP middleware (optional)
    router := http.NewServeMux()
    router.Handle("/api/", auth.JWTMiddleware(yourHandler))

    // Or mount full OIDC endpoints
    auth.MountOIDCRoutes(router)  // adds /authorize, /token, /jwks, etc.
}
```

#### Node.js SDK (wrapper)

```javascript
import { AuthCore } from '@authcore/sdk';

const auth = new AuthCore({
  baseUrl: 'http://localhost:8080',  // Points to AuthCore service
  tenantId: 'my-tenant',
  clientId: 'my-app',
});

// Server-side
const user = await auth.register({ email, password, name });
const session = await auth.login({ email, password });
const tokens = await auth.exchangeCode({ code, codeVerifier });
const claims = await auth.verifyJWT(accessToken);  // Uses JWKS

// Express middleware
app.use('/api', auth.jwtMiddleware());
```

#### Python SDK (wrapper)

```python
from authcore import AuthCore

auth = AuthCore(
    base_url="http://localhost:8080",
    tenant_id="my-tenant",
    client_id="my-app",
)

# Server-side
user = auth.register(email="user@example.com", password="secret", name="User")
session = auth.login(email="user@example.com", password="secret")
claims = auth.verify_jwt(access_token)  # Uses JWKS

# FastAPI/Flask middleware
@app.middleware("http")
async def auth_middleware(request, call_next):
    claims = auth.verify_jwt(request.headers.get("Authorization"))
    request.state.user = claims
    return await call_next(request)
```

---

### SDK vs Service — Comparison

| Aspect | **SDK (embedded)** | **Service (standalone)** |
|--------|:------------------:|:------------------------:|
| Deployment | Part of your app | Separate process/container |
| Network hop | None (in-process) | 1 hop per auth call |
| Language | Go only (native), others via HTTP wrapper | Any language (HTTP API) |
| Scaling | Scales with your app | Scales independently |
| Updates | Recompile + redeploy your app | Redeploy AuthCore only |
| Multi-language | One SDK per language | One server, all languages |
| Isolation | Shares memory with your app | Fully isolated |
| Database | Shares your DB connection pool | Own connection pool |
| Best for | Go monoliths, single-service apps | Microservices, polyglot teams |

### SDK Strategy: Three Tiers

```
Tier 1: Go SDK (native)
   └── Direct access to application services
   └── No HTTP overhead
   └── Full feature parity with server
   └── Effort: Medium (extract pkg/sdk from internal/)

Tier 2: HTTP Wrapper SDKs (Node.js, Python, Java, .NET)
   └── Thin HTTP client calling AuthCore server
   └── JWT verification via cached JWKS (local, no HTTP per request)
   └── Effort: Small per language

Tier 3: OIDC Auto-Configuration (zero SDK)
   └── Any OIDC library in any language
   └── Point at /.well-known/openid-configuration
   └── Everything auto-configures
   └── Already works today
```

---

### What Needs to Change for a Go SDK

| Current (internal/) | SDK (pkg/authcore/) | Change |
|---------------------|---------------------|--------|
| `internal/application/auth/` | `pkg/authcore/auth.go` | Move from internal → exported |
| `internal/application/user/` | `pkg/authcore/user.go` | Move from internal → exported |
| `internal/domain/*` | `pkg/authcore/domain/` | Already clean, just move |
| `internal/adapter/crypto/` | `pkg/authcore/crypto/` | Already standalone |
| `internal/adapter/postgres/` | `pkg/authcore/postgres/` | Already has port interfaces |
| `cmd/authcore/main.go` | `pkg/authcore/server.go` | Extract `setupServer` as `New()` |

The hexagonal architecture means **zero refactoring of business logic** — just move packages from `internal/` to `pkg/` and export the constructors.

```
Effort estimate:
  Go SDK:      1-2 weeks (restructure packages, add godoc, publish module)
  Node.js SDK: 3-5 days (HTTP wrapper + JWT verification)
  Python SDK:  3-5 days (HTTP wrapper + JWT verification)
  Java SDK:    Not needed (Spring auto-configures via OIDC)
  .NET SDK:    Not needed (ASP.NET auto-configures via OIDC)
```

---

## Recommended Deployment by Use Case

| Use Case | Model | Why |
|----------|-------|-----|
| Startup, single app | **Standalone** (docker-compose) | Simplest, cheapest |
| Multi-tenant SaaS | **Standalone** (ECS/Cloud Run) | Shared AuthCore, isolated tenants |
| Kubernetes microservices | **Sidecar** | ~15MB, no network hop |
| API gateway (Kong/Envoy) | **Edge Auth** | Single auth point for all services |
| Go monolith | **SDK (embedded)** | No separate process needed |
| Enterprise (Java/.NET) | **Standalone** + OIDC auto-config | Zero SDK, standard protocols |
| Serverless (Lambda) | **Standalone** + JWT verification only | Lambda verifies JWT, AuthCore runs separately |

---

## High Availability Architecture

```
                        ┌──────────────┐
                        │   DNS / CDN   │
                        └──────┬───────┘
                               │
                  ┌────────────┼────────────┐
                  │                         │
          ┌───────▼───────┐        ┌───────▼───────┐
          │  Region A      │        │  Region B      │
          │                │        │                │
          │ ┌─AuthCore─┐  │        │ ┌─AuthCore─┐  │
          │ │ x3       │  │        │ │ x3       │  │
          │ └────┬─────┘  │        │ └────┬─────┘  │
          │      │        │        │      │        │
          │ ┌────▼─────┐  │        │ ┌────▼─────┐  │
          │ │Postgres   │  │◄──────►│ │Postgres   │  │
          │ │(primary)  │  │ repl.  │ │(replica)  │  │
          │ └──────────┘  │        │ └──────────┘  │
          │               │        │               │
          │ ┌──────────┐  │        │ ┌──────────┐  │
          │ │Redis      │  │◄──────►│ │Redis      │  │
          │ │(primary)  │  │ repl.  │ │(replica)  │  │
          │ └──────────┘  │        │ └──────────┘  │
          └───────────────┘        └───────────────┘

  AuthCore is stateless — any instance can handle any request.
  State lives in Postgres (durable) and Redis (ephemeral).
  Horizontal scaling: just add more AuthCore instances.
```

### Scaling Numbers

| Component | 10K users | 100K users | 1M users |
|-----------|-----------|------------|----------|
| AuthCore instances | 2 | 3-5 | 10-20 |
| Postgres | db.t3.small | db.r5.large | db.r5.xlarge + read replicas |
| Redis | cache.t3.micro | cache.r5.large | cache.r5.xlarge (cluster) |
| Estimated cost | ~$50/mo | ~$200/mo | ~$800/mo |
| Requests/sec | ~500 | ~5,000 | ~50,000 |
