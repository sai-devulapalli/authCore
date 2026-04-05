# AuthPlex

**Headless Identity & Access Management Engine**

AuthPlex is a lightweight, multi-tenant IAM engine that provides OIDC/OAuth 2.0 authentication and authorization for any tech stack. No UI — pure API. ~20MB Docker image. 720 tests. 85% coverage.

## Quick Start

```bash
make build && ./bin/authplex       # In-memory mode (development)
```

```bash
# Production (Postgres + Redis)
AUTHPLEX_ENV=production \
AUTHPLEX_DATABASE_DSN="postgres://..." \
AUTHPLEX_REDIS_URL="redis://..." \
AUTHPLEX_ADMIN_API_KEY="your-key" \
./bin/authplex
```

## What It Does

| Feature | Status |
|---------|--------|
| OIDC Discovery + JWKS | Done |
| Auth Code + PKCE | Done |
| All 5 OAuth Grant Types | Done |
| Token Revocation + Introspection | Done |
| Multi-Tenancy (header/domain) | Done |
| User Registration + Login | Done |
| Email + SMS OTP Login | Done |
| Password Reset via OTP | Done |
| Social Login (Google, GitHub, Microsoft, Apple) | Done |
| TOTP MFA with per-tenant policy | Done |
| Client Registry with enforcement | Done |
| Rate Limiting | Done |
| AES-256-GCM Encryption at Rest | Done |
| RBAC (roles + permissions in JWT) | Done |
| Audit Logging (25+ event types) | Done |
| OpenTelemetry Tracing | Done |
| mTLS for M2M | Done |
| Postgres + Redis persistence | Done |
| Go SDK (embeddable library) | Done |
| SDKs: Java, .NET, Node.js, Python | Done |

## Endpoints (35+)

```
OIDC/OAuth:     /.well-known/openid-configuration  /jwks  /authorize  /token
                /device/authorize  /revoke  /introspect  /callback
User Auth:      /register  /login  /logout  /userinfo
OTP:            /otp/request  /otp/verify  /password/reset
MFA:            /mfa/totp/enroll  /mfa/totp/confirm  /mfa/verify
RBAC:           /tenants/{id}/roles  /tenants/{id}/users/{uid}/roles
                /tenants/{id}/users/{uid}/permissions
Audit:          /tenants/{id}/audit
Management:     /tenants  /tenants/{id}  /tenants/{id}/clients  /tenants/{id}/providers
Health:         /health
```

---

## Client Integration

AuthPlex is **headless** — any client in any language integrates via standard OIDC/OAuth 2.0. The OIDC discovery endpoint auto-configures most libraries.

### Setup (one-time, via Management API)

```bash
# 1. Create tenant
curl -X POST http://localhost:8080/tenants \
  -H "X-API-Key: your-admin-key" \
  -H "Content-Type: application/json" \
  -d '{"id":"my-tenant","domain":"myapp.com","issuer":"https://auth.myapp.com","algorithm":"RS256"}'

# 2. Register your app as an OAuth client
curl -X POST http://localhost:8080/tenants/my-tenant/clients \
  -H "X-API-Key: your-admin-key" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "My App",
    "client_type": "public",
    "redirect_uris": ["https://myapp.com/callback", "http://localhost:3000/callback"],
    "allowed_scopes": ["openid", "profile", "email"],
    "grant_types": ["authorization_code", "refresh_token"]
  }'
# → Returns client_id (save this)
```

### React / Next.js

```javascript
// 1. Register user
const res = await fetch('https://auth.myapp.com/register', {
  method: 'POST',
  headers: {'Content-Type': 'application/json', 'X-Tenant-ID': 'my-tenant'},
  body: JSON.stringify({email: 'user@example.com', password: 'secret', name: 'User'})
});
// → {user_id, email, verification_sent: true}

// 2. Login
const login = await fetch('https://auth.myapp.com/login', {
  method: 'POST',
  headers: {'Content-Type': 'application/json', 'X-Tenant-ID': 'my-tenant'},
  body: JSON.stringify({email: 'user@example.com', password: 'secret'})
});
const {session_token} = (await login.json()).data;

// 3. Generate PKCE challenge
const verifier = generateRandomString(43);
const challenge = base64url(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)));

// 4. Redirect to authorize
window.location = `https://auth.myapp.com/authorize?` +
  `response_type=code&client_id=${CLIENT_ID}` +
  `&redirect_uri=${encodeURIComponent('https://myapp.com/callback')}` +
  `&scope=openid+profile&state=${randomState}` +
  `&code_challenge=${challenge}&code_challenge_method=S256`;
// Include: headers: {Authorization: `Bearer ${session_token}`, 'X-Tenant-ID': 'my-tenant'}

// 5. After redirect, exchange code for tokens
const tokenRes = await fetch('https://auth.myapp.com/token', {
  method: 'POST',
  headers: {'Content-Type': 'application/x-www-form-urlencoded', 'X-Tenant-ID': 'my-tenant'},
  body: new URLSearchParams({
    grant_type: 'authorization_code',
    code: new URL(window.location).searchParams.get('code'),
    redirect_uri: 'https://myapp.com/callback',
    client_id: CLIENT_ID,
    code_verifier: verifier
  })
});
const {access_token, id_token, refresh_token} = await tokenRes.json();

// 6. Call your API
const data = await fetch('https://api.myapp.com/data', {
  headers: {'Authorization': `Bearer ${access_token}`}
});
```

### React Native / Flutter (Mobile)

Same as React but use `myapp://callback` as redirect URI and store tokens in secure keychain.

```bash
# Register mobile client with custom scheme
curl -X POST .../tenants/my-tenant/clients \
  -d '{"client_name":"Mobile","client_type":"public","redirect_uris":["myapp://callback"],"allowed_scopes":["openid","profile"],"grant_types":["authorization_code","refresh_token"]}'
```

### Python (Backend API — verify JWT)

```python
# pip install PyJWT requests
import jwt, requests

# Fetch JWKS from AuthPlex (cache this)
jwks_client = jwt.PyJWKClient("https://auth.myapp.com/jwks",
                               headers={"X-Tenant-ID": "my-tenant"})

# Verify access token from incoming request
def verify_token(access_token):
    signing_key = jwks_client.get_signing_key_from_jwt(access_token)
    decoded = jwt.decode(access_token, signing_key.key,
                         algorithms=["RS256", "ES256"],
                         audience="your-client-id")
    return decoded  # {"sub": "user-id", "aud": [...], "exp": ..., ...}
```

### Node.js / Express (Backend API — verify JWT)

```javascript
// npm install jose
import { createRemoteJWKSet, jwtVerify } from 'jose';

const JWKS = createRemoteJWKSet(
  new URL('https://auth.myapp.com/jwks'),
  { headers: {'X-Tenant-ID': 'my-tenant'} }
);

// Middleware
async function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({error: 'unauthorized'});

  try {
    const { payload } = await jwtVerify(token, JWKS, { audience: 'your-client-id' });
    req.user = payload;
    next();
  } catch (e) {
    res.status(401).json({error: 'invalid_token'});
  }
}
```

### Go (Backend API — verify JWT)

```go
import "github.com/coreos/go-oidc/v3/oidc"

// Auto-configure from OIDC discovery
provider, _ := oidc.NewProvider(ctx, "https://auth.myapp.com")
verifier := provider.Verifier(&oidc.Config{ClientID: "your-client-id"})

// Middleware
func authMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
        idToken, err := verifier.Verify(r.Context(), token)
        if err != nil {
            http.Error(w, "unauthorized", 401)
            return
        }
        // idToken.Subject = user ID
        next.ServeHTTP(w, r)
    })
}
```

### Java / Spring Boot

```yaml
# application.yml — zero code needed
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: https://auth.myapp.com
          jwk-set-uri: https://auth.myapp.com/jwks
```

### .NET / ASP.NET Core

```csharp
// Program.cs
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options => {
        options.Authority = "https://auth.myapp.com";
        options.Audience = "your-client-id";
    });
```

### cURL / Postman (Testing)

```bash
# Register
curl -X POST http://localhost:8080/register \
  -H "X-Tenant-ID: my-tenant" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"pass123","name":"Test"}'

# Login
curl -X POST http://localhost:8080/login \
  -H "X-Tenant-ID: my-tenant" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"pass123"}'

# OTP Login (passwordless)
curl -X POST http://localhost:8080/otp/request \
  -H "X-Tenant-ID: my-tenant" \
  -d '{"email":"test@example.com","purpose":"login"}'
# → Check console for OTP code (dev mode)

curl -X POST http://localhost:8080/otp/verify \
  -H "X-Tenant-ID: my-tenant" \
  -d '{"email":"test@example.com","code":"123456"}'

# Social Login (Google)
# First configure provider, then redirect user to:
# GET /authorize?provider=google&client_id=...&redirect_uri=...&scope=openid
```

### Server-to-Server (M2M — Client Credentials)

```bash
# Register confidential client
curl -X POST .../tenants/my-tenant/clients \
  -H "X-API-Key: admin-key" \
  -d '{"client_name":"Payment Service","client_type":"confidential","allowed_scopes":["payments:read","payments:write"],"grant_types":["client_credentials"]}'
# → {client_id: "...", client_secret: "..."} (secret shown once)

# Get M2M token
curl -X POST http://localhost:8080/token \
  -H "X-Tenant-ID: my-tenant" \
  -d "grant_type=client_credentials&client_id=CLIENT_ID&client_secret=SECRET&scope=payments:read"
# → {access_token: "...", token_type: "Bearer", expires_in: 3600}
```

### Smart TV / CLI (Device Code)

```bash
# 1. Request device code
curl -X POST http://localhost:8080/device/authorize \
  -H "X-Tenant-ID: my-tenant" \
  -d "client_id=tv-app&scope=openid"
# → {device_code, user_code: "ABCD-1234", verification_uri, interval: 5}

# 2. Show user: "Go to /device/verify, enter code ABCD-1234"

# 3. Poll every 5 seconds
curl -X POST http://localhost:8080/token \
  -H "X-Tenant-ID: my-tenant" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=DEV123&client_id=tv-app"
# → "authorization_pending" until user authorizes, then tokens
```

---

## Architecture

```
15MB binary → Hexagonal Architecture → Postgres + Redis
```

- **Domain**: Pure Go, no I/O, no frameworks
- **Application**: Use cases orchestrating domain via port interfaces
- **Adapter**: Postgres (7 repos), Redis (7 repos), SMTP, Twilio, stdlib crypto (no external JWT libs)

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/ARCHITECTURE.md) | System design, layers, data flow, security model |
| [Flows](docs/FLOWS.md) | 11 sequence diagrams for all auth flows |
| [Use Cases & Integration](docs/USE_CASES.md) | SPA, mobile, M2M, device code, social login + full SDK examples |
| [API Reference](docs/README.md) | Complete endpoint reference with curl examples |
| [Token Architecture](docs/TOKEN_ARCHITECTURE.md) | Session tokens, JWTs, refresh rotation, storage |
| [RBAC](docs/RBAC.md) | Roles, permissions, wildcard matching, JWT enrichment |
| [Compliance](docs/COMPLIANCE.md) | GDPR, SOC2, HIPAA, OWASP analysis |
| [SDK Guide](docs/SDK_GUIDE.md) | Embedded Go SDK, persistence options |
| [Deployment](docs/DEPLOYMENT.md) | Deployment models, cloud strategies, HA architecture |
| [Comparison](docs/COMPARISON.md) | AuthPlex vs Keycloak vs IdentityServer vs Cognito |
| [Roadmap](docs/ROADMAP.md) | Pending items, SAML/LDAP/Admin UI analysis |
| [Implementation Tracker](docs/IMPLEMENTATION_TRACKER.md) | Module status, changelog, standards compliance |

## Stats

```
Files:     ~237 Go files (source + test)
Tests:     720 assertions across 40 packages
Coverage:  85.0% (85% threshold enforced)
Image:     ~20MB (alpine:3.20)
RAM:       <300MB
Deps:      6 (env, testify, x/crypto, pgx, go-redis, testcontainers)
Modules:   12 completed (0-10 + SDK)
Migrations: 19 SQL files
```

## License

Private project.
