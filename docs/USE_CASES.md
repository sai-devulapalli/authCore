# AuthPlex — Use Cases & Integration Guide

## Use Cases

### 1. Multi-Tenant SaaS Platform

**Scenario**: You're building a SaaS where each customer (company) gets their own isolated auth.

```
Customer A (tenant-a)          Customer B (tenant-b)
├── Users: alice@a.com         ├── Users: bob@b.com
├── Clients: dashboard-a       ├── Clients: dashboard-b
├── Signing keys: RSA-2048     ├── Signing keys: EC-P256
├── MFA: required              ├── MFA: optional
├── Social: Google + GitHub    ├── Social: Microsoft
└── alice@a.com ≠ alice@a.com  └── (same email, different tenant)
    in tenant-b                     = OK
```

**Setup**:
```bash
# Create tenant for Customer A
curl -X POST http://authplex:8080/tenants \
  -H "X-API-Key: admin-key" \
  -d '{"id":"tenant-a","domain":"a.example.com","issuer":"https://a.example.com","algorithm":"RS256"}'

# Configure MFA
# (Update tenant with MFA policy via direct DB or future API)

# Register OAuth client for their dashboard
curl -X POST http://authplex:8080/tenants/tenant-a/clients \
  -d '{"client_name":"Dashboard","client_type":"public","redirect_uris":["https://dashboard.a.example.com/callback"],"allowed_scopes":["openid","profile"],"grant_types":["authorization_code","refresh_token"]}'
```

---

### 2. React SPA + REST API

**Scenario**: React frontend with a Go/Node/Python backend API.

**Frontend (React)**:
```javascript
// 1. Register
const register = await fetch('https://auth.myapp.com/register', {
  method: 'POST',
  headers: {'Content-Type': 'application/json', 'X-Tenant-ID': 'my-tenant'},
  body: JSON.stringify({email: 'user@example.com', password: 'secret', name: 'User'})
});

// 2. Login
const login = await fetch('https://auth.myapp.com/login', {
  method: 'POST',
  headers: {'Content-Type': 'application/json', 'X-Tenant-ID': 'my-tenant'},
  body: JSON.stringify({email: 'user@example.com', password: 'secret'})
});
const {session_token} = (await login.json()).data;

// 3. PKCE + Authorize
const verifier = generateRandomString(43);
const challenge = base64url(sha256(verifier));

window.location = `https://auth.myapp.com/authorize?` +
  `response_type=code&client_id=${CLIENT_ID}` +
  `&redirect_uri=${REDIRECT_URI}&scope=openid+profile` +
  `&code_challenge=${challenge}&code_challenge_method=S256` +
  `&state=${randomState}`;
// Include session: Authorization: Bearer {session_token}

// 4. After redirect, exchange code
const tokenResp = await fetch('https://auth.myapp.com/token', {
  method: 'POST',
  headers: {'Content-Type': 'application/x-www-form-urlencoded', 'X-Tenant-ID': 'my-tenant'},
  body: `grant_type=authorization_code&code=${code}&redirect_uri=${REDIRECT_URI}&client_id=${CLIENT_ID}&code_verifier=${verifier}`
});
const {access_token, id_token, refresh_token} = await tokenResp.json();

// 5. Call your API with access_token
const data = await fetch('https://api.myapp.com/data', {
  headers: {'Authorization': `Bearer ${access_token}`}
});
```

**Backend (any language)**:
```python
# Python: Verify JWT using JWKS
import jwt
import requests

# Fetch JWKS (cache this)
jwks = requests.get('https://auth.myapp.com/jwks',
                     headers={'X-Tenant-ID': 'my-tenant'}).json()

# Verify access token
decoded = jwt.decode(access_token, jwks, algorithms=['RS256', 'ES256'])
user_id = decoded['sub']
```

---

### 3. Mobile App (React Native / Flutter)

**Same as SPA** but uses `http://localhost:3000/callback` as redirect URI during development.

```bash
# Register client for mobile
curl -X POST .../tenants/my-tenant/clients \
  -d '{"client_name":"Mobile App","client_type":"public","redirect_uris":["myapp://callback","http://localhost:3000/callback"],"allowed_scopes":["openid","profile","offline_access"],"grant_types":["authorization_code","refresh_token"]}'
```

Mobile uses PKCE (no client_secret for public clients) and stores refresh_token securely in device keychain.

---

### 4. CLI / Smart TV (Device Code Flow)

**Scenario**: Device without a keyboard/browser.

```bash
# 1. Device requests authorization
curl -X POST https://auth.myapp.com/device/authorize \
  -H "X-Tenant-ID: my-tenant" \
  -d "client_id=tv-app&scope=openid"

# Response:
# {"device_code":"DEV123","user_code":"ABCD-1234","verification_uri":"/device/verify","expires_in":900,"interval":5}

# 2. Display to user: "Go to /device/verify, enter code ABCD-1234"

# 3. Device polls every 5 seconds
curl -X POST https://auth.myapp.com/token \
  -H "X-Tenant-ID: my-tenant" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=DEV123&client_id=tv-app"

# Returns "authorization_pending" until user authorizes, then returns tokens
```

---

### 5. Microservice-to-Microservice (M2M)

**Scenario**: Backend services authenticating with each other.

```bash
# Register confidential client
curl -X POST .../tenants/my-tenant/clients \
  -d '{"client_name":"Payment Service","client_type":"confidential","allowed_scopes":["payments:read","payments:write"],"grant_types":["client_credentials"]}'

# Response: {"client_id":"...", "client_secret":"..."}

# Service gets token
curl -X POST https://auth.myapp.com/token \
  -H "X-Tenant-ID: my-tenant" \
  -d "grant_type=client_credentials&client_id=CLIENT_ID&client_secret=CLIENT_SECRET&scope=payments:read"

# Use access_token to call other services
```

---

### 6. Social Login (Google + GitHub)

```bash
# 1. Configure providers
curl -X POST .../tenants/my-tenant/providers \
  -H "X-API-Key: admin-key" \
  -d '{"provider_type":"google","client_id":"GOOGLE_ID","client_secret":"GOOGLE_SECRET","scopes":["openid","email","profile"]}'

curl -X POST .../tenants/my-tenant/providers \
  -d '{"provider_type":"github","client_id":"GH_ID","client_secret":"GH_SECRET","scopes":["read:user","user:email"]}'

# 2. Frontend redirects to:
# https://auth.myapp.com/authorize?provider=google&client_id=my-app&redirect_uri=...&scope=openid&code_challenge=...

# 3. User authenticates with Google → AuthPlex handles callback → issues AuthPlex tokens
```

---

### 7. OTP-Only Authentication (No Password)

```bash
# 1. Register user (password still required for account, but login via OTP)
curl -X POST .../register -H "X-Tenant-ID: t1" \
  -d '{"email":"user@example.com","password":"initial-pass","name":"User"}'

# 2. Request OTP for login
curl -X POST .../otp/request -H "X-Tenant-ID: t1" \
  -d '{"email":"user@example.com","purpose":"login"}'

# 3. Verify OTP → get session
curl -X POST .../otp/verify -H "X-Tenant-ID: t1" \
  -d '{"email":"user@example.com","code":"123456"}'
# → {session_token, expires_in}

# 4. Use session for /authorize
```

---

## Integration Patterns

### Pattern A: AuthPlex as Auth Gateway

```
┌─────────┐     ┌──────────┐     ┌──────────┐
│ Frontend │────►│ AuthPlex │     │ Your API │
│  (SPA)   │◄───│          │     │          │
└─────────┘     └──────────┘     └──────────┘
      │                                │
      │         Bearer Token           │
      └───────────────────────────────►│
                                       │
                              Verify JWT via /jwks
```

Frontend talks to AuthPlex for auth, then calls your API with JWT. Your API verifies JWT using AuthPlex's JWKS endpoint.

### Pattern B: AuthPlex as Sidecar

```
┌────────────────────────────────────┐
│          Kubernetes Pod             │
│                                     │
│  ┌──────────┐    ┌──────────────┐  │
│  │ AuthPlex │◄──►│ Your Service │  │
│  │ (sidecar)│    │              │  │
│  │ :8080    │    │  :3000       │  │
│  └──────────┘    └──────────────┘  │
│                                     │
└────────────────────────────────────┘
```

AuthPlex runs alongside your service in the same pod. Inter-service communication is localhost. ~15MB image, <300MB RAM.

### Pattern C: Centralized Auth Service

```
┌─────────┐
│ App A   │──┐
└─────────┘  │     ┌──────────┐
             ├────►│ AuthPlex │
┌─────────┐  │     │ (shared) │
│ App B   │──┤     └──────────┘
└─────────┘  │
             │
┌─────────┐  │
│ App C   │──┘
└─────────┘
```

Single AuthPlex instance serves multiple applications within the same tenant. Each app is a registered client with its own redirect URIs and scopes.

---

## SDK Integration Examples

### Go

```go
// Auto-configure from OIDC discovery
import "github.com/coreos/go-oidc/v3/oidc"

provider, _ := oidc.NewProvider(ctx, "https://auth.myapp.com")
verifier := provider.Verifier(&oidc.Config{ClientID: "my-app"})

// Verify access token
token, err := verifier.Verify(ctx, accessToken)
```

### Python

```python
# pip install PyJWT requests
import jwt, requests

jwks_client = jwt.PyJWKClient("https://auth.myapp.com/jwks")
signing_key = jwks_client.get_signing_key_from_jwt(token)
decoded = jwt.decode(token, signing_key.key, algorithms=["RS256", "ES256"], audience="my-app")
```

### Node.js

```javascript
// npm install jose
import { createRemoteJWKSet, jwtVerify } from 'jose';

const JWKS = createRemoteJWKSet(new URL('https://auth.myapp.com/jwks'));
const { payload } = await jwtVerify(accessToken, JWKS, { audience: 'my-app' });
```

### Java (Spring)

```yaml
# application.yml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: https://auth.myapp.com
          jwk-set-uri: https://auth.myapp.com/jwks
```

### .NET

```csharp
services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options => {
        options.Authority = "https://auth.myapp.com";
        options.Audience = "my-app";
    });
```

---

## Environment Configuration

### Local Development

```bash
# No external dependencies needed
AUTHPLEX_ENV=local ./bin/authplex

# Everything in-memory, OTPs logged to console
# Perfect for frontend development
```

### Staging

```bash
AUTHPLEX_ENV=staging \
AUTHPLEX_DATABASE_DSN="postgres://user:pass@db:5432/authplex" \
AUTHPLEX_REDIS_URL="redis://redis:6379" \
AUTHPLEX_CORS_ORIGINS="https://staging.myapp.com" \
AUTHPLEX_ADMIN_API_KEY="staging-admin-key" \
AUTHPLEX_SMTP_HOST="smtp.sendgrid.net" \
AUTHPLEX_SMTP_PORT=587 \
AUTHPLEX_SMTP_USERNAME="apikey" \
AUTHPLEX_SMTP_PASSWORD="SG.xxx" \
AUTHPLEX_SMTP_FROM="noreply@myapp.com" \
./bin/authplex
```

### Production

```bash
AUTHPLEX_ENV=production \
AUTHPLEX_DATABASE_DSN="postgres://user:pass@rds-endpoint:5432/authplex?sslmode=require" \
AUTHPLEX_REDIS_URL="redis://elasticache-endpoint:6379" \
AUTHPLEX_CORS_ORIGINS="https://myapp.com,https://admin.myapp.com" \
AUTHPLEX_ADMIN_API_KEY="$(vault read -field=key secret/authplex/admin)" \
AUTHPLEX_ENCRYPTION_KEY="$(vault read -field=key secret/authplex/encryption)" \
AUTHPLEX_SMTP_HOST="smtp.sendgrid.net" \
AUTHPLEX_SMS_PROVIDER="twilio" \
AUTHPLEX_SMS_ACCOUNT_ID="AC123" \
AUTHPLEX_SMS_AUTH_TOKEN="$(vault read -field=token secret/authplex/twilio)" \
AUTHPLEX_SMS_FROM_NUMBER="+15551234567" \
./bin/authplex
```

### Docker Compose (Full Stack)

```yaml
version: '3.8'
services:
  authplex:
    image: authplex:latest
    ports: ["8080:8080"]
    environment:
      AUTHPLEX_ENV: staging
      AUTHPLEX_DATABASE_DSN: postgres://authplex:authplex_dev@postgres:5432/authplex?sslmode=disable
      AUTHPLEX_REDIS_URL: redis://redis:6379
      AUTHPLEX_ADMIN_API_KEY: dev-admin-key
    depends_on:
      postgres: {condition: service_healthy}
      redis: {condition: service_healthy}

  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: authplex
      POSTGRES_PASSWORD: authplex_dev
      POSTGRES_DB: authplex
    healthcheck:
      test: pg_isready -U authplex

  redis:
    image: redis:7-alpine
    healthcheck:
      test: redis-cli ping
```
