# AuthPlex — SDK Guide

## Overview

AuthPlex provides SDKs for **5 languages** plus the embedded **Go SDK**:

| SDK | Language | Package | Install |
|-----|----------|---------|---------|
| Go (embedded) | Go | `pkg/authplex` | `go get github.com/sai-devulapalli/authplex` |
| Java | Java 11+ | `com.authplex.sdk` | Maven/Gradle |
| .NET | C# (.NET 6+) | `AuthPlex.Sdk` | NuGet |
| Node.js | JavaScript/TypeScript | `@authplex/sdk` | `npm install @authplex/sdk` |
| Python | Python 3.10+ | `authplex-sdk` | `pip install authplex-sdk` |

All wrapper SDKs (Java, .NET, Node.js, Python) are HTTP clients that call the AuthPlex server API. The Go SDK can run as an **embedded library** (direct function calls, no HTTP).

---

## Quick Start — All Languages

### Initialize Client

<details>
<summary><b>Go (embedded SDK)</b></summary>

```go
import (
    "database/sql"
    "github.com/sai-devulapalli/authplex/pkg/authplex"
    _ "github.com/jackc/pgx/v5/stdlib"
)

db, _ := sql.Open("pgx", "postgres://localhost:5432/myapp")
auth := authplex.New(authplex.Config{
    Issuer:     "https://myapp.com",
    SessionTTL: 24 * time.Hour,
    AccessTTL:  1 * time.Hour,
}, db, nil) // nil redis = in-memory sessions
```
</details>

<details>
<summary><b>Java</b></summary>

```java
import com.authplex.sdk.AuthPlexClient;

AuthPlexClient auth = AuthPlexClient.builder()
    .baseUrl("http://localhost:8080")
    .tenantId("my-tenant")
    .clientId("my-app")
    .clientSecret("my-secret")
    .build();
```
</details>

<details>
<summary><b>C# (.NET)</b></summary>

```csharp
using AuthPlex.Sdk;

var auth = new AuthPlexClient(new AuthPlexOptions
{
    BaseUrl      = "http://localhost:8080",
    TenantId     = "my-tenant",
    ClientId     = "my-app",
    ClientSecret = "my-secret"
});
```
</details>

<details>
<summary><b>Node.js</b></summary>

```javascript
const { AuthPlex } = require('@authplex/sdk');

const auth = new AuthPlex({
  baseUrl:      'http://localhost:8080',
  tenantId:     'my-tenant',
  clientId:     'my-app',
  clientSecret: 'my-secret'
});
```
</details>

<details>
<summary><b>Python</b></summary>

```python
from authplex_sdk import AuthPlex

auth = AuthPlex(
    base_url="http://localhost:8080",
    tenant_id="my-tenant",
    client_id="my-app",
    client_secret="my-secret"
)
```
</details>

---

## 1. User Registration

<details>
<summary><b>Go</b></summary>

```go
user, err := auth.User.Register(ctx, authplex.RegisterRequest{
    Email:    "user@example.com",
    Password: "secret123",
    Name:     "Jane Doe",
    TenantID: "my-tenant",
})
fmt.Printf("User ID: %s\n", user.ID)
```
</details>

<details>
<summary><b>Java</b></summary>

```java
User user = auth.register("user@example.com", "secret123", "Jane Doe");
System.out.println("User ID: " + user.getUserId());
```
</details>

<details>
<summary><b>C#</b></summary>

```csharp
var user = await auth.RegisterAsync("user@example.com", "secret123", "Jane Doe");
Console.WriteLine($"User ID: {user.UserId}");
```
</details>

<details>
<summary><b>Node.js</b></summary>

```javascript
const user = await auth.register('user@example.com', 'secret123', 'Jane Doe');
console.log('User ID:', user.user_id);
```
</details>

<details>
<summary><b>Python</b></summary>

```python
user = auth.register("user@example.com", "secret123", "Jane Doe")
print(f"User ID: {user.user_id}")
```
</details>

<details>
<summary><b>cURL</b></summary>

```bash
curl -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: my-tenant" \
  -d '{"email":"user@example.com","password":"secret123","name":"Jane Doe"}'
```
</details>

---

## 2. User Login

<details>
<summary><b>Go</b></summary>

```go
session, err := auth.User.Login(ctx, authplex.LoginRequest{
    Email:    "user@example.com",
    Password: "secret123",
    TenantID: "my-tenant",
})
fmt.Printf("Session Token: %s\n", session.Token)
```
</details>

<details>
<summary><b>Java</b></summary>

```java
Session session = auth.login("user@example.com", "secret123");
System.out.println("Session: " + session.getSessionToken());
```
</details>

<details>
<summary><b>C#</b></summary>

```csharp
var session = await auth.LoginAsync("user@example.com", "secret123");
Console.WriteLine($"Session: {session.SessionToken}");
```
</details>

<details>
<summary><b>Node.js</b></summary>

```javascript
const session = await auth.login('user@example.com', 'secret123');
console.log('Session:', session.session_token);
```
</details>

<details>
<summary><b>Python</b></summary>

```python
session = auth.login("user@example.com", "secret123")
print(f"Session: {session.session_token}")
```
</details>

<details>
<summary><b>cURL</b></summary>

```bash
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: my-tenant" \
  -d '{"email":"user@example.com","password":"secret123"}'
```
</details>

---

## 3. Authorization Code + PKCE Flow

<details>
<summary><b>Go</b></summary>

```go
// Step 1: Generate PKCE challenge
verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
hash := sha256.Sum256([]byte(verifier))
challenge := base64.RawURLEncoding.EncodeToString(hash[:])

// Step 2: Redirect user to /authorize
authorizeURL := fmt.Sprintf("https://auth.myapp.com/authorize?"+
    "response_type=code&client_id=%s&redirect_uri=%s&scope=openid+profile"+
    "&state=random-state&code_challenge=%s&code_challenge_method=S256",
    clientID, redirectURI, challenge)

// Step 3: Exchange code for tokens (after redirect callback)
tokens, err := auth.Auth.IssueTokens(ctx, userID, clientID, tenantID, "openid profile")
fmt.Printf("Access Token: %s\n", tokens.AccessToken)
```
</details>

<details>
<summary><b>Java</b></summary>

```java
// After user completes authorization and you receive the code in callback:
TokenResponse tokens = auth.exchangeCode(code, "https://myapp.com/callback", codeVerifier);
System.out.println("Access Token: " + tokens.getAccessToken());
System.out.println("ID Token: " + tokens.getIdToken());
System.out.println("Refresh Token: " + tokens.getRefreshToken());
```
</details>

<details>
<summary><b>C#</b></summary>

```csharp
var tokens = await auth.ExchangeCodeAsync(code, "https://myapp.com/callback", codeVerifier);
Console.WriteLine($"Access Token: {tokens.AccessToken}");
Console.WriteLine($"ID Token: {tokens.IdToken}");
Console.WriteLine($"Refresh Token: {tokens.RefreshToken}");
```
</details>

<details>
<summary><b>Node.js</b></summary>

```javascript
const tokens = await auth.exchangeCode(code, 'https://myapp.com/callback', codeVerifier);
console.log('Access Token:', tokens.access_token);
console.log('ID Token:', tokens.id_token);
console.log('Refresh Token:', tokens.refresh_token);
```
</details>

<details>
<summary><b>Python</b></summary>

```python
tokens = auth.exchange_code(code, "https://myapp.com/callback", code_verifier)
print(f"Access Token: {tokens.access_token}")
print(f"Refresh Token: {tokens.refresh_token}")
```
</details>

<details>
<summary><b>cURL</b></summary>

```bash
# Step 1: Redirect browser to authorize endpoint
# GET http://localhost:8080/authorize?response_type=code&client_id=my-app&redirect_uri=https://myapp.com/callback&scope=openid+profile&state=random&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256

# Step 2: Exchange code (after redirect)
curl -X POST http://localhost:8080/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-Tenant-ID: my-tenant" \
  -d "grant_type=authorization_code&code=AUTH_CODE&redirect_uri=https://myapp.com/callback&client_id=my-app&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
```
</details>

---

## 4. Refresh Token

<details>
<summary><b>Go</b></summary>

```go
// SDK mode: tokens are issued directly
newTokens, err := auth.Auth.RefreshToken(ctx, refreshToken, clientID, tenantID)
```
</details>

<details>
<summary><b>Java</b></summary>

```java
TokenResponse newTokens = auth.refreshToken(refreshToken);
```
</details>

<details>
<summary><b>C#</b></summary>

```csharp
var newTokens = await auth.RefreshTokenAsync(refreshToken);
```
</details>

<details>
<summary><b>Node.js</b></summary>

```javascript
const newTokens = await auth.refreshToken(refreshToken);
```
</details>

<details>
<summary><b>Python</b></summary>

```python
new_tokens = auth.refresh_token(refresh_token)
```
</details>

<details>
<summary><b>cURL</b></summary>

```bash
curl -X POST http://localhost:8080/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-Tenant-ID: my-tenant" \
  -d "grant_type=refresh_token&refresh_token=REFRESH_TOKEN&client_id=my-app"
```
</details>

---

## 5. Client Credentials (M2M)

<details>
<summary><b>Java</b></summary>

```java
TokenResponse tokens = auth.clientCredentials("read:data write:data");
```
</details>

<details>
<summary><b>C#</b></summary>

```csharp
var tokens = await auth.ClientCredentialsAsync("read:data write:data");
```
</details>

<details>
<summary><b>Node.js</b></summary>

```javascript
const tokens = await auth.clientCredentials('read:data write:data');
```
</details>

<details>
<summary><b>Python</b></summary>

```python
tokens = auth.client_credentials("read:data write:data")
```
</details>

<details>
<summary><b>cURL</b></summary>

```bash
curl -X POST http://localhost:8080/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-Tenant-ID: my-tenant" \
  -d "grant_type=client_credentials&client_id=my-app&client_secret=my-secret&scope=read:data"
```
</details>

---

## 6. OTP (Passwordless Login)

<details>
<summary><b>Go</b></summary>

```go
// Request OTP
auth.User.RequestOTP(ctx, authplex.OTPRequest{
    Email:    "user@example.com",
    Purpose:  "login",
    TenantID: "my-tenant",
})

// Verify OTP → creates session
session, _ := auth.User.VerifyOTP(ctx, authplex.OTPVerifyRequest{
    Email:    "user@example.com",
    Code:     "123456",
    TenantID: "my-tenant",
})
```
</details>

<details>
<summary><b>Java</b></summary>

```java
auth.requestOtp("user@example.com", "login");

// User receives OTP via email/SMS...

Session session = auth.verifyOtp("user@example.com", "123456");
```
</details>

<details>
<summary><b>C#</b></summary>

```csharp
await auth.RequestOtpAsync("user@example.com", "login");

var session = await auth.VerifyOtpAsync("user@example.com", "123456");
```
</details>

<details>
<summary><b>Node.js</b></summary>

```javascript
await auth.requestOtp('user@example.com', 'login');

const session = await auth.verifyOtp('user@example.com', '123456');
```
</details>

<details>
<summary><b>Python</b></summary>

```python
auth.request_otp("user@example.com", "login")

session = auth.verify_otp("user@example.com", "123456")
```
</details>

<details>
<summary><b>cURL</b></summary>

```bash
# Request OTP
curl -X POST http://localhost:8080/otp/request \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: my-tenant" \
  -d '{"email":"user@example.com","purpose":"login"}'

# Verify OTP
curl -X POST http://localhost:8080/otp/verify \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: my-tenant" \
  -d '{"email":"user@example.com","code":"123456"}'
```
</details>

---

## 7. Password Reset

<details>
<summary><b>Go</b></summary>

```go
// Request reset OTP
auth.User.RequestOTP(ctx, authplex.OTPRequest{
    Email: "user@example.com", Purpose: "reset", TenantID: "my-tenant",
})

// Reset with OTP code
auth.User.ResetPassword(ctx, authplex.ResetPasswordRequest{
    Email: "user@example.com", Code: "123456", NewPassword: "newSecret456", TenantID: "my-tenant",
})
```
</details>

<details>
<summary><b>Java</b></summary>

```java
auth.requestOtp("user@example.com", "reset");
auth.resetPassword("user@example.com", "123456", "newSecret456");
```
</details>

<details>
<summary><b>C#</b></summary>

```csharp
await auth.RequestOtpAsync("user@example.com", "reset");
await auth.ResetPasswordAsync("user@example.com", "123456", "newSecret456");
```
</details>

<details>
<summary><b>Node.js</b></summary>

```javascript
await auth.requestOtp('user@example.com', 'reset');
await auth.resetPassword('user@example.com', '123456', 'newSecret456');
```
</details>

<details>
<summary><b>Python</b></summary>

```python
auth.request_otp("user@example.com", "reset")
auth.reset_password("user@example.com", "123456", "newSecret456")
```
</details>

<details>
<summary><b>cURL</b></summary>

```bash
curl -X POST http://localhost:8080/otp/request \
  -H "Content-Type: application/json" -H "X-Tenant-ID: my-tenant" \
  -d '{"email":"user@example.com","purpose":"reset"}'

curl -X POST http://localhost:8080/password/reset \
  -H "Content-Type: application/json" -H "X-Tenant-ID: my-tenant" \
  -d '{"email":"user@example.com","code":"123456","new_password":"newSecret456"}'
```
</details>

---

## 8. MFA — TOTP Enrollment

<details>
<summary><b>Go</b></summary>

```go
enrollment, _ := auth.MFA.EnrollTOTP(ctx, "user-id", "my-tenant")
// Show QR code: enrollment.OTPAuthURI

// User scans QR, enters code
auth.MFA.ConfirmTOTP(ctx, "user-id", "my-tenant", "123456")
```
</details>

<details>
<summary><b>Java / C# / Node.js / Python</b></summary>

```
POST /mfa/totp/enroll   { "subject": "user-id" }
→ { "data": { "secret": "JBSWY3...", "otpauth_uri": "otpauth://totp/..." } }

POST /mfa/totp/confirm  { "subject": "user-id", "code": "123456" }
→ { "data": { "status": "confirmed" } }
```
</details>

<details>
<summary><b>cURL</b></summary>

```bash
# Enroll
curl -X POST http://localhost:8080/mfa/totp/enroll \
  -H "Content-Type: application/json" \
  -d '{"subject":"user-id"}'

# Confirm
curl -X POST http://localhost:8080/mfa/totp/confirm \
  -H "Content-Type: application/json" \
  -d '{"subject":"user-id","code":"123456"}'
```
</details>

---

## 9. RBAC — Roles & Permissions

<details>
<summary><b>Go</b></summary>

```go
// SDK mode: call service directly
role, _ := auth.RBAC.CreateRole(ctx, "my-tenant", "editor", "Can edit posts", []string{"posts:read", "posts:write"})
auth.RBAC.AssignRole(ctx, "my-tenant", "user-id", role.ID)

permissions, _ := auth.RBAC.GetUserPermissions(ctx, "my-tenant", "user-id")
// → ["posts:read", "posts:write"]
```
</details>

<details>
<summary><b>Java</b></summary>

```java
Role role = auth.createRole("editor", "Can edit posts", new String[]{"posts:read", "posts:write"});
auth.assignRole("user-id", role.getId());
```
</details>

<details>
<summary><b>C#</b></summary>

```csharp
var role = await auth.CreateRoleAsync("editor", "Can edit posts", new[] { "posts:read", "posts:write" });
await auth.AssignRoleAsync("user-id", role.Id);
```
</details>

<details>
<summary><b>Node.js</b></summary>

```javascript
// Uses management API with admin key
const resp = await fetch('http://localhost:8080/tenants/my-tenant/roles', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', 'X-API-Key': 'admin-key' },
  body: JSON.stringify({ name: 'editor', description: 'Can edit posts', permissions: ['posts:read', 'posts:write'] })
});
const role = (await resp.json()).data;

// Assign role
await fetch(`http://localhost:8080/tenants/my-tenant/users/user-id/roles/${role.id}`, {
  method: 'POST',
  headers: { 'X-API-Key': 'admin-key' }
});
```
</details>

<details>
<summary><b>Python</b></summary>

```python
import json, urllib.request

# Create role (management API)
req = urllib.request.Request(
    "http://localhost:8080/tenants/my-tenant/roles",
    data=json.dumps({"name": "editor", "permissions": ["posts:read", "posts:write"]}).encode(),
    headers={"Content-Type": "application/json", "X-API-Key": "admin-key"},
    method="POST"
)
role = json.loads(urllib.request.urlopen(req).read())["data"]

# Assign role
urllib.request.urlopen(urllib.request.Request(
    f"http://localhost:8080/tenants/my-tenant/users/user-id/roles/{role['id']}",
    headers={"X-API-Key": "admin-key"}, method="POST", data=b""
))
```
</details>

<details>
<summary><b>cURL</b></summary>

```bash
# Create role
curl -X POST http://localhost:8080/tenants/my-tenant/roles \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer admin-key" \
  -d '{"name":"editor","description":"Can edit posts","permissions":["posts:read","posts:write"]}'

# Assign role to user
curl -X POST http://localhost:8080/tenants/my-tenant/users/user-id/roles/ROLE_ID \
  -H "Authorization: Bearer admin-key"

# Get user permissions
curl http://localhost:8080/tenants/my-tenant/users/user-id/permissions \
  -H "Authorization: Bearer admin-key"
```
</details>

---

## 10. Social Login (Google Example)

<details>
<summary><b>Go</b></summary>

```go
// Configure provider
auth.Provider.Create(ctx, authplex.ProviderRequest{
    ProviderType: "google",
    ClientID:     "GOOGLE_CLIENT_ID",
    ClientSecret: "GOOGLE_SECRET",
    Scopes:       []string{"openid", "email", "profile"},
    TenantID:     "my-tenant",
})

// Redirect user: GET /authorize?provider=google&client_id=my-app&redirect_uri=...&scope=openid
// After callback: exchange code for tokens normally
```
</details>

<details>
<summary><b>Any language — HTTP flow</b></summary>

```bash
# Step 1: Admin creates provider
curl -X POST http://localhost:8080/tenants/my-tenant/providers \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer admin-key" \
  -d '{
    "provider_type": "google",
    "client_id": "GOOGLE_CLIENT_ID",
    "client_secret": "GOOGLE_SECRET",
    "scopes": ["openid", "email", "profile"]
  }'

# Step 2: Redirect user's browser to:
# GET http://localhost:8080/authorize?provider=google&client_id=my-app&redirect_uri=https://myapp.com/callback&scope=openid+profile&state=random&code_challenge=CHALLENGE&code_challenge_method=S256

# Step 3: User authenticates with Google → redirected to /callback → redirected to your redirect_uri with code

# Step 4: Exchange code (same as auth code flow)
curl -X POST http://localhost:8080/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-Tenant-ID: my-tenant" \
  -d "grant_type=authorization_code&code=AUTH_CODE&redirect_uri=https://myapp.com/callback&client_id=my-app&code_verifier=VERIFIER"
```
</details>

---

## 11. WebAuthn/FIDO2 (Hardware Key / Biometric)

<details>
<summary><b>Any language — HTTP flow</b></summary>

```bash
# Step 1: Begin registration (get challenge)
curl -X POST http://localhost:8080/mfa/webauthn/register/begin \
  -H "Content-Type: application/json" \
  -d '{"subject":"user-id","display_name":"Jane Doe"}'
# → { "session_id": "...", "options": { "publicKey": { "challenge": "...", "rp": {...}, ... } } }

# Step 2: Browser calls navigator.credentials.create() with options
# Step 3: Send attestation response
curl -X POST http://localhost:8080/mfa/webauthn/register/finish \
  -H "Content-Type: application/json" \
  -d '{"subject":"user-id","response":{"session_id":"...","response":{...attestation...}}}'

# Step 4: Begin login (get assertion challenge)
curl -X POST http://localhost:8080/mfa/webauthn/login/begin \
  -H "Content-Type: application/json" \
  -d '{"subject":"user-id"}'

# Step 5: Browser calls navigator.credentials.get() with options
# Step 6: Send assertion response
curl -X POST http://localhost:8080/mfa/webauthn/login/finish \
  -H "Content-Type: application/json" \
  -d '{"challenge_id":"...","response":{...assertion...}}'
```
</details>

<details>
<summary><b>JavaScript (browser-side WebAuthn)</b></summary>

```javascript
// Registration
const beginResp = await fetch('/mfa/webauthn/register/begin', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ subject: userId, display_name: userName })
});
const { session_id, options } = await beginResp.json();

// Browser API — prompts user to touch security key / scan fingerprint
const credential = await navigator.credentials.create({ publicKey: options.publicKey });

// Send attestation back
await fetch('/mfa/webauthn/register/finish', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    subject: userId,
    response: { session_id, response: credential }
  })
});

// Authentication (similar flow with navigator.credentials.get)
```
</details>

---

## 12. Device Code Flow (TV/CLI)

<details>
<summary><b>cURL</b></summary>

```bash
# Step 1: Request device code
curl -X POST http://localhost:8080/device/authorize \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: my-tenant" \
  -d '{"client_id":"cli-app","scope":"openid"}'
# → { "device_code": "...", "user_code": "ABCD-1234", "verification_uri": "https://auth.myapp.com/device", "expires_in": 900, "interval": 5 }

# Step 2: Display user_code to user, ask them to visit verification_uri

# Step 3: Poll for token (every interval seconds)
curl -X POST http://localhost:8080/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-Tenant-ID: my-tenant" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=DEVICE_CODE&client_id=cli-app"
# → { "error": "authorization_pending" }  (keep polling)
# → { "access_token": "...", "token_type": "Bearer" }  (user authorized)
```
</details>

---

## 13. Token Introspection

<details>
<summary><b>cURL</b></summary>

```bash
curl -X POST http://localhost:8080/introspect \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-Tenant-ID: my-tenant" \
  -d "token=ACCESS_TOKEN&client_id=my-app"
# → { "active": true, "sub": "user-id", "scope": "openid profile", "client_id": "my-app", "exp": 1711234567 }
```
</details>

---

## 14. Token Revocation

<details>
<summary><b>cURL</b></summary>

```bash
# Revoke refresh token
curl -X POST http://localhost:8080/revoke \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-Tenant-ID: my-tenant" \
  -d "token=REFRESH_TOKEN&client_id=my-app"
```
</details>

---

## 15. Tenant Management (Admin API)

<details>
<summary><b>cURL</b></summary>

```bash
# Create tenant
curl -X POST http://localhost:8080/tenants \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ADMIN_API_KEY" \
  -d '{"id":"acme","domain":"acme.com","issuer":"https://auth.acme.com","algorithm":"RS256"}'

# List tenants
curl http://localhost:8080/tenants -H "Authorization: Bearer ADMIN_API_KEY"

# Create OAuth client
curl -X POST http://localhost:8080/tenants/acme/clients \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ADMIN_API_KEY" \
  -d '{"client_name":"Web App","client_type":"confidential","redirect_uris":["https://app.acme.com/callback"],"allowed_scopes":["openid","profile","email"],"grant_types":["authorization_code","refresh_token"]}'

# Query audit logs
curl "http://localhost:8080/tenants/acme/audit?action=login_success&limit=10" \
  -H "Authorization: Bearer ADMIN_API_KEY"
```
</details>

---

## Go Embedded SDK — Advanced Usage

### Protect HTTP Endpoints with JWT Middleware

```go
auth := authplex.New(config, db, rdb)
mux := http.NewServeMux()

// Public
mux.HandleFunc("/", homeHandler)

// Protected — JWT verified automatically
mux.Handle("/api/", auth.RequireJWT(http.HandlerFunc(apiHandler)))

// Access claims in handler
mux.Handle("/api/me", auth.RequireJWT(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    claims := authplex.ClaimsFromContext(r.Context())
    fmt.Fprintf(w, "Hello %s, roles: %v", claims.Subject, claims.Roles)
})))
```

### Mount Full OIDC Endpoints on Your Router

```go
auth := authplex.New(config, db, rdb)
mux := http.NewServeMux()

// Mount all 39 AuthPlex endpoints
auth.MountRoutes(mux, authplex.RouteConfig{
    TenantMode:  "header",
    CORSOrigins: "*",
    AdminAPIKey: "your-key",
    RateLimit:   20,
})

// Add your own endpoints alongside
mux.HandleFunc("/api/orders", ordersHandler)
http.ListenAndServe(":8080", mux)
```

### Three Persistence Options

| Option | Init Code | Best For |
|--------|-----------|----------|
| Shared DB | `authplex.New(cfg, yourDB, yourRedis)` | Startups |
| Separate DB | `authplex.New(cfg, authDB, authRedis)` | Compliance |
| In-memory | `authplex.New(cfg, nil, nil)` | Dev/testing |

---

## 16. AI Agent / M2M Authentication

### Create an Agent Client (Admin)

<details>
<summary><b>cURL</b></summary>

```bash
# Create a confidential client for your AI agent
curl -X POST http://localhost:8080/tenants/my-tenant/clients \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ADMIN_API_KEY" \
  -d '{
    "client_name": "My AI Agent",
    "client_type": "confidential",
    "is_agent": true,
    "redirect_uris": [],
    "allowed_scopes": ["data:read", "data:write"],
    "grant_types": ["client_credentials"]
  }'
# Response: {"data": {"client_id": "...", "client_secret": "..." }}
```
</details>

### Generate Static API Key

<details>
<summary><b>cURL</b></summary>

```bash
# Generate a non-expiring API key for simpler integrations
curl -X POST http://localhost:8080/tenants/my-tenant/clients/AGENT_CLIENT_ID/api-key \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ADMIN_API_KEY"
# Response: {"data": {"api_key": "ac_..."}}
```
</details>

### Get Agent JWT (client_credentials)

<details>
<summary><b>Go</b></summary>

```go
// Using the embedded SDK
tokens, err := auth.Auth.ClientCredentials(ctx, clientID, clientSecret, tenantID, "data:read data:write")
fmt.Printf("Agent Token: %s\n", tokens.AccessToken)
```
</details>

<details>
<summary><b>Java</b></summary>

```java
// Using the wrapper SDK
TokenResponse tokens = auth.clientCredentials("data:read data:write");
System.out.println("Agent Token: " + tokens.getAccessToken());

// Or with Spring Boot AgentAuthService (auto-caches + refreshes)
@Autowired AgentAuthService agentAuth;
String token = agentAuth.getAccessToken();
```
</details>

<details>
<summary><b>C#</b></summary>

```csharp
var tokens = await auth.ClientCredentialsAsync("data:read data:write");
Console.WriteLine($"Agent Token: {tokens.AccessToken}");
```
</details>

<details>
<summary><b>Node.js</b></summary>

```javascript
const tokens = await auth.clientCredentials('data:read data:write');
console.log('Agent Token:', tokens.access_token);
```
</details>

<details>
<summary><b>Python</b></summary>

```python
tokens = auth.client_credentials("data:read data:write")
print(f"Agent Token: {tokens.access_token}")
```
</details>

<details>
<summary><b>cURL</b></summary>

```bash
curl -X POST http://localhost:8080/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-Tenant-ID: my-tenant" \
  -d "grant_type=client_credentials&client_id=AGENT_CLIENT_ID&client_secret=AGENT_SECRET&scope=data:read data:write"
```
</details>

### Endpoint-Scoped Tokens

When an agent client is configured with endpoint restrictions, the issued JWT includes an `endpoints` claim:

```json
{
  "sub": "agent-client-id",
  "iss": "https://auth.myapp.com",
  "aud": "my-tenant",
  "scope": "data:read data:write",
  "endpoints": ["/api/data/*", "/api/reports/*"],
  "exp": 1711234567
}
```

Your consuming API should validate the `endpoints` claim against the request path:

```go
// Example: middleware to enforce endpoint scoping
claims := authplex.ClaimsFromContext(r.Context())
if len(claims.Endpoints) > 0 {
    allowed := false
    for _, pattern := range claims.Endpoints {
        if matchPath(pattern, r.URL.Path) { allowed = true; break }
    }
    if !allowed { http.Error(w, "forbidden", 403); return }
}
```

---

## SDK Repositories

| Language | Repository |
|----------|-----------|
| Go (embedded) | `github.com/sai-devulapalli/authplex/pkg/authplex` |
| Java | `github.com/sai-devulapalli/authplex-java-sdk` |
| .NET | `github.com/sai-devulapalli/authplex-dotnet-sdk` |
| Node.js | `github.com/sai-devulapalli/authplex-js` |
| Python | `github.com/sai-devulapalli/authplex-python` |
| Admin UI | `github.com/sai-devulapalli/authplex-admin` |
