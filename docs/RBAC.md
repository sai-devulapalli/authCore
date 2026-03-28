# AuthCore — Role-Based Access Control (RBAC)

## Overview

RBAC in AuthCore allows you to define roles and permissions per tenant, assign them to users, and include them in JWT claims. Your APIs then check these claims to authorize actions — no call back to AuthCore needed.

```
WITHOUT RBAC:    JWT = {sub: "alice"}         → Your API knows WHO, not what they CAN DO
WITH RBAC:       JWT = {sub: "alice",
                        roles: ["admin"],
                        permissions: ["posts:*", "users:read"]}
                                              → Your API knows WHO + what they CAN DO
```

---

## Architecture

```
┌────────────────────────────────────────────────────────┐
│                      AuthCore                           │
│                                                          │
│  Tenant: my-tenant                                       │
│  ┌─────────────────────────────────────────────┐        │
│  │  Roles                                       │        │
│  │  ├── admin    → [posts:*, users:*, settings:*]       │
│  │  ├── editor   → [posts:read, posts:write]            │
│  │  └── viewer   → [posts:read]                         │
│  └─────────────────────────────────────────────┘        │
│                                                          │
│  ┌─────────────────────────────────────────────┐        │
│  │  User → Role Assignments                     │        │
│  │  ├── alice   → [admin]                        │        │
│  │  ├── bob     → [editor, viewer]               │        │
│  │  └── charlie → [viewer]                       │        │
│  └─────────────────────────────────────────────┘        │
│                                                          │
│  Token Issuance:                                         │
│  ┌─────────────────────────────────────────────┐        │
│  │  JWT for alice = {                            │        │
│  │    sub: "alice-id",                           │        │
│  │    roles: ["admin"],                          │        │
│  │    permissions: ["posts:read", "posts:write", │        │
│  │                  "posts:delete", "users:read",│        │
│  │                  "users:write", "settings:*"] │        │
│  │  }                                            │        │
│  └─────────────────────────────────────────────┘        │
└────────────────────────────────────────────────────────┘
         │
         ▼
┌────────────────────────────────────────────────────────┐
│                    Your API                              │
│                                                          │
│  GET /api/posts         → check "posts:read"     → ✅   │
│  DELETE /api/posts/123  → check "posts:delete"   → ✅   │
│  GET /api/settings      → check "settings:read"  → ✅   │
│                                                          │
│  No call back to AuthCore — JWT is self-contained       │
└────────────────────────────────────────────────────────┘
```

---

## Data Model

### Role

```
Role
├── ID            (string, unique)
├── TenantID      (string, per-tenant isolation)
├── Name          (string, unique per tenant: "admin", "editor", "viewer")
├── Description   (string, human-readable)
├── Permissions   ([]string: ["posts:read", "posts:write", "users:*"])
├── CreatedAt
└── UpdatedAt
```

### User → Role Assignment

```
UserRoleAssignment
├── UserID        (string, references user)
├── RoleID        (string, references role)
├── TenantID      (string, per-tenant)
└── AssignedAt
```

### Permission Format

```
resource:action

Examples:
  posts:read         Read posts
  posts:write        Create/update posts
  posts:delete       Delete posts
  posts:*            All post actions (wildcard)
  users:read         Read user profiles
  users:*            All user actions
  settings:*         All settings actions
  *                  Superadmin — all permissions on all resources
```

---

## API Endpoints

### Role Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/tenants/{tid}/roles` | Create role |
| `GET` | `/tenants/{tid}/roles` | List all roles |
| `GET` | `/tenants/{tid}/roles/{rid}` | Get role details |
| `PUT` | `/tenants/{tid}/roles/{rid}` | Update role (name, permissions) |
| `DELETE` | `/tenants/{tid}/roles/{rid}` | Delete role |

### Role Assignment

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/tenants/{tid}/users/{uid}/roles` | Assign role to user |
| `DELETE` | `/tenants/{tid}/users/{uid}/roles/{rid}` | Revoke role from user |
| `GET` | `/tenants/{tid}/users/{uid}/roles` | Get user's roles |
| `GET` | `/tenants/{tid}/users/{uid}/permissions` | Get user's flattened permissions |

### Examples

```bash
# 1. Create roles
curl -X POST http://localhost:8080/tenants/my-tenant/roles \
  -H "X-API-Key: admin-key" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "admin",
    "description": "Full access to all resources",
    "permissions": ["posts:*", "users:*", "settings:*"]
  }'

curl -X POST http://localhost:8080/tenants/my-tenant/roles \
  -d '{"name": "editor", "permissions": ["posts:read", "posts:write"]}'

curl -X POST http://localhost:8080/tenants/my-tenant/roles \
  -d '{"name": "viewer", "permissions": ["posts:read"]}'

# 2. Assign role to user
curl -X POST http://localhost:8080/tenants/my-tenant/users/alice-id/roles \
  -H "X-API-Key: admin-key" \
  -d '{"role_id": "admin-role-id"}'

# 3. Check user's permissions
curl http://localhost:8080/tenants/my-tenant/users/alice-id/permissions \
  -H "X-API-Key: admin-key"
# → {"data": {"permissions": ["posts:read", "posts:write", "posts:delete", "users:read", "users:write", "settings:read", "settings:write"]}}

# 4. User logs in → JWT now contains roles + permissions
# POST /login → POST /token → JWT includes roles and permissions
```

---

## JWT Claims with RBAC

### Before RBAC

```json
{
  "iss": "https://authcore",
  "sub": "alice-id",
  "aud": ["my-app"],
  "exp": 1774646411,
  "iat": 1774642811,
  "jti": "unique-token-id"
}
```

### After RBAC

```json
{
  "iss": "https://authcore",
  "sub": "alice-id",
  "aud": ["my-app"],
  "exp": 1774646411,
  "iat": 1774642811,
  "jti": "unique-token-id",
  "roles": ["admin"],
  "permissions": ["posts:read", "posts:write", "posts:delete",
                   "users:read", "users:write",
                   "settings:read", "settings:write"]
}
```

**Important**: Roles and permissions are embedded at token issuance time. If you change a user's role, the change takes effect on their next JWT (next login or token refresh). Existing JWTs retain old permissions until they expire (1 hour max).

---

## Permission Checking in Your API

### Go

```go
// Middleware
func RequirePermission(permission string) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            claims := authcore.ClaimsFromContext(r.Context())
            if !HasPermission(claims.Permissions, permission) {
                http.Error(w, `{"error":"forbidden"}`, 403)
                return
            }
            next.ServeHTTP(w, r)
        })
    }
}

// Usage
mux.Handle("/api/posts", RequirePermission("posts:read")(listPostsHandler))
mux.Handle("/api/posts/new", RequirePermission("posts:write")(createPostHandler))
mux.Handle("/api/settings", RequirePermission("settings:*")(settingsHandler))
```

### Python (FastAPI)

```python
from functools import wraps

def require_permission(permission):
    def decorator(f):
        @wraps(f)
        async def wrapper(*args, **kwargs):
            claims = verify_jwt(request.headers["Authorization"])
            if not has_permission(claims["permissions"], permission):
                raise HTTPException(status_code=403, detail="forbidden")
            return await f(*args, **kwargs)
        return wrapper
    return decorator

@app.get("/api/posts")
@require_permission("posts:read")
async def list_posts():
    return {"posts": [...]}

@app.delete("/api/posts/{id}")
@require_permission("posts:delete")
async def delete_post(id: str):
    pass
```

### Node.js (Express)

```javascript
function requirePermission(permission) {
    return (req, res, next) => {
        const claims = req.user; // set by JWT middleware
        if (!hasPermission(claims.permissions, permission)) {
            return res.status(403).json({ error: 'forbidden' });
        }
        next();
    };
}

app.get('/api/posts', requirePermission('posts:read'), listPosts);
app.delete('/api/posts/:id', requirePermission('posts:delete'), deletePost);
```

### Java (Spring Boot)

```java
// Zero custom code — Spring reads roles/permissions from JWT automatically

@PreAuthorize("hasAuthority('SCOPE_posts:write')")
@PostMapping("/api/posts")
public Post createPost(@RequestBody Post post) { ... }

@PreAuthorize("hasAuthority('SCOPE_posts:delete')")
@DeleteMapping("/api/posts/{id}")
public void deletePost(@PathVariable String id) { ... }

@PreAuthorize("hasRole('admin')")
@GetMapping("/api/admin/dashboard")
public Dashboard adminDashboard() { ... }
```

### .NET (ASP.NET Core)

```csharp
[Authorize(Policy = "CanWritePosts")]
[HttpPost("/api/posts")]
public IActionResult CreatePost([FromBody] Post post) { ... }

// In Program.cs:
builder.Services.AddAuthorization(options => {
    options.AddPolicy("CanWritePosts", policy =>
        policy.RequireClaim("permissions", "posts:write"));
    options.AddPolicy("IsAdmin", policy =>
        policy.RequireRole("admin"));
});
```

---

## Wildcard Permission Logic

```
Hierarchy:
  *              matches everything
  posts:*        matches posts:read, posts:write, posts:delete
  posts:read     matches only posts:read
```

```go
func HasPermission(userPerms []string, required string) bool {
    for _, p := range userPerms {
        // Superadmin
        if p == "*" {
            return true
        }
        // Exact match
        if p == required {
            return true
        }
        // Wildcard: "posts:*" matches "posts:read"
        if strings.HasSuffix(p, ":*") {
            prefix := strings.TrimSuffix(p, ":*")
            if strings.HasPrefix(required, prefix+":") {
                return true
            }
        }
    }
    return false
}
```

---

## Database Schema

```sql
-- 010_create_rbac.sql

CREATE TABLE IF NOT EXISTS roles (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    name        TEXT NOT NULL,
    description TEXT DEFAULT '',
    permissions TEXT[] NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(tenant_id, name)
);

CREATE TABLE IF NOT EXISTS user_role_assignments (
    user_id     TEXT NOT NULL,
    role_id     TEXT NOT NULL,
    tenant_id   TEXT NOT NULL,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, role_id, tenant_id)
);

CREATE INDEX IF NOT EXISTS idx_user_roles ON user_role_assignments(user_id, tenant_id);
CREATE INDEX IF NOT EXISTS idx_role_users ON user_role_assignments(role_id, tenant_id);
```

---

## Example Scenarios

### Scenario 1: Blog Platform

```
Roles:
  admin    → [posts:*, users:*, comments:*, settings:*]
  author   → [posts:read, posts:write, comments:read, comments:write]
  moderator→ [posts:read, comments:read, comments:delete]
  reader   → [posts:read, comments:read]

Users:
  alice (admin)     → can do everything
  bob (author)      → can write posts and comments
  charlie (mod)     → can delete comments
  dave (reader)     → read-only
```

### Scenario 2: Multi-Tenant SaaS

```
Tenant A:
  Roles: [owner, member, billing]
  owner   → [*]
  member  → [projects:read, projects:write, tasks:*]
  billing → [invoices:read, payments:*]

Tenant B:
  Roles: [admin, developer, viewer]
  admin     → [*]
  developer → [repos:*, pipelines:*, deployments:read]
  viewer    → [repos:read, pipelines:read]

Each tenant defines their OWN roles — completely isolated.
```

### Scenario 3: API with Scoped Tokens (M2M)

```
Confidential client "payment-service":
  Scopes: [payments:read, payments:write]

Client credentials grant → JWT:
  {
    "sub": "payment-service",
    "scope": "payments:read payments:write"
  }

API checks: scope contains "payments:write" → allowed
```

---

## Role Change Propagation

```
Timeline:

T=0:   Alice has role "editor" → JWT contains permissions: [posts:read, posts:write]
T=5m:  Admin promotes Alice to "admin"
T=5m:  Alice's EXISTING JWT still has [posts:read, posts:write] (unchanged)
T=30m: Alice's JWT expires, she refreshes
T=30m: NEW JWT now has [posts:*, users:*, settings:*]

The delay = JWT expiry time (1 hour max).
```

**If you need instant propagation:**

| Option | How | Trade-off |
|--------|-----|-----------|
| Short JWT TTL | Set access_token to 5 minutes | More refresh calls |
| Token blacklist | Revoke old JWT on role change | Requires blacklist check on every request |
| Hybrid | Check roles in JWT + verify critical actions against AuthCore API | Extra network call for sensitive operations only |

---

## Comparison: AuthCore RBAC vs Others

| Feature | **AuthCore** | **Keycloak** | **Cognito** |
|---------|:-:|:-:|:-:|
| Role CRUD API | Yes | Yes + admin UI | Groups API |
| Per-tenant roles | Yes | Per-realm | Per-pool |
| Roles in JWT | Yes (`roles` claim) | Yes (`realm_access`) | Yes (`cognito:groups`) |
| Permissions in JWT | Yes (`permissions` claim) | Yes (`resource_access`) | No (groups only) |
| Wildcard permissions | Yes (`posts:*`) | No | No |
| Hierarchical roles | No (flat) | Yes (composite roles) | No |
| Role assignment API | Yes | Yes | Yes |
| UI for management | No (API only) | Yes (full console) | AWS Console |
| ABAC (attribute-based) | No | Partial (policies) | No |
| Real-time propagation | On next token | Real-time (API) | On next token |

---

## Implementation Status

| Component | Status |
|-----------|--------|
| Domain model (Role, Assignment) | **Done** — `internal/domain/rbac/` |
| Repository interfaces | **Done** — RoleRepository, AssignmentRepository |
| In-memory repositories | **Done** — `internal/adapter/cache/rbac_repository.go` |
| Postgres migration (010_create_rbac.sql) | **Done** — roles + user_role_assignments tables |
| Application service (RBAC CRUD) | **Done** — `internal/application/rbac/` |
| HTTP handlers (role + assignment endpoints) | **Done** — `internal/adapter/http/handler/rbac.go` |
| JWT claims extension | **Done** — Auth service enriches JWT with roles + permissions |
| Permission checking helpers | **Done** — `HasPermission()`, `FlattenPermissions()` in domain |
| Go SDK integration | **Done** — `AssignRole()` in pkg/authcore |
| Wrapper SDKs | **Done** — Java, .NET, Node.js, Python all include RBAC methods |
