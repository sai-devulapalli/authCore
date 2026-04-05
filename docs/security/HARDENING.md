# AuthPlex Production Hardening Guide

**Version:** 1.0  
**Date:** 2026-04-05  
**Audience:** Platform engineers and DevOps teams deploying AuthPlex in production

This guide provides exact commands and configuration to harden an AuthPlex deployment. Follow each section in order; all sections are cumulative.

---

## 1. Redis AUTH Enforcement

**Why it matters:** An unauthenticated Redis instance on a shared network exposes all session tokens, refresh tokens, MFA challenge state, and OTP codes. An attacker with Redis access can impersonate any authenticated user. See threat T-06 in `THREAT_MODEL.md`.

### 1.1 Configure Redis with a Strong Password

```ini
# /etc/redis/redis.conf or redis.conf in Docker volume

# Require authentication
requirepass "$(openssl rand -hex 32)"  # generate and store this securely

# Bind to specific interface — never 0.0.0.0 in production
bind 127.0.0.1 ::1

# Disable dangerous commands
rename-command FLUSHALL ""
rename-command FLUSHDB  ""
rename-command CONFIG   "CONFIG_DISABLED_PROD"
rename-command DEBUG    ""
rename-command SLAVEOF  ""
rename-command REPLICAOF ""

# Disable persistence if Redis is used as cache only (reduces risk of RDBMS file exfil)
# Comment out if you need persistence for session durability across restarts:
# save ""
# appendonly no

# Limit max memory to prevent OOM-driven eviction of security-critical keys
maxmemory 512mb
maxmemory-policy allkeys-lru
```

### 1.2 Create a Least-Privilege Redis User (ACL)

```bash
# Connect as default admin user and create a scoped ACL
redis-cli -a "${REDIS_ADMIN_PASSWORD}" <<EOF
ACL SETUSER authplex ON >"${AUTHPLEX_REDIS_PASSWORD}" \
  ~authplex:* \
  +GET +SET +DEL +EXISTS +EXPIRE +TTL +KEYS \
  +INCR +INCRBY \
  +LPUSH +LRANGE +LREM \
  -@all +@read +@write -@dangerous
ACL SAVE
EOF
```

### 1.3 Set AuthPlex Redis URL

```bash
# Format: redis://:password@host:port/db
# Note the colon before the password (no username for default ACL user)
export AUTHPLEX_REDIS_URL="redis://:${AUTHPLEX_REDIS_PASSWORD}@redis:6379/0"

# For ACL user:
export AUTHPLEX_REDIS_URL="redis://authplex:${AUTHPLEX_REDIS_PASSWORD}@redis:6379/0"
```

### 1.4 Startup Validation (add to AuthPlex config validation)

AuthPlex should refuse to start if Redis is configured without credentials in production. Add this check:

```go
// internal/config/validate.go
if cfg.Env == "production" && cfg.Redis.URL != "" {
    u, err := url.Parse(cfg.Redis.URL)
    if err != nil || u.User == nil || u.User.Password() == "" {
        return fmt.Errorf("production: AUTHPLEX_REDIS_URL must include credentials (redis://:password@host:port/db)")
    }
}
```

---

## 2. Postgres Least-Privilege Setup

**Why it matters:** Running AuthPlex with a Postgres superuser means a SQL injection or code execution vulnerability could drop tables, exfiltrate all data, or write files. Least-privilege limits blast radius.

### 2.1 Create a Dedicated Role

```sql
-- Run as postgres superuser

-- Application role (no login, used for GRANT inheritance)
CREATE ROLE authplex_role NOLOGIN;

-- Application user
CREATE ROLE authplex_app
    LOGIN
    PASSWORD 'use_a_strong_random_password_here'
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE
    CONNECTION LIMIT 50;

GRANT authplex_role TO authplex_app;
```

### 2.2 Grant Minimum Necessary Privileges

```sql
-- Connect to the authplex database
\c authplex

-- Schema usage
GRANT USAGE ON SCHEMA public TO authplex_role;

-- Grant only what the app needs (no DDL)
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO authplex_role;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO authplex_role;

-- For future tables created by migrations:
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO authplex_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO authplex_role;

-- Explicitly deny dangerous operations:
REVOKE CREATE ON SCHEMA public FROM authplex_role;
REVOKE ALL ON SCHEMA pg_catalog FROM authplex_role;
```

### 2.3 Row-Level Security (Defense-in-Depth)

```sql
-- Enable RLS on all tenant-scoped tables
-- Example for the users table:

ALTER TABLE users ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON users
    USING (tenant_id = current_setting('authplex.tenant_id')::uuid);

-- AuthPlex sets this per-connection via:
-- SET LOCAL authplex.tenant_id = '<uuid>';

-- Repeat for all tenant-scoped tables:
-- clients, oauth_codes, sessions, refresh_tokens, rbac_assignments,
-- audit_events, webhooks, mfa_totp_secrets, webauthn_credentials, etc.
```

### 2.4 Separate Migration User

```sql
-- Migration tool (Flyway, goose, etc.) gets DDL privileges
CREATE ROLE authplex_migrate
    LOGIN
    PASSWORD 'use_a_different_strong_password'
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE;

GRANT CREATE ON SCHEMA public TO authplex_migrate;
GRANT ALL ON ALL TABLES IN SCHEMA public TO authplex_migrate;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO authplex_migrate;
```

Run migrations with `authplex_migrate`, application with `authplex_app`. Never use the same credentials for both.

---

## 3. TLS Configuration (nginx Reverse Proxy)

**Why it matters:** AuthPlex binds to HTTP internally. TLS must be terminated by a reverse proxy. Weak TLS configuration allows downgrade attacks, BEAST, POODLE, and similar protocol-level attacks.

### 3.1 nginx.conf — TLS Hardening Block

```nginx
# /etc/nginx/conf.d/authplex.conf

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name auth.example.com;

    # Certificate (use Let's Encrypt via Certbot or cert-manager in K8s)
    ssl_certificate     /etc/letsencrypt/live/auth.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/auth.example.com/privkey.pem;

    # Protocol: TLS 1.2 minimum, TLS 1.3 preferred
    ssl_protocols TLSv1.2 TLSv1.3;

    # Ciphers: modern profile (TLS 1.2 forward-secret + AEAD only)
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;  # Let client choose in TLS 1.3

    # DH parameters (for DHE cipher)
    ssl_dhparam /etc/nginx/dhparam.pem;  # openssl dhparam -out /etc/nginx/dhparam.pem 4096

    # Session cache (performance)
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;  # Disable for perfect forward secrecy

    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 8.8.8.8 8.8.4.4 valid=300s;
    resolver_timeout 5s;

    # Security headers (these supplement headers set by AuthPlex)
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
    add_header Content-Security-Policy "default-src 'none'; frame-ancestors 'none'" always;

    # Proxy to AuthPlex
    location / {
        proxy_pass http://authplex:8080;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        # Do NOT forward X-Forwarded-For — AuthPlex uses RemoteAddr for rate limiting
        # proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;  # Disabled intentionally
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeouts
        proxy_connect_timeout  5s;
        proxy_read_timeout     60s;
        proxy_send_timeout     60s;

        # Buffer settings
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
    }
}

# Redirect HTTP → HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name auth.example.com;
    return 301 https://$host$request_uri;
}
```

### 3.2 Generate DH Parameters

```bash
# One-time setup — takes several minutes
openssl dhparam -out /etc/nginx/dhparam.pem 4096
```

### 3.3 Verify TLS Configuration

```bash
# Test with testssl.sh
docker run --rm -ti drwetter/testssl.sh --full auth.example.com

# Or with sslyze
pip install sslyze
python -m sslyze auth.example.com:443
```

Expected grades: **A+** on SSL Labs (ssllabs.com/ssltest).

---

## 4. Admin API Key Rotation Policy

**Why it matters:** A long-lived, never-rotated admin key is a single point of compromise. If the key is exfiltrated, the attacker has indefinite admin access. See threat T-04 in `THREAT_MODEL.md`.

### 4.1 Key Format

```
authplex_admin_{random32hex}

Example: authplex_admin_a3f8e2c1d4b5a6f7e8d9c0b1a2e3f4d5
```

Generate a new key:
```bash
echo "authplex_admin_$(openssl rand -hex 32)"
```

### 4.2 Rotation Without Downtime (Dual-Key Window)

AuthPlex should support two active admin keys simultaneously during rotation. Until that feature is shipped, use this procedure:

```bash
# Step 1: Generate new key
NEW_KEY="authplex_admin_$(openssl rand -hex 32)"
echo "New key: ${NEW_KEY}"

# Step 2: Update the secret in your secrets manager FIRST
# AWS Secrets Manager:
aws secretsmanager update-secret \
  --secret-id authplex/admin-key \
  --secret-string "${NEW_KEY}"

# HashiCorp Vault:
vault kv put secret/authplex admin_key="${NEW_KEY}"

# Step 3: Update all consumers of the admin key (CI/CD, scripts, etc.)
# Allow a 1-hour transition window during business hours

# Step 4: Restart AuthPlex to pick up the new key
# (zero-downtime with multiple replicas: rolling restart)
kubectl rollout restart deployment/authplex

# Step 5: Verify new key works
curl -H "Authorization: Bearer ${NEW_KEY}" \
     https://auth.example.com/api/v1/admin/tenants

# Step 6: Revoke old key (update secret to remove it)
# Step 7: Record rotation in admin audit log
```

### 4.3 Rotation Schedule

| Environment | Rotation Interval | Trigger Events |
|-------------|------------------|----------------|
| Production | 90 days | Schedule + any suspected compromise |
| Staging | 180 days | Schedule |
| Development | On demand | Any team member departure |

Set a calendar reminder. Add a startup warning: log a `WARN` if the key was created more than 75 days ago (requires storing `key_created_at` alongside the key hash).

---

## 5. Secret Management

**Why it matters:** Secrets in Docker images, git repositories, or unencrypted environment variables are frequently exposed in breaches, CI logs, and container registries.

### 5.1 Required Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `AUTHPLEX_JWT_PRIVATE_KEY` | RSA/EC private key PEM | Yes |
| `AUTHPLEX_DB_URL` | Postgres connection string with credentials | Yes |
| `AUTHPLEX_ADMIN_KEY` | Admin API key | Yes |
| `AUTHPLEX_REDIS_URL` | Redis URL with password | Yes (if Redis used) |
| `AUTHPLEX_AES_KEY` | 32-byte AES key for secrets encryption (hex) | Yes |
| `AUTHPLEX_SMTP_PASSWORD` | SMTP server password | If email enabled |

### 5.2 What NEVER Goes in Environment Variables or Files

```
# These should NEVER be:
# - Committed to git (even in .env files)
# - Baked into Docker images (ENV in Dockerfile)
# - Written to docker-compose.yml plaintext
# - Printed in application logs
# - Exposed in /health or /debug endpoints

AUTHPLEX_JWT_PRIVATE_KEY  # use Vault/Secrets Manager
AUTHPLEX_AES_KEY           # use Vault/Secrets Manager
AUTHPLEX_ADMIN_KEY         # use Vault/Secrets Manager
```

### 5.3 HashiCorp Vault Agent Sidecar

```yaml
# kubernetes/authplex-deployment.yaml (partial)
spec:
  template:
    metadata:
      annotations:
        vault.hashicorp.com/agent-inject: "true"
        vault.hashicorp.com/role: "authplex-production"
        vault.hashicorp.com/agent-inject-secret-jwt-key: "secret/authplex/jwt-private-key"
        vault.hashicorp.com/agent-inject-template-jwt-key: |
          {{- with secret "secret/authplex/jwt-private-key" -}}
          {{ .Data.data.key }}
          {{- end }}
    spec:
      containers:
      - name: authplex
        image: ghcr.io/sai-devulapalli/authplex:latest
        env:
        - name: AUTHPLEX_JWT_PRIVATE_KEY_FILE
          value: /vault/secrets/jwt-key
```

### 5.4 AWS Secrets Manager

```yaml
# kubernetes/authplex-deployment.yaml with AWS Secrets Store CSI Driver
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: authplex-secrets
spec:
  provider: aws
  parameters:
    objects: |
      - objectName: "authplex/production/jwt-private-key"
        objectType: "secretsmanager"
        objectAlias: "jwt_private_key"
      - objectName: "authplex/production/admin-key"
        objectType: "secretsmanager"
        objectAlias: "admin_key"
      - objectName: "authplex/production/aes-key"
        objectType: "secretsmanager"
        objectAlias: "aes_key"
---
# Mount as volume in deployment
spec:
  containers:
  - name: authplex
    volumeMounts:
    - name: secrets-store
      mountPath: /mnt/secrets
      readOnly: true
  volumes:
  - name: secrets-store
    csi:
      driver: secrets-store.csi.k8s.io
      readOnly: true
      volumeAttributes:
        secretProviderClass: authplex-secrets
```

### 5.5 .gitignore and Pre-commit Hooks

```bash
# .gitignore
.env
.env.local
.env.production
*.pem
*.key
*_rsa
*_ecdsa
secrets/

# Install git-secrets to prevent accidental commits
brew install git-secrets
git secrets --install
git secrets --register-aws
git secrets --add 'authplex_admin_[a-f0-9]{32}'
git secrets --add 'AUTHPLEX_JWT_PRIVATE_KEY'
```

---

## 6. Log Sanitization Verification

**Why it matters:** Developers sometimes accidentally log authentication tokens, passwords, or API keys during debugging. These must be detected and removed before production.

### 6.1 Pre-Production Log Audit

Run this against your log output (test environment with realistic traffic first):

```bash
# Scan for sensitive patterns in log files
grep -iE 'password|passwd|secret|private.key|bearer |authorization:|api.key|token.*=|access.token' \
     /var/log/authplex/*.log | head -50

# Scan application source code for potential log leaks
grep -rn 'slog\.\|log\.' internal/ | \
  grep -iE 'password|token|secret|key|auth' | \
  grep -v '_test.go' | \
  grep -v '// '

# Run in CI as a gate:
! grep -rn 'slog\..*[Pp]assword\|slog\..*[Tt]oken\|slog\..*[Ss]ecret' internal/ --include="*.go" | grep -v '_test.go'
```

### 6.2 Patterns That Should Never Appear in Logs

```bash
# This script should produce zero matches in production logs
PATTERNS=(
    'password'
    'passwd'
    'Bearer [A-Za-z0-9._-]+'
    'Authorization: '
    'authplex_admin_'
    'client_secret'
    'refresh_token.*[A-Za-z0-9]{20}'
    'code_verifier'
    'private.*key'
    'BEGIN.*PRIVATE'
)

for pattern in "${PATTERNS[@]}"; do
    count=$(grep -ciE "${pattern}" /var/log/authplex/app.log 2>/dev/null || echo 0)
    if [ "${count}" -gt 0 ]; then
        echo "FAIL: Pattern '${pattern}' found ${count} times in logs"
    fi
done
```

### 6.3 Structured Log Field Audit

```bash
# For JSON logs (staging/production), check that sensitive fields are absent
cat /var/log/authplex/app.log | \
  jq 'select(.password != null or .token != null or .secret != null or .authorization != null)' | \
  head -20
```

Expected output: nothing (no results means no leaks).

---

## 7. Docker and Kubernetes Security Context

**Why it matters:** Running containers as root means any container escape gives the attacker root on the host. Read-only filesystem prevents an attacker from writing backdoors. Dropping capabilities reduces the kernel attack surface.

### 7.1 Dockerfile Security Hardening

```dockerfile
# multi-stage build — production image has no build tools
FROM golang:1.23-alpine AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o authplex ./cmd/authplex/

# Production image
FROM scratch

# Copy CA certificates for outbound TLS (webhook delivery, social login)
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy binary only — no shell, no package manager, no OS tools
COPY --from=builder /build/authplex /authplex

# Run as non-root user
# UID 65534 = 'nobody' — no home directory, no shell, no privileges
USER 65534:65534

EXPOSE 8080

ENTRYPOINT ["/authplex"]
```

### 7.2 Kubernetes Security Context

```yaml
# kubernetes/authplex-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: authplex
  namespace: auth
spec:
  replicas: 3
  selector:
    matchLabels:
      app: authplex
  template:
    metadata:
      labels:
        app: authplex
    spec:
      # Pod-level security
      securityContext:
        runAsNonRoot: true
        runAsUser: 65534
        runAsGroup: 65534
        fsGroup: 65534
        seccompProfile:
          type: RuntimeDefault

      # No service account token mounted (AuthPlex doesn't need K8s API access)
      automountServiceAccountToken: false

      containers:
      - name: authplex
        image: ghcr.io/sai-devulapalli/authplex:v1.0.0  # pin exact version, not :latest
        ports:
        - containerPort: 8080
          name: http

        # Container-level security
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          runAsNonRoot: true
          runAsUser: 65534
          capabilities:
            drop:
            - ALL  # drop every Linux capability

        # Resource limits (prevent resource exhaustion DoS)
        resources:
          requests:
            cpu: "100m"
            memory: "64Mi"
          limits:
            cpu: "500m"
            memory: "256Mi"

        # Readiness/liveness probes
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 10
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 30

        # Temp dir for scratch space (read-only root requires this)
        volumeMounts:
        - name: tmp
          mountPath: /tmp

      volumes:
      - name: tmp
        emptyDir: {}
```

### 7.3 Kubernetes Network Policy

```yaml
# kubernetes/authplex-netpol.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: authplex-netpol
  namespace: auth
spec:
  podSelector:
    matchLabels:
      app: authplex

  policyTypes:
  - Ingress
  - Egress

  ingress:
  # Allow ingress only from nginx ingress controller
  - from:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: ingress-nginx
    ports:
    - protocol: TCP
      port: 8080

  egress:
  # Allow DNS
  - to:
    - namespaceSelector: {}
    ports:
    - protocol: UDP
      port: 53
    - protocol: TCP
      port: 53

  # Allow Postgres
  - to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: data
    ports:
    - protocol: TCP
      port: 5432

  # Allow Redis
  - to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: data
    ports:
    - protocol: TCP
      port: 6379

  # Allow HTTPS for webhook delivery and social login
  - to:
    - namespaceSelector: {}
    ports:
    - protocol: TCP
      port: 443
```

### 7.4 Image Signing and Scanning

```bash
# Sign images with Cosign (Sigstore)
cosign sign --key cosign.key ghcr.io/sai-devulapalli/authplex:v1.0.0

# Verify before deployment
cosign verify --key cosign.pub ghcr.io/sai-devulapalli/authplex:v1.0.0

# Scan for CVEs
trivy image ghcr.io/sai-devulapalli/authplex:v1.0.0

# Expected: zero CRITICAL or HIGH CVEs (scratch base image has none)
```

---

## 8. Production Environment Checklist

Before going live, verify all items:

```
[ ] Redis AUTH enforced; startup fails without credentials
[ ] Postgres running as authplex_app (not superuser)
[ ] RLS enabled on all tenant-scoped tables
[ ] TLS 1.2+ enforced; TLS 1.0/1.1 disabled
[ ] HSTS header set with preload
[ ] Admin API key rotated from default; 90-day rotation scheduled
[ ] All secrets stored in Vault or Secrets Manager; not in .env files
[ ] No secrets committed to git (git-secrets installed)
[ ] Log audit run; no sensitive values in logs
[ ] Container running as UID 65534 (non-root)
[ ] Read-only root filesystem enabled
[ ] ALL capabilities dropped
[ ] Network policy applied; only port 8080 ingress
[ ] Resource limits set on all containers
[ ] Image signed with Cosign; CVE scan shows zero HIGH/CRITICAL
[ ] Backup verified (Postgres + Redis snapshot)
[ ] Health endpoint responding: GET /health → 200
[ ] Audit log ingesting to SIEM
[ ] govulncheck run in CI with zero findings
```
