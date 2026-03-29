# AuthCore — Deployment Guide

> **Image size:** ~15MB | **RAM:** <300MB | **Binary:** single static Go binary

---

## Table of Contents

- [Quick Start (Local)](#quick-start-local)
- [Docker Compose (Dev/Staging)](#docker-compose-devstaging)
- [Production Docker Compose](#production-docker-compose)
- [Kubernetes](#kubernetes)
- [AWS (ECS Fargate)](#aws-ecs-fargate)
- [GCP (Cloud Run)](#gcp-cloud-run)
- [Bare Metal / VPS](#bare-metal--vps)
- [Environment Variables](#environment-variables)
- [Production Checklist](#production-checklist)
- [Health Checks & Monitoring](#health-checks--monitoring)
- [Backup & Restore](#backup--restore)
- [Scaling Guide](#scaling-guide)
- [Deployment Models](#deployment-models)
- [Troubleshooting](#troubleshooting)

---

## Quick Start (Local)

```bash
# Build from source
make build

# Run in local mode (in-memory storage, no Postgres/Redis needed)
./bin/authcore
# → Listening on :8080, in-memory storage, dev mode

# Verify
curl http://localhost:8080/health
# → {"status":"up"}
```

---

## Docker Compose (Dev/Staging)

```bash
# Start Postgres + Redis
docker-compose up -d

# Build and run AuthCore
make build
AUTHCORE_ENV=staging \
AUTHCORE_DATABASE_DSN="postgres://authcore:authcore_dev@localhost:5432/authcore?sslmode=disable" \
AUTHCORE_REDIS_URL="redis://localhost:6379" \
./bin/authcore
```

Or use the Docker image:

```bash
# Build Docker image
make docker
# → authcore:latest (~15MB)

# Run with docker
docker run -p 8080:8080 \
  -e AUTHCORE_ENV=staging \
  -e AUTHCORE_DATABASE_DSN="postgres://authcore:authcore_dev@postgres:5432/authcore?sslmode=disable" \
  -e AUTHCORE_REDIS_URL="redis://redis:6379" \
  --network host \
  authcore:latest
```

---

## Production Docker Compose

```yaml
# docker-compose.prod.yml
services:
  authcore:
    image: authcore:latest
    ports:
      - "8080:8080"
    environment:
      AUTHCORE_ENV: production
      AUTHCORE_HTTP_PORT: 8080
      AUTHCORE_DATABASE_DSN: postgres://authcore:${DB_PASSWORD}@postgres:5432/authcore?sslmode=require
      AUTHCORE_REDIS_URL: redis://redis:6379
      AUTHCORE_ADMIN_API_KEY: ${ADMIN_API_KEY}
      AUTHCORE_ENCRYPTION_KEY: ${ENCRYPTION_KEY}
      AUTHCORE_ISSUER: https://auth.myapp.com
      AUTHCORE_CORS_ORIGINS: https://myapp.com,https://admin.myapp.com
      AUTHCORE_TENANT_MODE: header
      AUTHCORE_KEY_ROTATION_DAYS: 90
      AUTHCORE_SMTP_HOST: smtp.sendgrid.net
      AUTHCORE_SMTP_PORT: 587
      AUTHCORE_SMTP_USERNAME: apikey
      AUTHCORE_SMTP_PASSWORD: ${SENDGRID_API_KEY}
      AUTHCORE_SMTP_FROM: noreply@myapp.com
      AUTHCORE_SMS_PROVIDER: twilio
      AUTHCORE_SMS_ACCOUNT_ID: ${TWILIO_ACCOUNT_SID}
      AUTHCORE_SMS_AUTH_TOKEN: ${TWILIO_AUTH_TOKEN}
      AUTHCORE_SMS_FROM_NUMBER: ${TWILIO_FROM_NUMBER}
      AUTHCORE_WEBAUTHN_RP_ID: myapp.com
      AUTHCORE_WEBAUTHN_RP_NAME: MyApp
      AUTHCORE_WEBAUTHN_RP_ORIGINS: https://myapp.com
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    restart: always
    deploy:
      replicas: 2
      resources:
        limits:
          memory: 256M
          cpus: '0.5'
    healthcheck:
      test: ["CMD", "wget", "--no-verbose", "--tries=1", "--spider", "http://localhost:8080/health"]
      interval: 10s
      timeout: 5s
      retries: 3

  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: authcore
      POSTGRES_USER: authcore
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U authcore"]
      interval: 5s
      timeout: 5s
      retries: 5
    restart: always

  redis:
    image: redis:7-alpine
    command: redis-server --requirepass ${REDIS_PASSWORD}
    healthcheck:
      test: ["CMD", "redis-cli", "-a", "${REDIS_PASSWORD}", "ping"]
      interval: 5s
      timeout: 5s
      retries: 5
    restart: always

  nginx:
    image: nginx:alpine
    ports:
      - "443:443"
      - "80:80"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./certs:/etc/nginx/certs:ro
    depends_on:
      - authcore
    restart: always

volumes:
  pgdata:
```

Create `.env`:

```bash
DB_PASSWORD=strong-random-password-here
REDIS_PASSWORD=another-strong-password
ADMIN_API_KEY=your-admin-api-key-min-32-chars
ENCRYPTION_KEY=hex-encoded-32-byte-key
SENDGRID_API_KEY=SG.xxxxx
TWILIO_ACCOUNT_SID=ACxxxxx
TWILIO_AUTH_TOKEN=xxxxx
TWILIO_FROM_NUMBER=+1234567890
```

Start:

```bash
docker-compose -f docker-compose.prod.yml --env-file .env up -d
```

---

## Kubernetes

### Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: authcore
  labels:
    app: authcore
spec:
  replicas: 3
  selector:
    matchLabels:
      app: authcore
  template:
    metadata:
      labels:
        app: authcore
    spec:
      containers:
      - name: authcore
        image: authcore:latest
        ports:
        - containerPort: 8080
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "256Mi"
            cpu: "500m"
        env:
        - name: AUTHCORE_ENV
          value: production
        - name: AUTHCORE_ISSUER
          value: https://auth.myapp.com
        - name: AUTHCORE_CORS_ORIGINS
          value: https://myapp.com
        - name: AUTHCORE_TENANT_MODE
          value: header
        - name: AUTHCORE_KEY_ROTATION_DAYS
          value: "90"
        - name: AUTHCORE_DATABASE_DSN
          valueFrom:
            secretKeyRef:
              name: authcore-secrets
              key: database-dsn
        - name: AUTHCORE_REDIS_URL
          valueFrom:
            secretKeyRef:
              name: authcore-secrets
              key: redis-url
        - name: AUTHCORE_ADMIN_API_KEY
          valueFrom:
            secretKeyRef:
              name: authcore-secrets
              key: admin-api-key
        - name: AUTHCORE_ENCRYPTION_KEY
          valueFrom:
            secretKeyRef:
              name: authcore-secrets
              key: encryption-key
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 3
          periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: authcore
spec:
  selector:
    app: authcore
  ports:
  - port: 80
    targetPort: 8080
  type: ClusterIP
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: authcore
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  tls:
  - hosts: [auth.myapp.com]
    secretName: authcore-tls
  rules:
  - host: auth.myapp.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: authcore
            port:
              number: 80
```

### Secrets

```bash
kubectl create secret generic authcore-secrets \
  --from-literal=database-dsn='postgres://authcore:pass@postgres:5432/authcore?sslmode=require' \
  --from-literal=redis-url='redis://:pass@redis:6379' \
  --from-literal=admin-api-key='your-admin-key' \
  --from-literal=encryption-key='hex-32-byte-key'
```

### Sidecar Pattern

```yaml
# Add AuthCore as a sidecar in your app's pod
spec:
  containers:
  - name: my-app
    image: my-app:latest
    ports: [{containerPort: 3000}]
    env:
    - name: AUTHCORE_URL
      value: http://localhost:8080   # same pod, localhost

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

## AWS (ECS Fargate)

```bash
# 1. Push image to ECR
aws ecr get-login-password | docker login --username AWS --password-stdin $ECR_URI
docker tag authcore:latest $ECR_URI/authcore:latest
docker push $ECR_URI/authcore:latest

# 2. Create task definition (via console or CLI)
# - Image: $ECR_URI/authcore:latest
# - Port: 8080
# - CPU: 256 (.25 vCPU)
# - Memory: 512MB
# - Environment: from Secrets Manager

# 3. Create service
# - Cluster: your-cluster
# - Service: authcore
# - Desired count: 2
# - Load balancer: ALB with HTTPS listener
# - Health check: /health

# 4. Infrastructure
# - RDS PostgreSQL (db.t3.micro for dev, db.r5.large for prod)
# - ElastiCache Redis (cache.t3.micro for dev)
# - ALB with ACM certificate
```

**Estimated cost:**

| Component | Dev | Production |
|-----------|-----|-----------|
| Fargate (2 tasks) | $15/mo | $60/mo |
| RDS Postgres | $15/mo | $100/mo |
| ElastiCache Redis | $12/mo | $50/mo |
| ALB | $18/mo | $18/mo |
| **Total** | **~$60/mo** | **~$230/mo** |

---

## GCP (Cloud Run)

```bash
# 1. Build and push
gcloud builds submit --tag gcr.io/$PROJECT/authcore

# 2. Deploy
gcloud run deploy authcore \
  --image gcr.io/$PROJECT/authcore \
  --platform managed \
  --port 8080 \
  --memory 256Mi \
  --cpu 1 \
  --min-instances 1 \
  --max-instances 10 \
  --set-env-vars "AUTHCORE_ENV=production,AUTHCORE_ISSUER=https://auth.myapp.com" \
  --set-secrets "AUTHCORE_DATABASE_DSN=authcore-db-dsn:latest,AUTHCORE_ADMIN_API_KEY=authcore-admin-key:latest"

# 3. Infrastructure
# - Cloud SQL PostgreSQL
# - Memorystore Redis
# - Cloud Run with VPC connector for private DB access
```

**Estimated cost:** ~$40-80/mo (pay-per-request)

---

## Bare Metal / VPS

```bash
# 1. Build binary
make build VERSION=1.0.0

# 2. Copy to server
scp bin/authcore user@server:/opt/authcore/

# 3. Create systemd service
cat > /etc/systemd/system/authcore.service << 'EOF'
[Unit]
Description=AuthCore Identity Server
After=network.target postgresql.service redis.service

[Service]
Type=simple
User=authcore
Group=authcore
WorkingDirectory=/opt/authcore
ExecStart=/opt/authcore/authcore
Restart=always
RestartSec=5
LimitNOFILE=65536

Environment=AUTHCORE_ENV=production
Environment=AUTHCORE_HTTP_PORT=8080
Environment=AUTHCORE_ISSUER=https://auth.myapp.com
EnvironmentFile=/opt/authcore/.env

[Install]
WantedBy=multi-user.target
EOF

# 4. Start
systemctl daemon-reload
systemctl enable authcore
systemctl start authcore

# 5. Nginx reverse proxy with TLS
# See nginx.conf example below
```

### Nginx Configuration

```nginx
server {
    listen 443 ssl http2;
    server_name auth.myapp.com;

    ssl_certificate     /etc/letsencrypt/live/auth.myapp.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/auth.myapp.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

server {
    listen 80;
    server_name auth.myapp.com;
    return 301 https://$host$request_uri;
}
```

---

## Environment Variables

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `AUTHCORE_ENV` | `local` | No | `local`, `staging`, `production` |
| `AUTHCORE_HTTP_PORT` | `8080` | No | Server listen port |
| `AUTHCORE_ISSUER` | `http://localhost:8080` | **Yes (prod)** | OAuth issuer URL (must match your domain) |
| `AUTHCORE_DATABASE_DSN` | (Postgres default) | **Yes (prod)** | PostgreSQL connection string |
| `AUTHCORE_REDIS_URL` | `redis://localhost:6379` | No | Redis URL (omit for in-memory fallback) |
| `AUTHCORE_ADMIN_API_KEY` | (empty = no auth) | **Yes (prod)** | Management API authentication key |
| `AUTHCORE_ENCRYPTION_KEY` | (empty) | Recommended | AES-256-GCM key for encryption at rest (hex-encoded 32 bytes) |
| `AUTHCORE_TENANT_MODE` | `header` | No | `header` (X-Tenant-ID) or `domain` (Host header) |
| `AUTHCORE_CORS_ORIGINS` | `*` | **Yes (prod)** | Comma-separated allowed origins |
| `AUTHCORE_KEY_ROTATION_DAYS` | `90` | No | Automatic signing key rotation interval |
| `AUTHCORE_SMTP_HOST` | (empty) | For email | SMTP server for email OTP |
| `AUTHCORE_SMTP_PORT` | `587` | For email | SMTP port |
| `AUTHCORE_SMTP_USERNAME` | (empty) | For email | SMTP auth username |
| `AUTHCORE_SMTP_PASSWORD` | (empty) | For email | SMTP auth password |
| `AUTHCORE_SMTP_FROM` | `noreply@authcore.local` | For email | Sender email address |
| `AUTHCORE_SMS_PROVIDER` | (empty) | For SMS | `twilio` or empty (console) |
| `AUTHCORE_SMS_ACCOUNT_ID` | (empty) | For SMS | Twilio Account SID |
| `AUTHCORE_SMS_AUTH_TOKEN` | (empty) | For SMS | Twilio Auth Token |
| `AUTHCORE_SMS_FROM_NUMBER` | (empty) | For SMS | Twilio sender number |
| `AUTHCORE_WEBAUTHN_RP_ID` | `localhost` | For WebAuthn | Relying Party ID (your domain) |
| `AUTHCORE_WEBAUTHN_RP_NAME` | `AuthCore` | For WebAuthn | Display name in browser prompt |
| `AUTHCORE_WEBAUTHN_RP_ORIGINS` | `http://localhost:8080` | For WebAuthn | Comma-separated allowed origins |

### Generating Secrets

```bash
# Admin API key (32+ characters)
openssl rand -base64 32

# Encryption key (32 bytes, hex-encoded)
openssl rand -hex 32

# Database password
openssl rand -base64 24
```

---

## Production Checklist

### Security

- [ ] `AUTHCORE_ADMIN_API_KEY` is set (non-empty, 32+ chars)
- [ ] `AUTHCORE_ENCRYPTION_KEY` is set (protects sensitive data at rest)
- [ ] `AUTHCORE_CORS_ORIGINS` lists specific domains (not `*`)
- [ ] `AUTHCORE_ISSUER` matches your public domain (e.g., `https://auth.myapp.com`)
- [ ] TLS termination configured (nginx/ALB/CloudFront in front)
- [ ] Database connection uses `sslmode=require`
- [ ] Redis connection uses password authentication
- [ ] All secrets stored in secret manager (not in env files on disk)
- [ ] `AUTHCORE_ENV` set to `production` (error-level JSON logging)

### Infrastructure

- [ ] PostgreSQL provisioned with automatic backups
- [ ] Redis provisioned (optional — falls back to in-memory)
- [ ] At least 2 AuthCore instances for availability
- [ ] Health check configured on load balancer (`GET /health`)
- [ ] DNS pointed to load balancer
- [ ] TLS certificate provisioned (Let's Encrypt / ACM)

### Operations

- [ ] Log aggregation configured (stdout → CloudWatch / Datadog / ELK)
- [ ] Alerts on health check failures
- [ ] Database backup schedule (daily minimum)
- [ ] Tested disaster recovery (restore from backup)
- [ ] Graceful shutdown verified (SIGTERM → 15s drain)

### Pre-launch Verification

```bash
# 1. Health check
curl https://auth.myapp.com/health
# → {"status":"up"}

# 2. Create tenant
curl -X POST https://auth.myapp.com/tenants \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"id":"prod","domain":"myapp.com","issuer":"https://auth.myapp.com","algorithm":"RS256"}'

# 3. OIDC discovery
curl -H "X-Tenant-ID: prod" https://auth.myapp.com/.well-known/openid-configuration

# 4. JWKS
curl -H "X-Tenant-ID: prod" https://auth.myapp.com/jwks

# 5. Register test user
curl -X POST https://auth.myapp.com/register \
  -H "X-Tenant-ID: prod" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@myapp.com","password":"test123","name":"Test"}'

# 6. Login
curl -X POST https://auth.myapp.com/login \
  -H "X-Tenant-ID: prod" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@myapp.com","password":"test123"}'
```

---

## Health Checks & Monitoring

### Endpoints

| Endpoint | Purpose | Auth Required |
|----------|---------|---------------|
| `GET /health` | Liveness + readiness | No |

### Logging

| Environment | Level | Format |
|-------------|-------|--------|
| `local` | DEBUG | Text (human-readable) |
| `staging` | INFO | JSON (structured) |
| `production` | ERROR | JSON + trace IDs |

### Key Metrics to Monitor

| Metric | Source | Alert Threshold |
|--------|--------|-----------------|
| HTTP 5xx rate | Access logs | > 1% of requests |
| Response latency (p99) | Access logs | > 500ms |
| Health check | `/health` | Any failure |
| Postgres connections | DB metrics | > 80% pool used |
| Redis memory | Redis INFO | > 80% maxmemory |
| Auth failure rate | Audit logs (`login_failure`) | Sudden spike |

### OpenTelemetry

AuthCore includes OTel tracing middleware. Export traces to Jaeger, Zipkin, or any OTLP collector:

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=http://jaeger:4318 \
./bin/authcore
```

---

## Backup & Restore

### Postgres Backup

```bash
# Daily backup (add to cron)
pg_dump -h localhost -U authcore authcore | gzip > backup-$(date +%Y%m%d).sql.gz

# Restore
gunzip < backup-20260329.sql.gz | psql -h localhost -U authcore authcore
```

### Redis (Optional)

Redis stores ephemeral data (sessions, OTP codes). It can be rebuilt from scratch — no backup required. If you want session persistence across restarts:

```bash
# Redis RDB snapshot
redis-cli BGSAVE
cp /var/lib/redis/dump.rdb backup-redis-$(date +%Y%m%d).rdb
```

### What's in Each Store

| Store | Data | Loss Impact |
|-------|------|------------|
| Postgres | Users, tenants, clients, keys, refresh tokens, providers, roles, audit | **Critical** — permanent data loss |
| Redis | Sessions, auth codes, OTP codes, device codes, blacklist | **Minor** — users re-login, codes re-issue |
| In-memory | Same as Redis when Redis unavailable | Lost on restart |

---

## Scaling Guide

### Horizontal Scaling

AuthCore is **stateless** — add more instances behind a load balancer.

```
              ┌──────────────┐
              │ Load Balancer │
              └──────┬───────┘
         ┌───────────┼───────────┐
         │           │           │
    ┌────▼───┐  ┌────▼───┐  ┌───▼────┐
    │AC-1    │  │AC-2    │  │AC-3    │
    │:8080   │  │:8080   │  │:8080   │
    └────┬───┘  └────┬───┘  └───┬────┘
         └───────────┼───────────┘
              ┌──────┴──────┐
              │  Postgres   │
              │  + Redis    │
              └─────────────┘
```

### Sizing Guide

| Users | AuthCore Instances | Postgres | Redis | Est. Cost |
|-------|-------------------|----------|-------|-----------|
| 1K | 1 | db.t3.micro | cache.t3.micro | ~$30/mo |
| 10K | 2 | db.t3.small | cache.t3.micro | ~$60/mo |
| 100K | 3-5 | db.r5.large | cache.r5.large | ~$200/mo |
| 1M | 10-20 | db.r5.xlarge + replicas | cache.r5.xlarge cluster | ~$800/mo |

### Bottleneck Analysis

| Bottleneck | Symptom | Fix |
|-----------|---------|-----|
| CPU | High latency on bcrypt/JWT signing | Add AuthCore instances |
| Postgres connections | Connection pool exhaustion | Increase pool size, add PgBouncer |
| Postgres reads | Slow list/query operations | Add read replicas |
| Redis memory | OOM errors | Increase instance size, shorter TTLs |

---

## Deployment Models

### 1. Standalone Service (Most Common)

AuthCore runs as its own service. Your apps call it via HTTP.

**Best for:** Most teams. Simple, clear boundary.

### 2. Sidecar (Kubernetes)

AuthCore runs in the same pod as your app. `localhost:8080`, sub-ms latency.

**Best for:** Microservices where each service needs auth. ~15MB, ~128Mi RAM overhead per pod.

### 3. Edge Auth (API Gateway)

AuthCore sits behind/inside your API gateway. All auth happens at the edge.

**Best for:** Teams already using Kong, Envoy, or Traefik. Backend services just read JWT claims.

### 4. Embedded (Go SDK)

AuthCore is a library inside your Go app. No separate process.

**Best for:** Go monoliths. Zero network overhead.

---

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| `health` returns 503 | Database unreachable | Check `AUTHCORE_DATABASE_DSN`, verify Postgres is running |
| `connection refused` on :8080 | AuthCore not started | Check logs: `journalctl -u authcore` or `docker logs authcore` |
| 401 on management endpoints | Wrong or missing API key | Verify `AUTHCORE_ADMIN_API_KEY` matches your `Authorization: Bearer` header |
| CORS errors in browser | Origins not configured | Set `AUTHCORE_CORS_ORIGINS` to your frontend domain |
| JWT verification fails | Issuer mismatch | Ensure `AUTHCORE_ISSUER` matches the `iss` claim clients expect |
| Sessions lost on restart | No Redis configured | Set `AUTHCORE_REDIS_URL` for persistent sessions |
| "no active key pair" | Keys not provisioned | Create a tenant — keys are auto-provisioned on first use |
| Migrations fail | Database permissions | Ensure DB user has CREATE TABLE privileges |
| Rate limit 429 | Too many requests from same IP | Legitimate traffic: increase limit. Attack: add WAF/firewall |
| Email OTP not received | SMTP not configured | Set `AUTHCORE_SMTP_*` variables, or check console logs for OTP code (dev mode) |

### Useful Debug Commands

```bash
# Check AuthCore logs
docker logs authcore --tail 100 -f

# Check database connectivity
psql $AUTHCORE_DATABASE_DSN -c "SELECT 1"

# Check Redis connectivity
redis-cli -u $AUTHCORE_REDIS_URL ping

# Check migrations status
psql $AUTHCORE_DATABASE_DSN -c "SELECT * FROM schema_migrations ORDER BY id"

# Count users
psql $AUTHCORE_DATABASE_DSN -c "SELECT tenant_id, COUNT(*) FROM users GROUP BY tenant_id"

# Recent audit events
psql $AUTHCORE_DATABASE_DSN -c "SELECT action, actor_id, timestamp FROM audit_events ORDER BY timestamp DESC LIMIT 10"
```
