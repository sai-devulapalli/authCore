# AuthPlex Security

**This is the main security landing page for AuthPlex.**

---

## Security Documentation Index

| Document | Description |
|----------|-------------|
| [THREAT_MODEL.md](./THREAT_MODEL.md) | STRIDE threat analysis — top 10 threats with mitigations and residual risk |
| [PENTEST_CHECKLIST.md](./PENTEST_CHECKLIST.md) | 48-item penetration testing checklist across 9 attack categories |
| [COMPLIANCE.md](./COMPLIANCE.md) | Gap analysis: OWASP ASVS L2, HIPAA, SOC 2 Type II, GDPR |
| [HARDENING.md](./HARDENING.md) | Step-by-step production hardening: Redis, Postgres, TLS, secrets, Docker |
| [INCIDENT_RESPONSE.md](./INCIDENT_RESPONSE.md) | Playbook for 5 incident scenarios with exact commands |

---

## Reporting a Vulnerability

AuthPlex takes security vulnerabilities seriously. If you have found a security issue, please **do not open a public GitHub issue**. Follow the responsible disclosure process below.

### How to Report

**Email:** security@authplex.io  
**Response time:** We will acknowledge your report within 48 hours  
**PGP Key:** Available at `https://authplex.io/.well-known/pgp-key.asc`

### What to Include in Your Report

Please include as much of the following as possible:

1. **Description** — A clear description of the vulnerability
2. **Reproduction steps** — Step-by-step instructions to reproduce the issue
3. **Impact** — What an attacker could achieve by exploiting this
4. **Affected version(s)** — Which version(s) of AuthPlex are affected
5. **Suggested fix** — If you have one (optional but appreciated)
6. **Your contact information** — So we can follow up and credit you

### What You Can Expect

- Acknowledgment within **48 hours** of your report
- Initial triage and severity assessment within **5 business days**
- Regular updates on remediation progress
- Credit in the release notes (unless you prefer to remain anonymous)
- We will not take legal action against researchers acting in good faith

### Coordinated Disclosure

We follow a **90-day coordinated disclosure** timeline:

1. We receive your report
2. We confirm the vulnerability and develop a fix
3. We release the fix (targeting within the SLA below)
4. You may publish your findings after the fix is released, or after 90 days, whichever comes first

If you need to disclose sooner due to active exploitation, please let us know and we will expedite.

---

## Vulnerability Severity Definitions

| Severity | CVSS Score Range | Definition | Example |
|----------|-----------------|------------|---------|
| **Critical** | 9.0–10.0 | Remote code execution, authentication bypass affecting all tenants, complete data exposure | JWT alg:none accepted; tenant isolation bypass |
| **High** | 7.0–8.9 | Significant data exposure, privilege escalation within a tenant, major auth control bypass | Admin key accepted in URL params; TOTP replay |
| **Medium** | 4.0–6.9 | Limited data exposure, partial auth bypass, logic errors with limited impact | Audit log missing event types; CORS misconfiguration |
| **Low** | 0.1–3.9 | Minor information disclosure, hardening recommendations, missing headers | Missing security header; verbose error messages |
| **Informational** | N/A | Best practice suggestions, configuration improvements | Missing rate limit on non-sensitive endpoint |

---

## Fix SLA by Severity

| Severity | Target Fix Time | Release Type |
|----------|----------------|--------------|
| Critical | 24 hours | Emergency patch release |
| High | 7 days | Patch release |
| Medium | 30 days | Minor release |
| Low | 90 days | Minor or major release |
| Informational | 180 days or by request | Documentation update |

These are targets. For critical vulnerabilities we may release a workaround or mitigation within hours while a full fix is developed.

---

## Scope — What Is In Scope for Security Research

The following are **in scope** for responsible disclosure:

| Target | Scope |
|--------|-------|
| All 49 AuthPlex HTTP endpoints | ✅ In scope |
| OAuth 2.0 / OIDC flows | ✅ In scope |
| MFA implementation (TOTP, WebAuthn) | ✅ In scope |
| RBAC and tenant isolation | ✅ In scope |
| Audit log integrity | ✅ In scope |
| Admin API security | ✅ In scope |
| SAML SP implementation | ✅ In scope |
| Webhook delivery security | ✅ In scope |
| Cryptographic implementation (`pkg/sdk/crypto`) | ✅ In scope |
| Docker image security | ✅ In scope |

The following are **out of scope**:

| Out of Scope | Reason |
|-------------|--------|
| Denial of service attacks (volumetric) | Not actionable as code vulnerability |
| Social engineering of AuthPlex team | Not a code vulnerability |
| Physical attacks on infrastructure | Out of scope for software |
| Vulnerabilities in third-party dependencies | Report to the respective project; notify us too |
| Issues requiring physical access to the server | Out of scope |
| Self-inflicted vulnerabilities (operator misconfiguration) | Document in `HARDENING.md` instead |
| Findings from scanning a production deployment you do not own | Unauthorized testing is illegal |

### Testing Guidelines

- **Always test against your own deployment** — never against production systems you do not own
- Use the in-memory mode (`make build && ./bin/authplex`) for rapid local testing
- Use Docker Compose for a realistic environment: `docker-compose up`
- Do not attempt to exploit vulnerabilities beyond proof-of-concept (read, do not modify or delete data)
- Do not store or share any test data that resembles real user data

---

## Security Architecture Summary

| Control | Implementation |
|---------|---------------|
| **Password hashing** | bcrypt cost 12 (`golang.org/x/crypto/bcrypt`) |
| **Secret encryption** | AES-256-GCM with `crypto/rand` IV per encryption |
| **Token generation** | `crypto/rand` — 256-bit entropy minimum |
| **JWT signing** | RSA-2048+ or ECDSA P-256 (stdlib `crypto/rsa`, `crypto/ecdsa`) |
| **PKCE** | S256 mandatory — plain PKCE not accepted |
| **SQL injection** | Parameterized queries throughout (`pgx` driver) |
| **Tenant isolation** | `tenant_id` in all queries + Postgres RLS |
| **Timing attacks** | `crypto/subtle.ConstantTimeCompare` for all secret comparisons |
| **Rate limiting** | 20 req/min per TCP `RemoteAddr` (not spoofable via headers) |
| **Security headers** | HSTS, CSP `default-src 'none'`, X-Frame-Options DENY, X-Content-Type-Options nosniff |
| **OTP security** | 5-attempt limit, single-use, 5-minute TTL |
| **Audit logging** | 25+ event types, slog structured format, no secrets in logs |
| **Dependencies** | Minimal — stdlib crypto preferred over third-party JWT libs |

---

## security.txt

This file should be deployed at `/.well-known/security.txt` on your AuthPlex deployment. If you are using nginx as a reverse proxy, add:

```nginx
location /.well-known/security.txt {
    return 200 "Contact: security@authplex.io\nPreferred-Languages: en\nPolicy: https://github.com/sai-devulapalli/authplex/blob/main/docs/security/SECURITY.md\nExpires: 2027-04-05T00:00:00Z\n";
    add_header Content-Type text/plain;
}
```

Or serve the following file at `/.well-known/security.txt`:

```
Contact: security@authplex.io
Preferred-Languages: en
Policy: https://github.com/sai-devulapalli/authplex/blob/main/docs/security/SECURITY.md
Expires: 2027-04-05T00:00:00Z
```

---

## Known Security Limitations

The following are known limitations that operators should be aware of. These are documented gaps, not undisclosed vulnerabilities.

| Limitation | Impact | Workaround | Tracked In |
|------------|--------|-----------|------------|
| Redis AUTH not enforced at startup | Unauthenticated Redis accessible | Enforce via deployment config | `COMPLIANCE.md` gap #1 |
| Admin API key has no expiry | Long-lived key if not rotated | Manual rotation per `HARDENING.md` | `COMPLIANCE.md` gap #2 |
| ROPC grant enabled | Password grant allows client-side credential handling | Disable for high-security tenants if supported | `THREAT_MODEL.md` T-01 |
| SAML SP mode only | Cannot act as SAML IdP | Use OIDC flows for IdP functionality | Architecture decision |
| No SCIM support | Manual user provisioning | Use Admin API for user management | Roadmap |
| No built-in Prometheus metrics | Limited observability | Parse structured logs with a log aggregator | Roadmap |
| TOTP same-window replay possible | Within 30s, same code can be reused | Short window limits impact | `COMPLIANCE.md` gap #3 |

---

## Hall of Fame

We recognize security researchers who have responsibly disclosed vulnerabilities to us.

*No findings reported yet. Be the first.*

| Researcher | Severity | Finding | Date |
|------------|----------|---------|------|
| — | — | — | — |

---

## Security Contacts

| Role | Contact |
|------|---------|
| Security disclosures | security@authplex.io |
| General security questions | security@authplex.io |
| GDPR/Privacy inquiries | privacy@authplex.io |
| Emergency (active breach) | security@authplex.io with subject `[URGENT]` |

*Response times: Emergency — 4 hours | Security disclosure — 48 hours | General inquiry — 5 business days*
