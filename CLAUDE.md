# AuthCore Development Guide

## Build & Test Commands
```bash
export PATH="/opt/homebrew/bin:$PATH"  # Go is at /opt/homebrew/bin/go
make build          # Build binary to ./bin/authcore
make test-unit      # Unit tests with coverage (excludes postgres/mssql adapters)
make test-func      # Functional tests (requires Docker for testcontainers)
make test-e2e       # E2E tests (141 subtests, in-memory + Docker variants)
make coverage-check # Enforce 80% line coverage threshold
make lint           # Run golangci-lint
make docker         # Build Docker image
```

## Architecture
- **Hexagonal Architecture**: domain (pure logic) -> application (use cases) -> adapter (infrastructure)
- **No panics**: All methods return `Result[T]` or `(T, error)`. Graceful failure only.
- **Test triad**: 85% unit (no build tag), 10% functional (`//go:build functional`), 5% e2e (`//go:build e2e`)
- **E2E tests**: NO mocks. Use real Postgres, Redis via testcontainers.
- **Logging**: slog-based. local=debug/text, staging=info/JSON, production=error/JSON+traces.
- **Dependencies**: Minimal — stdlib crypto, key external deps (env, testify, x/crypto, go-webauthn, crewjam/saml).

## Module Build Order
Each module must pass quality gates before proceeding to next:
1. Module 0: Scaffold & Quality Gates ✅
2. Module 1: Foundation SDK (pkg/sdk) ✅
3. Module 2: OIDC Discovery & JWKS ✅
4. Module 3: Token Issuance (Auth Code + PKCE) ✅
5. Module 4: Multi-Tenancy ✅
6. Module 5: Client Registry + All Grant Types + Token Lifecycle ✅
7. Module 6: Social Login (Google, GitHub, Microsoft, Apple, generic) ✅
8. Module 7a: MFA/2FA — TOTP (RFC 6238) ✅
9. Module 8: User Authentication (register, login, sessions, /userinfo) ✅
10. Module 7b: WebAuthn/FIDO2 ✅
11. GTM: Token Versioning + Postgres RBAC + Audit Wiring + Admin Auth + RLS + SAML ✅

## Current Stats
- **~262 Go files** (source + test)
- **791 test functions** across 45 packages (141 E2E subtests)
- **80%+ line coverage**
- **46 HTTP endpoints** (OIDC/OAuth + Management + MFA + WebAuthn + SAML + Admin)

## Quality Gates
- Line coverage >= 80%
- Branch coverage: exhaustive switch linter + all error paths tested
- Zero `panic()` in non-test code
- `make lint` passes with zero warnings

## Key Patterns
- `Result[T]` monad for error handling (`pkg/sdk/errors/result.go`)
- `AppError` with `ErrorCode` → HTTP status mapping (`pkg/sdk/errors/`)
- `WriteRaw` for OIDC/OAuth spec responses (bare JSON)
- `WriteJSON` for management API (data envelope)
- Port interfaces in domain packages, adapters implement them
- In-memory repos in `cmd/authcore/` for dev, Postgres repos in `adapter/postgres/`
- Functional options pattern for configuration (`With*` methods)

## Full Documentation
See `docs/README.md` for complete API reference, authentication flows, and architecture details.
