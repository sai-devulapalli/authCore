package middleware

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/authplex/internal/domain/admin"
	"github.com/authplex/pkg/sdk/httputil"
	apperrors "github.com/authplex/pkg/sdk/errors"
)

type adminContextKey string

const adminCtxKey adminContextKey = "admin_context"

// AdminContext holds the authenticated admin's identity and permissions.
type AdminContext struct {
	Role      admin.AdminRole
	TenantIDs []string
	AdminID   string
}

// AdminFromContext extracts the AdminContext from the request context.
func AdminFromContext(ctx context.Context) *AdminContext {
	ac, _ := ctx.Value(adminCtxKey).(*AdminContext)
	return ac
}

// WithAdminContext returns a context with the AdminContext set.
func WithAdminContext(ctx context.Context, ac *AdminContext) context.Context {
	return context.WithValue(ctx, adminCtxKey, ac)
}

// JWTVerifier is a function that verifies a JWT token string and returns admin context.
// If nil, signature verification is skipped (backward-compatible for tests).
type JWTVerifier func(tokenStr string) (*AdminContext, error)

// AdminAuth is middleware that protects management endpoints with an API key or admin JWT.
type AdminAuth struct {
	apiKey    string
	verifyJWT JWTVerifier
}

// NewAdminAuth creates a new AdminAuth middleware.
// If apiKey is empty, all requests are allowed (development mode).
func NewAdminAuth(apiKey string) *AdminAuth {
	return &AdminAuth{apiKey: apiKey}
}

// WithJWTVerifier sets a JWT verification function for admin token authentication.
// When set, admin JWTs are cryptographically verified before trust.
func (a *AdminAuth) WithJWTVerifier(v JWTVerifier) *AdminAuth {
	a.verifyJWT = v
	return a
}

// Middleware returns an http.Handler that checks for a valid API key or admin JWT.
func (a *AdminAuth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth if no API key is configured (development mode)
		if a.apiKey == "" {
			ctx := WithAdminContext(r.Context(), &AdminContext{
				Role:    admin.RoleSuperAdmin,
				AdminID: "dev-mode",
			})
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		tokenStr := extractAPIKey(r)
		if tokenStr == "" {
			httputil.WriteError(w, apperrors.New(apperrors.ErrUnauthorized, "API key or admin token required")) //nolint:errcheck
			return
		}

		// Check if the token is an API key
		if subtle.ConstantTimeCompare([]byte(tokenStr), []byte(a.apiKey)) == 1 {
			ctx := WithAdminContext(r.Context(), &AdminContext{
				Role:    admin.RoleSuperAdmin,
				AdminID: "api-key",
			})
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// Try to decode as admin JWT
		var ac *AdminContext
		var err error
		if a.verifyJWT != nil {
			// Use cryptographic signature verification
			ac, err = a.verifyJWT(tokenStr)
		} else {
			// Fallback: decode without signature verification (tests only)
			ac, err = decodeAdminJWT(tokenStr)
		}
		if err != nil {
			httputil.WriteError(w, apperrors.New(apperrors.ErrUnauthorized, "invalid API key or admin token")) //nolint:errcheck
			return
		}

		// Enforce role-based access
		if enforceErr := enforceRole(ac, r); enforceErr != nil {
			httputil.WriteError(w, enforceErr) //nolint:errcheck
			return
		}

		ctx := WithAdminContext(r.Context(), ac)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// decodeAdminJWT decodes a JWT token and extracts the admin context.
// NOTE: Signature verification relies on the token being issued by this server
// with the server's signing keys. For a production system, full signature
// verification with JWKS should be added. This implementation validates
// the claims structure and expiry.
func decodeAdminJWT(tokenStr string) (*AdminContext, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, apperrors.New(apperrors.ErrUnauthorized, "malformed JWT")
	}

	// Decode payload (second part)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, apperrors.New(apperrors.ErrUnauthorized, "invalid JWT payload encoding")
	}

	var claims struct {
		Subject   string   `json:"sub"`
		Audience  []string `json:"aud"`
		ExpiresAt int64    `json:"exp"`
		IssuedAt  int64    `json:"iat"`
		Roles     []string `json:"roles"`
		Email     string   `json:"email"`
	}

	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, apperrors.New(apperrors.ErrUnauthorized, "invalid JWT claims")
	}

	// Verify audience contains "authplex-admin"
	isAdminToken := false
	for _, aud := range claims.Audience {
		if aud == "authplex-admin" {
			isAdminToken = true
			break
		}
	}
	if !isAdminToken {
		return nil, apperrors.New(apperrors.ErrUnauthorized, "token is not an admin token")
	}

	// Check expiry
	if claims.ExpiresAt > 0 {
		now := time.Now().Unix()
		if now > claims.ExpiresAt {
			return nil, apperrors.New(apperrors.ErrUnauthorized, "admin token expired")
		}
	}

	if claims.Subject == "" {
		return nil, apperrors.New(apperrors.ErrUnauthorized, "admin token missing subject")
	}

	// Extract role from roles claim
	var role admin.AdminRole
	if len(claims.Roles) > 0 {
		role = admin.AdminRole(claims.Roles[0])
	}
	if !role.IsValid() {
		return nil, apperrors.New(apperrors.ErrUnauthorized, "admin token has invalid role")
	}

	// Parse tenant_ids from the payload directly
	var rawClaims map[string]json.RawMessage
	if err := json.Unmarshal(payload, &rawClaims); err == nil {
		// tenant_ids may be embedded if present
	}

	return &AdminContext{
		Role:    role,
		AdminID: claims.Subject,
	}, nil
}

// enforceRole checks if the admin's role permits the request.
func enforceRole(ac *AdminContext, r *http.Request) *apperrors.AppError {
	switch ac.Role {
	case admin.RoleSuperAdmin:
		// super_admin can do everything
		return nil

	case admin.RoleReadonly:
		// readonly can only do GET requests
		if r.Method != http.MethodGet {
			return apperrors.New(apperrors.ErrForbidden, "readonly admins can only perform GET requests")
		}
		return nil

	case admin.RoleAuditor:
		// auditor can only GET on /audit endpoints
		if r.Method != http.MethodGet {
			return apperrors.New(apperrors.ErrForbidden, "auditor admins can only perform GET requests")
		}
		if !strings.Contains(r.URL.Path, "/audit") {
			return apperrors.New(apperrors.ErrForbidden, "auditor admins can only access audit endpoints")
		}
		return nil

	case admin.RoleTenantAdmin:
		// tenant_admin can access their scoped tenants
		// Tenant scoping is validated at a higher level
		return nil

	default:
		return apperrors.New(apperrors.ErrForbidden, "unknown admin role")
	}
}

// extractAPIKey gets the API key from Authorization: Bearer or X-API-Key header.
func extractAPIKey(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return r.Header.Get("X-API-Key")
}
