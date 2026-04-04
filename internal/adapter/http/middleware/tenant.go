package middleware

import (
	"log/slog"
	"net/http"

	tenantsvc "github.com/authplex/internal/application/tenant"
	"github.com/authplex/internal/config"
	"github.com/authplex/internal/domain/shared"
	"github.com/authplex/pkg/sdk/httputil"
)

// TenantResolver is middleware that extracts tenant from the request
// and injects it into the context.
type TenantResolver struct {
	tenantSvc *tenantsvc.Service
	mode      config.TenantMode
	logger    *slog.Logger
}

// NewTenantResolver creates a new TenantResolver middleware.
func NewTenantResolver(svc *tenantsvc.Service, mode config.TenantMode, logger *slog.Logger) *TenantResolver {
	return &TenantResolver{
		tenantSvc: svc,
		mode:      mode,
		logger:    logger,
	}
}

// Middleware returns an http.Handler middleware that resolves the tenant.
func (tr *TenantResolver) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var identifier string

		switch tr.mode {
		case config.TenantModeHeader:
			identifier = r.Header.Get("X-Tenant-ID")
			if identifier == "" {
				httputil.WriteError(w, httputil.MethodNotAllowed("X-Tenant-ID header is required")) //nolint:errcheck
				return
			}
		case config.TenantModeDomain:
			identifier = r.Host
			if identifier == "" {
				httputil.WriteError(w, httputil.MethodNotAllowed("Host header is required")) //nolint:errcheck
				return
			}
		}

		t, appErr := tr.tenantSvc.Resolve(r.Context(), identifier, tr.mode)
		if appErr != nil {
			tr.logger.Debug("tenant resolution failed", "identifier", identifier, "mode", tr.mode)
			httputil.WriteError(w, appErr) //nolint:errcheck
			return
		}

		ctx := shared.WithTenant(r.Context(), t.ID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
