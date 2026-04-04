package handler

import (
	"net/http"

	"github.com/authplex/internal/application/discovery"
	"github.com/authplex/internal/domain/shared"
	"github.com/authplex/pkg/sdk/httputil"
)

// DiscoveryHandler serves the OIDC discovery document.
type DiscoveryHandler struct {
	svc *discovery.Service
}

// NewDiscoveryHandler creates a new DiscoveryHandler.
func NewDiscoveryHandler(svc *discovery.Service) *DiscoveryHandler {
	return &DiscoveryHandler{svc: svc}
}

// HandleDiscovery serves GET /.well-known/openid-configuration.
// Uses WriteRaw because the response must match RFC 8414 exactly (no envelope).
func (h *DiscoveryHandler) HandleDiscovery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	// In multi-tenant mode, tenant issuer can come from context (set by middleware)
	// or from the X-Tenant-Issuer header.
	tenantIssuer := r.Header.Get("X-Tenant-Issuer")
	if tenantIssuer == "" {
		if _, ok := shared.TenantFromContext(r.Context()); ok {
			// Tenant resolved by middleware; issuer will be overridden per-tenant
			// once tenant service provides issuer lookup.
		}
	}
	doc := h.svc.GetDiscoveryDocument(tenantIssuer)

	httputil.WriteRaw(w, http.StatusOK, doc) //nolint:errcheck
}
