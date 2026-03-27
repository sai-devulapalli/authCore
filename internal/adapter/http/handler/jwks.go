package handler

import (
	"net/http"

	"github.com/authcore/internal/application/jwks"
	"github.com/authcore/internal/domain/shared"
	"github.com/authcore/pkg/sdk/httputil"
)

// JWKSHandler serves the JSON Web Key Set endpoint.
type JWKSHandler struct {
	svc *jwks.Service
}

// NewJWKSHandler creates a new JWKSHandler.
func NewJWKSHandler(svc *jwks.Service) *JWKSHandler {
	return &JWKSHandler{svc: svc}
}

// HandleJWKS serves GET /jwks.
// Uses WriteRaw because the response must match RFC 7517 exactly (no envelope).
func (h *JWKSHandler) HandleJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	// Tenant ID resolution: context → header → query param → "default"
	tenantID, ok := shared.TenantFromContext(r.Context())
	if !ok {
		tenantID = r.Header.Get("X-Tenant-ID")
		if tenantID == "" {
			tenantID = r.URL.Query().Get("tenant_id")
		}
		if tenantID == "" {
			tenantID = "default"
		}
	}

	set, appErr := h.svc.GetJWKS(r.Context(), tenantID)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	httputil.WriteRaw(w, http.StatusOK, set) //nolint:errcheck
}
