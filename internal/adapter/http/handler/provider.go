package handler

import (
	"net/http"

	providersvc "github.com/authplex/internal/application/provider"
	"github.com/authplex/pkg/sdk/httputil"
)

// ProviderHandler serves the identity provider management API.
type ProviderHandler struct {
	svc *providersvc.Service
}

// NewProviderHandler creates a new ProviderHandler.
func NewProviderHandler(svc *providersvc.Service) *ProviderHandler {
	return &ProviderHandler{svc: svc}
}

// HandleProviders serves /tenants/{tenant_id}/providers (POST, GET).
func (h *ProviderHandler) HandleProviders(w http.ResponseWriter, r *http.Request) {
	tenantID := extractPathSegment(r.URL.Path, "tenants", 1)
	if tenantID == "" {
		httputil.WriteError(w, httputil.MethodNotAllowed("tenant_id is required")) //nolint:errcheck
		return
	}

	switch r.Method {
	case http.MethodPost:
		var req providersvc.CreateProviderRequest
		if appErr := httputil.DecodeJSON(r, &req); appErr != nil {
			httputil.WriteError(w, appErr) //nolint:errcheck
			return
		}
		req.TenantID = tenantID
		created, appErr := h.svc.Create(r.Context(), req)
		if appErr != nil {
			httputil.WriteError(w, appErr) //nolint:errcheck
			return
		}
		httputil.WriteJSON(w, http.StatusCreated, created) //nolint:errcheck

	case http.MethodGet:
		providers, appErr := h.svc.List(r.Context(), tenantID)
		if appErr != nil {
			httputil.WriteError(w, appErr) //nolint:errcheck
			return
		}
		httputil.WriteJSON(w, http.StatusOK, providers) //nolint:errcheck

	default:
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
	}
}

// HandleProvider serves /tenants/{tenant_id}/providers/{provider_id} (GET, DELETE).
func (h *ProviderHandler) HandleProvider(w http.ResponseWriter, r *http.Request) {
	tenantID := extractPathSegment(r.URL.Path, "tenants", 1)
	providerID := extractPathSegment(r.URL.Path, "providers", 1)
	if tenantID == "" || providerID == "" {
		httputil.WriteError(w, httputil.MethodNotAllowed("tenant_id and provider_id are required")) //nolint:errcheck
		return
	}

	switch r.Method {
	case http.MethodGet:
		resp, appErr := h.svc.Get(r.Context(), providerID, tenantID)
		if appErr != nil {
			httputil.WriteError(w, appErr) //nolint:errcheck
			return
		}
		httputil.WriteJSON(w, http.StatusOK, resp) //nolint:errcheck

	case http.MethodDelete:
		if appErr := h.svc.Delete(r.Context(), providerID, tenantID); appErr != nil {
			httputil.WriteError(w, appErr) //nolint:errcheck
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
	}
}
