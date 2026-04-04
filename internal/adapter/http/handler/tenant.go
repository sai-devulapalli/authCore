package handler

import (
	"net/http"
	"strconv"
	"strings"

	tenantsvc "github.com/authplex/internal/application/tenant"
	"github.com/authplex/pkg/sdk/httputil"
)

// TenantHandler serves the tenant management API.
type TenantHandler struct {
	svc *tenantsvc.Service
}

// NewTenantHandler creates a new TenantHandler.
func NewTenantHandler(svc *tenantsvc.Service) *TenantHandler {
	return &TenantHandler{svc: svc}
}

// HandleTenants serves /tenants (POST, GET list).
func (h *TenantHandler) HandleTenants(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		h.createTenant(w, r)
	case http.MethodGet:
		h.listTenants(w, r)
	default:
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
	}
}

// HandleTenant serves /tenants/{id} (GET, PUT, DELETE).
func (h *TenantHandler) HandleTenant(w http.ResponseWriter, r *http.Request) {
	id := extractTenantID(r.URL.Path)
	if id == "" {
		httputil.WriteError(w, httputil.MethodNotAllowed("tenant ID is required")) //nolint:errcheck
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.getTenant(w, r, id)
	case http.MethodPut:
		h.updateTenant(w, r, id)
	case http.MethodDelete:
		h.deleteTenant(w, r, id)
	default:
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
	}
}

func (h *TenantHandler) createTenant(w http.ResponseWriter, r *http.Request) {
	var req tenantsvc.CreateTenantRequest
	if appErr := httputil.DecodeJSON(r, &req); appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	created, appErr := h.svc.Create(r.Context(), req)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	httputil.WriteJSON(w, http.StatusCreated, created) //nolint:errcheck
}

func (h *TenantHandler) listTenants(w http.ResponseWriter, r *http.Request) {
	offset, _ := strconv.Atoi(httputil.QueryParam(r, "offset", "0"))
	limit, _ := strconv.Atoi(httputil.QueryParam(r, "limit", "20"))

	tenants, total, appErr := h.svc.List(r.Context(), offset, limit)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"tenants": tenants,
		"total":   total,
		"offset":  offset,
		"limit":   limit,
	}) //nolint:errcheck
}

func (h *TenantHandler) getTenant(w http.ResponseWriter, r *http.Request, id string) {
	t, appErr := h.svc.Get(r.Context(), id)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	httputil.WriteJSON(w, http.StatusOK, t) //nolint:errcheck
}

func (h *TenantHandler) updateTenant(w http.ResponseWriter, r *http.Request, id string) {
	var req tenantsvc.UpdateTenantRequest
	if appErr := httputil.DecodeJSON(r, &req); appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	updated, appErr := h.svc.Update(r.Context(), id, req)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	httputil.WriteJSON(w, http.StatusOK, updated) //nolint:errcheck
}

func (h *TenantHandler) deleteTenant(w http.ResponseWriter, r *http.Request, id string) {
	if appErr := h.svc.Delete(r.Context(), id); appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// extractTenantID extracts the tenant ID from a URL path like /tenants/{id}.
func extractTenantID(path string) string {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) >= 2 && parts[0] == "tenants" {
		return parts[1]
	}
	return ""
}
