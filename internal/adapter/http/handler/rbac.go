package handler

import (
	"net/http"

	rbacsvc "github.com/authcore/internal/application/rbac"
	"github.com/authcore/pkg/sdk/httputil"
)

// RBACHandler serves role and assignment management endpoints.
type RBACHandler struct {
	svc *rbacsvc.Service
}

// NewRBACHandler creates a new RBACHandler.
func NewRBACHandler(svc *rbacsvc.Service) *RBACHandler {
	return &RBACHandler{svc: svc}
}

// HandleRoles serves /tenants/{tid}/roles (POST, GET).
func (h *RBACHandler) HandleRoles(w http.ResponseWriter, r *http.Request) {
	tenantID := extractPathSegment(r.URL.Path, "tenants", 1)
	if tenantID == "" {
		httputil.WriteError(w, httputil.MethodNotAllowed("tenant_id is required")) //nolint:errcheck
		return
	}

	switch r.Method {
	case http.MethodPost:
		var req rbacsvc.CreateRoleRequest
		if appErr := httputil.DecodeJSON(r, &req); appErr != nil {
			httputil.WriteError(w, appErr) //nolint:errcheck
			return
		}
		req.TenantID = tenantID
		resp, appErr := h.svc.CreateRole(r.Context(), req)
		if appErr != nil {
			httputil.WriteError(w, appErr) //nolint:errcheck
			return
		}
		httputil.WriteJSON(w, http.StatusCreated, resp) //nolint:errcheck

	case http.MethodGet:
		roles, appErr := h.svc.ListRoles(r.Context(), tenantID)
		if appErr != nil {
			httputil.WriteError(w, appErr) //nolint:errcheck
			return
		}
		httputil.WriteJSON(w, http.StatusOK, roles) //nolint:errcheck

	default:
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
	}
}

// HandleRole serves /tenants/{tid}/roles/{rid} (GET, PUT, DELETE).
func (h *RBACHandler) HandleRole(w http.ResponseWriter, r *http.Request) {
	tenantID := extractPathSegment(r.URL.Path, "tenants", 1)
	roleID := extractPathSegment(r.URL.Path, "roles", 1)
	if tenantID == "" || roleID == "" {
		httputil.WriteError(w, httputil.MethodNotAllowed("tenant_id and role_id required")) //nolint:errcheck
		return
	}

	switch r.Method {
	case http.MethodGet:
		resp, appErr := h.svc.GetRole(r.Context(), roleID, tenantID)
		if appErr != nil {
			httputil.WriteError(w, appErr) //nolint:errcheck
			return
		}
		httputil.WriteJSON(w, http.StatusOK, resp) //nolint:errcheck

	case http.MethodPut:
		var req rbacsvc.UpdateRoleRequest
		if appErr := httputil.DecodeJSON(r, &req); appErr != nil {
			httputil.WriteError(w, appErr) //nolint:errcheck
			return
		}
		req.TenantID = tenantID
		resp, appErr := h.svc.UpdateRole(r.Context(), roleID, req)
		if appErr != nil {
			httputil.WriteError(w, appErr) //nolint:errcheck
			return
		}
		httputil.WriteJSON(w, http.StatusOK, resp) //nolint:errcheck

	case http.MethodDelete:
		if appErr := h.svc.DeleteRole(r.Context(), roleID, tenantID); appErr != nil {
			httputil.WriteError(w, appErr) //nolint:errcheck
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
	}
}

// HandleUserRoles serves /tenants/{tid}/users/{uid}/roles (POST, GET).
func (h *RBACHandler) HandleUserRoles(w http.ResponseWriter, r *http.Request) {
	tenantID := extractPathSegment(r.URL.Path, "tenants", 1)
	userID := extractPathSegment(r.URL.Path, "users", 1)
	if tenantID == "" || userID == "" {
		httputil.WriteError(w, httputil.MethodNotAllowed("tenant_id and user_id required")) //nolint:errcheck
		return
	}

	switch r.Method {
	case http.MethodPost:
		var req rbacsvc.AssignRoleRequest
		if appErr := httputil.DecodeJSON(r, &req); appErr != nil {
			httputil.WriteError(w, appErr) //nolint:errcheck
			return
		}
		if appErr := h.svc.AssignRole(r.Context(), userID, req.RoleID, tenantID); appErr != nil {
			httputil.WriteError(w, appErr) //nolint:errcheck
			return
		}
		httputil.WriteJSON(w, http.StatusCreated, map[string]string{"status": "assigned"}) //nolint:errcheck

	case http.MethodGet:
		roles, appErr := h.svc.GetUserRoles(r.Context(), userID, tenantID)
		if appErr != nil {
			httputil.WriteError(w, appErr) //nolint:errcheck
			return
		}
		httputil.WriteJSON(w, http.StatusOK, roles) //nolint:errcheck

	default:
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
	}
}

// HandleUserPermissions serves GET /tenants/{tid}/users/{uid}/permissions.
func (h *RBACHandler) HandleUserPermissions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	tenantID := extractPathSegment(r.URL.Path, "tenants", 1)
	userID := extractPathSegment(r.URL.Path, "users", 1)

	perms, appErr := h.svc.GetUserPermissions(r.Context(), userID, tenantID)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string][]string{"permissions": perms}) //nolint:errcheck
}
