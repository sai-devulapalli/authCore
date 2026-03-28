package handler

import (
	"net/http"
	"strconv"

	auditsvc "github.com/authcore/internal/application/audit"
	domainaudit "github.com/authcore/internal/domain/audit"
	"github.com/authcore/pkg/sdk/httputil"
)

// AuditHandler serves audit log query endpoints.
type AuditHandler struct {
	svc *auditsvc.Service
}

// NewAuditHandler creates a new AuditHandler.
func NewAuditHandler(svc *auditsvc.Service) *AuditHandler {
	return &AuditHandler{svc: svc}
}

// HandleAuditLogs serves GET /tenants/{tid}/audit.
func (h *AuditHandler) HandleAuditLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	tenantID := extractPathSegment(r.URL.Path, "tenants", 1)
	if tenantID == "" {
		httputil.WriteError(w, httputil.MethodNotAllowed("tenant_id is required")) //nolint:errcheck
		return
	}

	limit, _ := strconv.Atoi(httputil.QueryParam(r, "limit", "50"))
	offset, _ := strconv.Atoi(httputil.QueryParam(r, "offset", "0"))

	filter := domainaudit.QueryFilter{
		TenantID:     tenantID,
		ActorID:      httputil.QueryParam(r, "actor_id", ""),
		Action:       domainaudit.EventType(httputil.QueryParam(r, "action", "")),
		ResourceType: httputil.QueryParam(r, "resource_type", ""),
		ResourceID:   httputil.QueryParam(r, "resource_id", ""),
		Limit:        limit,
		Offset:       offset,
	}

	events, appErr := h.svc.Query(r.Context(), filter)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"events": events,
		"count":  len(events),
		"offset": offset,
		"limit":  limit,
	}) //nolint:errcheck
}
