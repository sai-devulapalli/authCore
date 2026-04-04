package handler

import (
	"net/http"

	"github.com/authplex/internal/application/auth"
	"github.com/authplex/pkg/sdk/httputil"
)

// IntrospectHandler serves the token introspection endpoint (RFC 7662).
type IntrospectHandler struct {
	svc *auth.Service
}

// NewIntrospectHandler creates a new IntrospectHandler.
func NewIntrospectHandler(svc *auth.Service) *IntrospectHandler {
	return &IntrospectHandler{svc: svc}
}

// HandleIntrospect serves POST /introspect.
func (h *IntrospectHandler) HandleIntrospect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	if err := r.ParseForm(); err != nil {
		httputil.WriteError(w, httputil.MethodNotAllowed("invalid form body")) //nolint:errcheck
		return
	}

	req := auth.IntrospectRequest{
		Token:         r.FormValue("token"),
		TokenTypeHint: r.FormValue("token_type_hint"),
		ClientID:      r.FormValue("client_id"),
		ClientSecret:  r.FormValue("client_secret"),
		TenantID:      resolveTenantID(r),
	}

	resp, appErr := h.svc.Introspect(r.Context(), req)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	httputil.WriteRaw(w, http.StatusOK, resp) //nolint:errcheck
}
