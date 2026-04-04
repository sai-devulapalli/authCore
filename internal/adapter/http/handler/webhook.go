package handler

import (
	"net/http"

	webhooksvc "github.com/authplex/internal/application/webhook"
	"github.com/authplex/internal/domain/webhook"
	sdkerrors "github.com/authplex/pkg/sdk/errors"
	"github.com/authplex/pkg/sdk/httputil"
)

// WebhookHandler serves the webhook management API.
type WebhookHandler struct {
	svc *webhooksvc.Service
}

// NewWebhookHandler creates a new WebhookHandler.
func NewWebhookHandler(svc *webhooksvc.Service) *WebhookHandler {
	return &WebhookHandler{svc: svc}
}

// HandleWebhooks serves /tenants/{tid}/webhooks (POST, GET).
func (h *WebhookHandler) HandleWebhooks(w http.ResponseWriter, r *http.Request) {
	tenantID := extractPathSegment(r.URL.Path, "tenants", 1)
	if tenantID == "" {
		httputil.WriteError(w, sdkerrors.New(sdkerrors.ErrBadRequest, "tenant_id is required")) //nolint:errcheck
		return
	}

	switch r.Method {
	case http.MethodPost:
		h.createWebhook(w, r, tenantID)
	case http.MethodGet:
		h.listWebhooks(w, r, tenantID)
	default:
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
	}
}

// HandleWebhook serves /tenants/{tid}/webhooks/{wid} (DELETE).
func (h *WebhookHandler) HandleWebhook(w http.ResponseWriter, r *http.Request) {
	tenantID := extractPathSegment(r.URL.Path, "tenants", 1)
	webhookID := extractPathSegment(r.URL.Path, "webhooks", 1)
	if tenantID == "" || webhookID == "" {
		httputil.WriteError(w, sdkerrors.New(sdkerrors.ErrBadRequest, "tenant_id and webhook_id are required")) //nolint:errcheck
		return
	}

	switch r.Method {
	case http.MethodDelete:
		h.deleteWebhook(w, r, tenantID, webhookID)
	default:
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
	}
}

func (h *WebhookHandler) createWebhook(w http.ResponseWriter, r *http.Request, tenantID string) {
	var req struct {
		URL    string   `json:"url"`
		Events []string `json:"events"`
	}
	if appErr := httputil.DecodeJSON(r, &req); appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	if req.URL == "" {
		httputil.WriteError(w, sdkerrors.New(sdkerrors.ErrBadRequest, "url is required")) //nolint:errcheck
		return
	}

	wh, err := h.svc.Create(r.Context(), tenantID, req.URL, req.Events)
	if err != nil {
		httputil.WriteError(w, sdkerrors.New(sdkerrors.ErrInternal, err.Error())) //nolint:errcheck
		return
	}

	httputil.WriteJSON(w, http.StatusCreated, wh) //nolint:errcheck
}

func (h *WebhookHandler) listWebhooks(w http.ResponseWriter, r *http.Request, tenantID string) {
	hooks, err := h.svc.List(r.Context(), tenantID)
	if err != nil {
		httputil.WriteError(w, sdkerrors.New(sdkerrors.ErrInternal, err.Error())) //nolint:errcheck
		return
	}

	if hooks == nil {
		hooks = []webhook.Webhook{}
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"webhooks": hooks,
		"count":    len(hooks),
	}) //nolint:errcheck
}

func (h *WebhookHandler) deleteWebhook(w http.ResponseWriter, r *http.Request, tenantID, webhookID string) {
	if err := h.svc.Delete(r.Context(), webhookID, tenantID); err != nil {
		httputil.WriteError(w, sdkerrors.New(sdkerrors.ErrInternal, err.Error())) //nolint:errcheck
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
