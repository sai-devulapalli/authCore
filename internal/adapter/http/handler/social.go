package handler

import (
	"net/http"
	"net/url"

	"github.com/authplex/internal/application/social"
	"github.com/authplex/pkg/sdk/httputil"
)

// SocialHandler handles social login endpoints.
type SocialHandler struct {
	svc *social.Service
}

// NewSocialHandler creates a new SocialHandler.
func NewSocialHandler(svc *social.Service) *SocialHandler {
	return &SocialHandler{svc: svc}
}

// HandleCallback serves GET /callback from external providers.
func (h *SocialHandler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	req := social.CallbackRequest{
		Code:             httputil.QueryParam(r, "code", ""),
		State:            httputil.QueryParam(r, "state", ""),
		Error:            httputil.QueryParam(r, "error", ""),
		ErrorDescription: httputil.QueryParam(r, "error_description", ""),
	}

	resp, appErr := h.svc.HandleCallback(r.Context(), req)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	// Redirect back to the original client with the AuthPlex auth code
	redirectURL, err := url.Parse(resp.RedirectURI)
	if err != nil {
		httputil.WriteError(w, httputil.MethodNotAllowed("invalid redirect_uri")) //nolint:errcheck
		return
	}

	q := redirectURL.Query()
	q.Set("code", resp.Code)
	if resp.State != "" {
		q.Set("state", resp.State)
	}
	redirectURL.RawQuery = q.Encode()

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}
