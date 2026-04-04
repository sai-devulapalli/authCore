package handler

import (
	"net/http"
	"net/url"

	samlsvc "github.com/authplex/internal/application/saml"
	"github.com/authplex/pkg/sdk/httputil"
)

// SAMLHandler handles SAML 2.0 SP endpoints.
type SAMLHandler struct {
	svc *samlsvc.Service
}

// NewSAMLHandler creates a new SAMLHandler.
func NewSAMLHandler(svc *samlsvc.Service) *SAMLHandler {
	return &SAMLHandler{svc: svc}
}

// HandleMetadata serves GET /saml/metadata — returns SP metadata XML.
func (h *SAMLHandler) HandleMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	providerID := httputil.QueryParam(r, "provider", "")
	if providerID == "" {
		httputil.WriteError(w, httputil.MethodNotAllowed("provider query parameter is required")) //nolint:errcheck
		return
	}

	// Tenant ID can come from header since metadata may be fetched without tenant middleware
	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		tenantID = httputil.QueryParam(r, "tenant", "default")
	}

	xmlBytes, err := h.svc.GenerateMetadata(r.Context(), tenantID, providerID)
	if err != nil {
		httputil.WriteError(w, httputil.MethodNotAllowed(err.Error())) //nolint:errcheck
		return
	}

	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write(xmlBytes) //nolint:errcheck
}

// HandleSSO serves GET /saml/sso — initiates SAML SSO by redirecting to IdP.
func (h *SAMLHandler) HandleSSO(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	tenantID := r.Header.Get("X-Tenant-ID")

	req := samlsvc.SSORequest{
		ProviderID:          httputil.QueryParam(r, "provider", ""),
		TenantID:            tenantID,
		ClientID:            httputil.QueryParam(r, "client_id", ""),
		RedirectURI:         httputil.QueryParam(r, "redirect_uri", ""),
		Scope:               httputil.QueryParam(r, "scope", ""),
		State:               httputil.QueryParam(r, "state", ""),
		CodeChallenge:       httputil.QueryParam(r, "code_challenge", ""),
		CodeChallengeMethod: httputil.QueryParam(r, "code_challenge_method", ""),
	}

	if req.ProviderID == "" {
		httputil.WriteError(w, httputil.MethodNotAllowed("provider query parameter is required")) //nolint:errcheck
		return
	}

	redirectURL, appErr := h.svc.InitiateSSO(r.Context(), req)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// HandleACS serves POST /saml/acs — receives SAML assertion from IdP.
func (h *SAMLHandler) HandleACS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	if err := r.ParseForm(); err != nil {
		httputil.WriteError(w, httputil.MethodNotAllowed("failed to parse form data")) //nolint:errcheck
		return
	}

	relayState := r.FormValue("RelayState")

	if r.FormValue("SAMLResponse") == "" {
		httputil.WriteError(w, httputil.MethodNotAllowed("SAMLResponse is required")) //nolint:errcheck
		return
	}
	if relayState == "" {
		httputil.WriteError(w, httputil.MethodNotAllowed("RelayState is required")) //nolint:errcheck
		return
	}

	resp, appErr := h.svc.HandleACS(r.Context(), r, relayState)
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
