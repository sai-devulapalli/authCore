package handler

import (
	"net/http"

	"github.com/authplex/internal/application/auth"
	clientsvc "github.com/authplex/internal/application/client"
	"github.com/authplex/internal/domain/client"
	"github.com/authplex/pkg/sdk/httputil"
)

// TokenHandler serves the OAuth 2.0 token endpoint.
type TokenHandler struct {
	svc       *auth.Service
	clientSvc *clientsvc.Service
}

// NewTokenHandler creates a new TokenHandler.
func NewTokenHandler(svc *auth.Service) *TokenHandler {
	return &TokenHandler{svc: svc}
}

// WithClientService sets the client service for client validation.
func (h *TokenHandler) WithClientService(svc *clientsvc.Service) *TokenHandler {
	h.clientSvc = svc
	return h
}

// HandleToken serves POST /token.
func (h *TokenHandler) HandleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	if err := r.ParseForm(); err != nil {
		httputil.WriteError(w, httputil.MethodNotAllowed("invalid form body")) //nolint:errcheck
		return
	}

	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	grantType := r.FormValue("grant_type")
	tenantID := resolveTenantID(r)

	// For refresh_token grants the tenant can be inferred from the stored token,
	// so the X-Tenant-ID header is not required. Pre-fetch the tenant ID so
	// confidential client authentication succeeds even without the header.
	if grantType == "refresh_token" && tenantID == "" && h.svc != nil {
		if rt := r.FormValue("refresh_token"); rt != "" {
			if resolvedID, err := h.svc.GetRefreshTokenTenantID(r.Context(), rt); err == nil && resolvedID != "" {
				tenantID = resolvedID
			}
		}
	}

	// Validate client if client service is configured
	scope := r.FormValue("scope")

	if h.clientSvc != nil && clientID != "" {
		if clientSecret != "" {
			// Confidential client: authenticate with secret
			c, appErr := h.clientSvc.Authenticate(r.Context(), clientID, clientSecret, tenantID)
			if appErr != nil {
				httputil.WriteError(w, appErr) //nolint:errcheck
				return
			}
			if !c.HasGrantType(client.GrantType(grantType)) {
				httputil.WriteRaw(w, http.StatusBadRequest, map[string]string{"error": "unauthorized_client"}) //nolint:errcheck
				return
			}
			if invalid := c.ValidateScopes(scope); len(invalid) > 0 {
				httputil.WriteRaw(w, http.StatusBadRequest, map[string]string{"error": "invalid_scope"}) //nolint:errcheck
				return
			}
		} else {
			// Public client: validate existence + grant type + scopes
			c, appErr := h.clientSvc.ValidateClient(r.Context(), clientID, tenantID)
			if appErr != nil {
				httputil.WriteError(w, appErr) //nolint:errcheck
				return
			}
			if !c.HasGrantType(client.GrantType(grantType)) {
				httputil.WriteRaw(w, http.StatusBadRequest, map[string]string{"error": "unauthorized_client"}) //nolint:errcheck
				return
			}
			if invalid := c.ValidateScopes(scope); len(invalid) > 0 {
				httputil.WriteRaw(w, http.StatusBadRequest, map[string]string{"error": "invalid_scope"}) //nolint:errcheck
				return
			}
		}
	}

	req := auth.TokenRequest{
		GrantType:    grantType,
		Code:         r.FormValue("code"),
		RedirectURI:  r.FormValue("redirect_uri"),
		ClientID:     clientID,
		ClientSecret: clientSecret,
		CodeVerifier: r.FormValue("code_verifier"),
		TenantID:     tenantID,
		RefreshToken: r.FormValue("refresh_token"),
		DeviceCode:   r.FormValue("device_code"),
		Username:     r.FormValue("username"),
		Password:     r.FormValue("password"),
		Scope:        scope,
	}

	resp, appErr := h.svc.Exchange(r.Context(), req)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	httputil.WriteRaw(w, http.StatusOK, resp) //nolint:errcheck
}
