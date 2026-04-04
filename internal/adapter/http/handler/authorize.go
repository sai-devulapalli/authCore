package handler

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/authplex/internal/application/auth"
	clientsvc "github.com/authplex/internal/application/client"
	mfasvc "github.com/authplex/internal/application/mfa"
	"github.com/authplex/internal/application/social"
	tenantsvc "github.com/authplex/internal/application/tenant"
	usersvc "github.com/authplex/internal/application/user"
	"github.com/authplex/internal/domain/shared"
	"github.com/authplex/pkg/sdk/httputil"
)

// AuthorizeHandler serves the OAuth 2.0 authorization endpoint.
type AuthorizeHandler struct {
	svc       *auth.Service
	socialSvc *social.Service
	userSvc   *usersvc.Service
	clientSvc *clientsvc.Service
	mfaSvc    *mfasvc.Service
	tenantSvc *tenantsvc.Service
}

// NewAuthorizeHandler creates a new AuthorizeHandler.
func NewAuthorizeHandler(svc *auth.Service) *AuthorizeHandler {
	return &AuthorizeHandler{svc: svc}
}

// WithSocialService sets the social login service for provider-based auth.
func (h *AuthorizeHandler) WithSocialService(svc *social.Service) *AuthorizeHandler {
	h.socialSvc = svc
	return h
}

// WithUserService sets the user service for session-based auth.
func (h *AuthorizeHandler) WithUserService(svc *usersvc.Service) *AuthorizeHandler {
	h.userSvc = svc
	return h
}

// WithClientService sets the client service for client validation.
func (h *AuthorizeHandler) WithClientService(svc *clientsvc.Service) *AuthorizeHandler {
	h.clientSvc = svc
	return h
}

// WithMFA sets the MFA and tenant services for MFA enforcement.
func (h *AuthorizeHandler) WithMFA(mfa *mfasvc.Service, tenant *tenantsvc.Service) *AuthorizeHandler {
	h.mfaSvc = mfa
	h.tenantSvc = tenant
	return h
}

// HandleAuthorize serves GET /authorize.
// Subject resolution order: session token → X-Subject header → 401 login_required.
func (h *AuthorizeHandler) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	// Social login: if provider query param is present, delegate to social service
	provider := httputil.QueryParam(r, "provider", "")
	if provider != "" && h.socialSvc != nil {
		socialReq := social.SocialAuthorizeRequest{
			Provider:            provider,
			TenantID:            resolveTenantID(r),
			ClientID:            httputil.QueryParam(r, "client_id", ""),
			RedirectURI:         httputil.QueryParam(r, "redirect_uri", ""),
			Scope:               httputil.QueryParam(r, "scope", "openid"),
			State:               httputil.QueryParam(r, "state", ""),
			CodeChallenge:       httputil.QueryParam(r, "code_challenge", ""),
			CodeChallengeMethod: httputil.QueryParam(r, "code_challenge_method", ""),
			Nonce:               httputil.QueryParam(r, "nonce", ""),
			Subject:             resolveSubject(r, h.userSvc),
		}
		redirectTo, appErr := h.socialSvc.AuthorizeRedirect(r.Context(), socialReq)
		if appErr != nil {
			httputil.WriteError(w, appErr) //nolint:errcheck
			return
		}
		http.Redirect(w, r, redirectTo, http.StatusFound)
		return
	}

	// Resolve subject from session or X-Subject header
	subject := resolveSubject(r, h.userSvc)
	if subject == "" {
		// OIDC-compliant: return login_required error
		httputil.WriteRaw(w, http.StatusUnauthorized, map[string]string{"error": "login_required"}) //nolint:errcheck
		return
	}

	clientID := httputil.QueryParam(r, "client_id", "")
	redirectURI := httputil.QueryParam(r, "redirect_uri", "")
	tenantID := resolveTenantID(r)

	// Validate client if client service is configured
	if h.clientSvc != nil && clientID != "" {
		c, appErr := h.clientSvc.ValidateClient(r.Context(), clientID, tenantID)
		if appErr != nil {
			httputil.WriteError(w, appErr) //nolint:errcheck
			return
		}
		if redirectURI != "" && !c.HasRedirectURI(redirectURI) {
			httputil.WriteRaw(w, http.StatusBadRequest, map[string]string{"error": "invalid_redirect_uri"}) //nolint:errcheck
			return
		}
		// Validate scopes
		scope := httputil.QueryParam(r, "scope", "openid")
		if invalid := c.ValidateScopes(scope); len(invalid) > 0 {
			httputil.WriteRaw(w, http.StatusBadRequest, map[string]string{
				"error":             "invalid_scope",
				"error_description": "scope not allowed: " + strings.Join(invalid, ", "),
			}) //nolint:errcheck
			return
		}
	}

	// MFA enforcement: if tenant requires MFA and user has TOTP enrolled, issue challenge
	if h.mfaSvc != nil && h.tenantSvc != nil {
		t, tErr := h.tenantSvc.Get(r.Context(), tenantID)
		if tErr == nil && t.MFA.IsMFARequired() && h.mfaSvc.HasEnrolledMFA(r.Context(), tenantID, subject) {
			challengeResp, chErr := h.mfaSvc.CreateChallenge(r.Context(), mfasvc.CreateChallengeRequest{
				Subject:             subject,
				TenantID:            tenantID,
				Methods:             t.MFA.Methods,
				OriginalClientID:    clientID,
				OriginalRedirectURI: redirectURI,
				OriginalScope:       httputil.QueryParam(r, "scope", "openid"),
				OriginalState:       httputil.QueryParam(r, "state", ""),
				CodeChallenge:       httputil.QueryParam(r, "code_challenge", ""),
				CodeChallengeMethod: httputil.QueryParam(r, "code_challenge_method", ""),
				Nonce:               httputil.QueryParam(r, "nonce", ""),
			})
			if chErr == nil {
				httputil.WriteRaw(w, http.StatusOK, challengeResp) //nolint:errcheck
				return
			}
		}
	}

	req := auth.AuthorizeRequest{
		ResponseType:        httputil.QueryParam(r, "response_type", ""),
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		Scope:               httputil.QueryParam(r, "scope", "openid"),
		State:               httputil.QueryParam(r, "state", ""),
		CodeChallenge:       httputil.QueryParam(r, "code_challenge", ""),
		CodeChallengeMethod: httputil.QueryParam(r, "code_challenge_method", ""),
		Subject:             subject,
		TenantID:            tenantID,
		Nonce:               httputil.QueryParam(r, "nonce", ""),
	}

	resp, appErr := h.svc.Authorize(r.Context(), req)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

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

// resolveSubject determines the user subject from session or header.
// Priority: session token → X-Subject header.
func resolveSubject(r *http.Request, userSvc *usersvc.Service) string {
	// Try session-based auth
	if userSvc != nil {
		sessionToken := extractSessionToken(r)
		if sessionToken != "" {
			session, appErr := userSvc.ResolveSession(r.Context(), sessionToken)
			if appErr == nil {
				return session.UserID
			}
		}
	}

	// Fall back to X-Subject header (headless integrations)
	return r.Header.Get("X-Subject")
}

// resolveTenantID gets the tenant ID from context (middleware) or header fallback.
func resolveTenantID(r *http.Request) string {
	if tenantID, ok := shared.TenantFromContext(r.Context()); ok {
		return tenantID
	}
	return r.Header.Get("X-Tenant-ID")
}
