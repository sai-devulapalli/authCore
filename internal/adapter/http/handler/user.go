package handler

import (
	"net/http"
	"strconv"
	"strings"

	usersvc "github.com/authplex/internal/application/user"
	"github.com/authplex/internal/domain/shared"
	sdkerrors "github.com/authplex/pkg/sdk/errors"
	"github.com/authplex/pkg/sdk/httputil"
)

// UserHandler serves user authentication endpoints.
type UserHandler struct {
	svc *usersvc.Service
}

// NewUserHandler creates a new UserHandler.
func NewUserHandler(svc *usersvc.Service) *UserHandler {
	return &UserHandler{svc: svc}
}

// HandleRegister serves POST /register.
func (h *UserHandler) HandleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	var req usersvc.RegisterRequest
	if appErr := httputil.DecodeJSON(r, &req); appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}
	req.TenantID = resolveTenantID(r)

	resp, appErr := h.svc.Register(r.Context(), req)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	httputil.WriteJSON(w, http.StatusCreated, resp) //nolint:errcheck
}

// HandleLogin serves POST /login.
func (h *UserHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	var req usersvc.LoginRequest
	if appErr := httputil.DecodeJSON(r, &req); appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}
	req.TenantID = resolveTenantID(r)

	resp, appErr := h.svc.Login(r.Context(), req)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	httputil.WriteJSON(w, http.StatusOK, resp) //nolint:errcheck
}

// HandleLogout serves POST /logout.
func (h *UserHandler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	sessionToken := extractSessionToken(r)
	appErr := h.svc.Logout(r.Context(), usersvc.LogoutRequest{SessionToken: sessionToken})
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "logged_out"}) //nolint:errcheck
}

// HandleUserInfo serves GET /userinfo (OIDC UserInfo endpoint).
func (h *UserHandler) HandleUserInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	// Resolve user from session
	sessionToken := extractSessionToken(r)
	if sessionToken == "" {
		httputil.WriteRaw(w, http.StatusUnauthorized, map[string]string{"error": "login_required"}) //nolint:errcheck
		return
	}

	session, appErr := h.svc.ResolveSession(r.Context(), sessionToken)
	if appErr != nil {
		httputil.WriteRaw(w, http.StatusUnauthorized, map[string]string{"error": "login_required"}) //nolint:errcheck
		return
	}

	tenantID, _ := shared.TenantFromContext(r.Context())
	if tenantID == "" {
		tenantID = session.TenantID
	}

	info, appErr := h.svc.GetUserInfo(r.Context(), session.UserID, tenantID)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	httputil.WriteRaw(w, http.StatusOK, info) //nolint:errcheck
}

// HandleRequestOTP serves POST /otp/request.
func (h *UserHandler) HandleRequestOTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	var req usersvc.RequestOTPRequest
	if appErr := httputil.DecodeJSON(r, &req); appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}
	req.TenantID = resolveTenantID(r)

	resp, appErr := h.svc.RequestOTP(r.Context(), req)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	httputil.WriteJSON(w, http.StatusOK, resp) //nolint:errcheck
}

// HandleVerifyOTP serves POST /otp/verify.
func (h *UserHandler) HandleVerifyOTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	var req usersvc.VerifyOTPRequest
	if appErr := httputil.DecodeJSON(r, &req); appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}
	req.TenantID = resolveTenantID(r)

	resp, appErr := h.svc.VerifyOTP(r.Context(), req)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	httputil.WriteJSON(w, http.StatusOK, resp) //nolint:errcheck
}

// HandleResetPassword serves POST /password/reset.
func (h *UserHandler) HandleResetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	var req usersvc.ResetPasswordRequest
	if appErr := httputil.DecodeJSON(r, &req); appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}
	req.TenantID = resolveTenantID(r)

	if appErr := h.svc.ResetPassword(r.Context(), req); appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "password_reset"}) //nolint:errcheck
}

// HandleListUsers serves GET /tenants/{tid}/users.
func (h *UserHandler) HandleListUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	tenantID := extractPathSegment(r.URL.Path, "tenants", 1)
	if tenantID == "" {
		httputil.WriteError(w, sdkerrors.New(sdkerrors.ErrBadRequest, "tenant_id is required")) //nolint:errcheck
		return
	}

	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 20
	}

	users, total, appErr := h.svc.ListUsers(r.Context(), tenantID, offset, limit)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"users":  users,
		"count":  total,
		"offset": offset,
		"limit":  limit,
	}) //nolint:errcheck
}

// extractSessionToken gets the session token from Authorization header or X-Session-Token.
func extractSessionToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return r.Header.Get("X-Session-Token")
}
