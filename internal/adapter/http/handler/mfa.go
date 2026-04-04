package handler

import (
	"net/http"

	mfasvc "github.com/authplex/internal/application/mfa"
	"github.com/authplex/pkg/sdk/httputil"
)

// MFAHandler serves MFA endpoints.
type MFAHandler struct {
	svc *mfasvc.Service
}

// NewMFAHandler creates a new MFAHandler.
func NewMFAHandler(svc *mfasvc.Service) *MFAHandler {
	return &MFAHandler{svc: svc}
}

// HandleEnroll serves POST /mfa/totp/enroll.
func (h *MFAHandler) HandleEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	var req mfasvc.EnrollRequest
	if appErr := httputil.DecodeJSON(r, &req); appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}
	req.TenantID = resolveTenantID(r)

	resp, appErr := h.svc.EnrollTOTP(r.Context(), req)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	httputil.WriteJSON(w, http.StatusOK, resp) //nolint:errcheck
}

// HandleConfirm serves POST /mfa/totp/confirm.
func (h *MFAHandler) HandleConfirm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	var req mfasvc.VerifyRequest
	if appErr := httputil.DecodeJSON(r, &req); appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}
	req.TenantID = resolveTenantID(r)

	if appErr := h.svc.ConfirmTOTP(r.Context(), req); appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "confirmed"}) //nolint:errcheck
}

// HandleVerify serves POST /mfa/verify — completes an MFA challenge.
func (h *MFAHandler) HandleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	var req mfasvc.MFAVerifyRequest
	if appErr := httputil.DecodeJSON(r, &req); appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	resp, appErr := h.svc.VerifyMFA(r.Context(), req)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]string{
		"code":  resp.Code,
		"state": resp.State,
	}) //nolint:errcheck
}

// HandleWebAuthnRegisterBegin serves POST /mfa/webauthn/register/begin.
func (h *MFAHandler) HandleWebAuthnRegisterBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	var req mfasvc.WebAuthnRegisterRequest
	if appErr := httputil.DecodeJSON(r, &req); appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}
	req.TenantID = resolveTenantID(r)

	resp, appErr := h.svc.BeginWebAuthnRegistration(r.Context(), req)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(resp) //nolint:errcheck
}

// HandleWebAuthnRegisterFinish serves POST /mfa/webauthn/register/finish.
func (h *MFAHandler) HandleWebAuthnRegisterFinish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	var req mfasvc.WebAuthnRegisterFinishRequest
	if appErr := httputil.DecodeJSON(r, &req); appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}
	req.TenantID = resolveTenantID(r)

	if appErr := h.svc.FinishWebAuthnRegistration(r.Context(), req); appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "registered"}) //nolint:errcheck
}

// HandleWebAuthnLoginBegin serves POST /mfa/webauthn/login/begin.
func (h *MFAHandler) HandleWebAuthnLoginBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	var req mfasvc.WebAuthnLoginRequest
	if appErr := httputil.DecodeJSON(r, &req); appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}
	req.TenantID = resolveTenantID(r)

	resp, appErr := h.svc.BeginWebAuthnLogin(r.Context(), req)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(resp) //nolint:errcheck
}

// HandleWebAuthnLoginFinish serves POST /mfa/webauthn/login/finish.
func (h *MFAHandler) HandleWebAuthnLoginFinish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	var req mfasvc.WebAuthnLoginFinishRequest
	if appErr := httputil.DecodeJSON(r, &req); appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	if appErr := h.svc.FinishWebAuthnLogin(r.Context(), req); appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "verified"}) //nolint:errcheck
}
