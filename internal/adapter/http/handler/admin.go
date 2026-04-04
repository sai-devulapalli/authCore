package handler

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"time"

	adminsvc "github.com/authplex/internal/application/admin"
	"github.com/authplex/internal/application/jwks"
	"github.com/authplex/internal/domain/admin"
	"github.com/authplex/internal/domain/tenant"
	"github.com/authplex/internal/domain/token"
	apperrors "github.com/authplex/pkg/sdk/errors"
	"github.com/authplex/pkg/sdk/httputil"
)

// AdminHandler serves the admin user management API.
type AdminHandler struct {
	svc      *adminsvc.Service
	jwksSvc  *jwks.Service
	signer   token.Signer
	issuer   string
	adminKey string
}

// NewAdminHandler creates a new AdminHandler.
func NewAdminHandler(svc *adminsvc.Service, jwksSvc *jwks.Service, signer token.Signer, issuer, adminKey string) *AdminHandler {
	return &AdminHandler{
		svc:      svc,
		jwksSvc:  jwksSvc,
		signer:   signer,
		issuer:   issuer,
		adminKey: adminKey,
	}
}

// HandleBootstrap serves POST /admin/bootstrap.
func (h *AdminHandler) HandleBootstrap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	var req adminsvc.BootstrapRequest
	if appErr := httputil.DecodeJSON(r, &req); appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	resp, appErr := h.svc.Bootstrap(r.Context(), req, h.adminKey)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	httputil.WriteJSON(w, http.StatusCreated, resp) //nolint:errcheck
}

// HandleLogin serves POST /admin/login.
func (h *AdminHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	var req adminsvc.LoginRequest
	if appErr := httputil.DecodeJSON(r, &req); appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	adminUser, appErr := h.svc.Login(r.Context(), req)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	// Sign admin JWT
	jwt, signErr := h.signAdminJWT(r, adminUser)
	if signErr != nil {
		httputil.WriteError(w, signErr) //nolint:errcheck
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{ //nolint:errcheck
		"token":      jwt,
		"token_type": "Bearer",
		"expires_in": 3600,
		"admin": map[string]any{
			"id":    adminUser.ID,
			"email": adminUser.Email,
			"role":  adminUser.Role,
		},
	})
}

// HandleUsers serves GET and POST /admin/users.
func (h *AdminHandler) HandleUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		admins, appErr := h.svc.ListAdmins(r.Context())
		if appErr != nil {
			httputil.WriteError(w, appErr) //nolint:errcheck
			return
		}
		httputil.WriteJSON(w, http.StatusOK, map[string]any{"admins": admins}) //nolint:errcheck

	case http.MethodPost:
		var req adminsvc.CreateAdminRequest
		if appErr := httputil.DecodeJSON(r, &req); appErr != nil {
			httputil.WriteError(w, appErr) //nolint:errcheck
			return
		}

		resp, appErr := h.svc.CreateAdmin(r.Context(), req)
		if appErr != nil {
			httputil.WriteError(w, appErr) //nolint:errcheck
			return
		}
		httputil.WriteJSON(w, http.StatusCreated, resp) //nolint:errcheck

	default:
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
	}
}

// signAdminJWT creates a signed JWT for an admin user.
func (h *AdminHandler) signAdminJWT(r *http.Request, adminUser *admin.AdminUser) (string, *apperrors.AppError) {
	// Admin has its own dedicated signing key, independent of any tenant
	const adminKeyNamespace = "__admin__"

	kp, appErr := h.jwksSvc.GetActiveKeyPair(r.Context(), adminKeyNamespace)
	if appErr != nil {
		// Auto-provision a dedicated admin signing key
		kid, err := generateAdminJTI()
		if err != nil {
			return "", apperrors.Wrap(apperrors.ErrInternal, "failed to generate key ID", err)
		}
		kp, appErr = h.jwksSvc.EnsureKeyPair(r.Context(), adminKeyNamespace, kid, tenant.RS256)
		if appErr != nil {
			return "", apperrors.Wrap(apperrors.ErrInternal, "no signing key available", appErr)
		}
	}

	now := time.Now().UTC()
	jti, err := generateAdminJTI()
	if err != nil {
		return "", apperrors.Wrap(apperrors.ErrInternal, "failed to generate token ID", err)
	}

	claims := token.Claims{
		Issuer:    h.issuer,
		Subject:   adminUser.ID,
		Audience:  []string{"authplex-admin"},
		ExpiresAt: now.Add(1 * time.Hour).Unix(),
		IssuedAt:  now.Unix(),
		JWTID:     jti,
		Roles:     []string{string(adminUser.Role)},
		Email:     adminUser.Email,
	}

	signed, signErr := h.signer.Sign(claims, kp.ID, kp.PrivateKey, kp.Algorithm)
	if signErr != nil {
		return "", apperrors.Wrap(apperrors.ErrInternal, "failed to sign admin token", signErr)
	}

	return signed, nil
}

func generateAdminJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
