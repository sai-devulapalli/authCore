//go:build e2e

package e2e

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// OTP Login Flow
// ---------------------------------------------------------------------------

func TestE2E_OTP_Login(t *testing.T) {
	env := setupFullTestServer(t)
	defer env.server.Close()

	tenantID := env.createTenant(t, "otp-login-tenant", "RS256")
	env.registerUser(t, tenantID, "otp@example.com", "pass123", "OTP User")

	t.Run("request OTP with purpose login returns 200", func(t *testing.T) {
		status, body := env.doJSON(t, http.MethodPost, "/otp/request", map[string]any{
			"email":   "otp@example.com",
			"purpose": "login",
		}, map[string]string{
			"X-Tenant-ID": tenantID,
		})
		assert.Equal(t, http.StatusOK, status)
		data := body["data"].(map[string]any)
		assert.Equal(t, "OTP sent", data["message"])
		assert.NotZero(t, data["expires_in"])
	})

	t.Run("verify OTP with correct code creates session", func(t *testing.T) {
		// Request OTP first
		env.doJSON(t, http.MethodPost, "/otp/request", map[string]any{
			"email":   "otp@example.com",
			"purpose": "login",
		}, map[string]string{
			"X-Tenant-ID": tenantID,
		})

		// Wait briefly for async processing
		time.Sleep(50 * time.Millisecond)

		code := env.emailSender.getCode("otp@example.com")
		require.NotEmpty(t, code, "captured OTP code should not be empty")

		status, body := env.doJSON(t, http.MethodPost, "/otp/verify", map[string]any{
			"email": "otp@example.com",
			"code":  code,
		}, map[string]string{
			"X-Tenant-ID": tenantID,
		})
		assert.Equal(t, http.StatusOK, status)
		data := body["data"].(map[string]any)
		assert.NotEmpty(t, data["session_token"], "should return session_token")
	})

	t.Run("verify OTP with wrong code returns 400", func(t *testing.T) {
		// Request fresh OTP
		env.doJSON(t, http.MethodPost, "/otp/request", map[string]any{
			"email":   "otp@example.com",
			"purpose": "login",
		}, map[string]string{
			"X-Tenant-ID": tenantID,
		})

		status, _ := env.doJSON(t, http.MethodPost, "/otp/verify", map[string]any{
			"email": "otp@example.com",
			"code":  "000000",
		}, map[string]string{
			"X-Tenant-ID": tenantID,
		})
		assert.Equal(t, http.StatusBadRequest, status)
	})

	t.Run("request OTP for nonexistent user returns 404", func(t *testing.T) {
		status, _ := env.doJSON(t, http.MethodPost, "/otp/request", map[string]any{
			"email":   "nobody@example.com",
			"purpose": "login",
		}, map[string]string{
			"X-Tenant-ID": tenantID,
		})
		assert.Equal(t, http.StatusNotFound, status)
	})

	t.Run("request OTP missing email returns 400", func(t *testing.T) {
		status, _ := env.doJSON(t, http.MethodPost, "/otp/request", map[string]any{
			"purpose": "login",
		}, map[string]string{
			"X-Tenant-ID": tenantID,
		})
		assert.Equal(t, http.StatusBadRequest, status)
	})

	t.Run("request OTP invalid purpose returns 400", func(t *testing.T) {
		status, _ := env.doJSON(t, http.MethodPost, "/otp/request", map[string]any{
			"email":   "otp@example.com",
			"purpose": "invalid",
		}, map[string]string{
			"X-Tenant-ID": tenantID,
		})
		assert.Equal(t, http.StatusBadRequest, status)
	})
}

// ---------------------------------------------------------------------------
// Password Reset Flow
// ---------------------------------------------------------------------------

func TestE2E_PasswordReset(t *testing.T) {
	env := setupFullTestServer(t)
	defer env.server.Close()

	tenantID := env.createTenant(t, "reset-tenant", "RS256")
	env.registerUser(t, tenantID, "reset@example.com", "oldpassword123", "Reset User")

	t.Run("full password reset flow", func(t *testing.T) {
		// Step 1: Request reset OTP
		status, body := env.doJSON(t, http.MethodPost, "/otp/request", map[string]any{
			"email":   "reset@example.com",
			"purpose": "reset",
		}, map[string]string{
			"X-Tenant-ID": tenantID,
		})
		require.Equal(t, http.StatusOK, status)
		data := body["data"].(map[string]any)
		assert.Equal(t, "OTP sent", data["message"])

		time.Sleep(50 * time.Millisecond)
		code := env.emailSender.getCode("reset@example.com")
		require.NotEmpty(t, code, "reset OTP code should be captured")

		// Step 2: Reset password with valid OTP
		status, _ = env.doJSON(t, http.MethodPost, "/password/reset", map[string]any{
			"email":        "reset@example.com",
			"code":         code,
			"new_password": "newpassword456",
		}, map[string]string{
			"X-Tenant-ID": tenantID,
		})
		assert.Equal(t, http.StatusOK, status)

		// Step 3: Login with old password should fail
		status, _ = env.doJSON(t, http.MethodPost, "/login", map[string]any{
			"email":    "reset@example.com",
			"password": "oldpassword123",
		}, map[string]string{
			"X-Tenant-ID": tenantID,
		})
		assert.Equal(t, http.StatusUnauthorized, status, "old password should no longer work")

		// Step 4: Login with new password should succeed
		status, loginBody := env.doJSON(t, http.MethodPost, "/login", map[string]any{
			"email":    "reset@example.com",
			"password": "newpassword456",
		}, map[string]string{
			"X-Tenant-ID": tenantID,
		})
		assert.Equal(t, http.StatusOK, status, "new password should work")
		loginData := loginBody["data"].(map[string]any)
		assert.NotEmpty(t, loginData["session_token"])
	})

	t.Run("password reset with wrong OTP returns 400", func(t *testing.T) {
		// Request a fresh OTP
		env.doJSON(t, http.MethodPost, "/otp/request", map[string]any{
			"email":   "reset@example.com",
			"purpose": "reset",
		}, map[string]string{
			"X-Tenant-ID": tenantID,
		})

		status, _ := env.doJSON(t, http.MethodPost, "/password/reset", map[string]any{
			"email":        "reset@example.com",
			"code":         "000000",
			"new_password": "whatever123",
		}, map[string]string{
			"X-Tenant-ID": tenantID,
		})
		assert.Equal(t, http.StatusBadRequest, status)
	})

	t.Run("password reset missing new_password returns 400", func(t *testing.T) {
		status, _ := env.doJSON(t, http.MethodPost, "/password/reset", map[string]any{
			"email": "reset@example.com",
			"code":  "123456",
		}, map[string]string{
			"X-Tenant-ID": tenantID,
		})
		assert.Equal(t, http.StatusBadRequest, status)
	})
}

// ---------------------------------------------------------------------------
// Email Verification via OTP
// ---------------------------------------------------------------------------

func TestE2E_EmailVerification(t *testing.T) {
	env := setupFullTestServer(t)
	defer env.server.Close()

	tenantID := env.createTenant(t, "verify-tenant", "RS256")
	env.registerUser(t, tenantID, "verify@example.com", "pass123", "Verify User")

	t.Run("request verify OTP and verify email", func(t *testing.T) {
		// Request verification OTP
		status, body := env.doJSON(t, http.MethodPost, "/otp/request", map[string]any{
			"email":   "verify@example.com",
			"purpose": "verify",
		}, map[string]string{
			"X-Tenant-ID": tenantID,
		})
		require.Equal(t, http.StatusOK, status)
		data := body["data"].(map[string]any)
		assert.Equal(t, "OTP sent", data["message"])

		time.Sleep(50 * time.Millisecond)
		code := env.emailSender.getCode("verify@example.com")
		require.NotEmpty(t, code, "verification OTP code should be captured")

		// Verify the OTP
		status, verifyBody := env.doJSON(t, http.MethodPost, "/otp/verify", map[string]any{
			"email": "verify@example.com",
			"code":  code,
		}, map[string]string{
			"X-Tenant-ID": tenantID,
		})
		assert.Equal(t, http.StatusOK, status)
		verifyData := verifyBody["data"].(map[string]any)
		assert.NotEmpty(t, verifyData["session_token"])

		// Check userinfo for email_verified
		session := verifyData["session_token"].(string)
		status, userInfo := env.get(t, "/userinfo", map[string]string{
			"X-Tenant-ID":  tenantID,
			"Authorization": "Bearer " + session,
		})
		assert.Equal(t, http.StatusOK, status)
		assert.Equal(t, "verify@example.com", userInfo["email"])
		// email_verified should be true after verification
		if verified, ok := userInfo["email_verified"]; ok {
			assert.Equal(t, true, verified, "email should be verified after OTP verify")
		}
	})
}
