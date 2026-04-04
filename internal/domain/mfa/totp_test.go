package mfa

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// RFC 6238 test secret: "12345678901234567890" (ASCII)
var testSecret = []byte("12345678901234567890")

func TestGenerateTOTP_KnownVector(t *testing.T) {
	// RFC 6238 Appendix B test vectors for SHA1
	// Time step 0 (Unix time 0) should produce a known value
	// T = 0, counter = 0
	code := GenerateTOTP(testSecret, time.Unix(0, 0))
	assert.Len(t, code, 6)
	assert.Equal(t, "755224", code) // HOTP counter=0 for "12345678901234567890"
}

func TestGenerateTOTP_DifferentTimes(t *testing.T) {
	t1 := time.Unix(30, 0)  // counter = 1
	t2 := time.Unix(60, 0)  // counter = 2
	t3 := time.Unix(90, 0)  // counter = 3

	code1 := GenerateTOTP(testSecret, t1)
	code2 := GenerateTOTP(testSecret, t2)
	code3 := GenerateTOTP(testSecret, t3)

	assert.Len(t, code1, 6)
	assert.Len(t, code2, 6)
	assert.Len(t, code3, 6)

	// Different time steps should produce different codes
	assert.NotEqual(t, code1, code2)
	assert.NotEqual(t, code2, code3)
}

func TestGenerateTOTP_SameTimeStep(t *testing.T) {
	// Times within the same 30-second window should produce the same code
	t1 := time.Unix(100, 0)
	t2 := time.Unix(115, 0) // same 30s window (100/30 = 3, 115/30 = 3)

	assert.Equal(t, GenerateTOTP(testSecret, t1), GenerateTOTP(testSecret, t2))
}

func TestVerifyTOTP_CurrentCode(t *testing.T) {
	now := time.Now().UTC()
	code := GenerateTOTP(testSecret, now)

	assert.True(t, VerifyTOTP(testSecret, code, now))
}

func TestVerifyTOTP_PreviousStep(t *testing.T) {
	now := time.Now().UTC()
	prev := now.Add(-30 * time.Second) // previous time step
	code := GenerateTOTP(testSecret, prev)

	// Should accept code from previous window (within tolerance)
	assert.True(t, VerifyTOTP(testSecret, code, now))
}

func TestVerifyTOTP_NextStep(t *testing.T) {
	now := time.Now().UTC()
	next := now.Add(30 * time.Second) // next time step
	code := GenerateTOTP(testSecret, next)

	// Should accept code from next window (within tolerance)
	assert.True(t, VerifyTOTP(testSecret, code, now))
}

func TestVerifyTOTP_WrongCode(t *testing.T) {
	now := time.Now().UTC()
	assert.False(t, VerifyTOTP(testSecret, "000000", now))
}

func TestVerifyTOTP_OutsideWindow(t *testing.T) {
	now := time.Now().UTC()
	// Generate code for 3 steps ago (outside ±1 window)
	farPast := now.Add(-90 * time.Second)
	code := GenerateTOTP(testSecret, farPast)

	assert.False(t, VerifyTOTP(testSecret, code, now))
}

func TestBuildOTPAuthURI(t *testing.T) {
	uri := BuildOTPAuthURI("AuthPlex", "user@example.com", "JBSWY3DPEHPK3PXP")

	assert.Contains(t, uri, "otpauth://totp/")
	assert.Contains(t, uri, "AuthPlex")
	assert.Contains(t, uri, "user@example.com")
	assert.Contains(t, uri, "secret=JBSWY3DPEHPK3PXP")
	assert.Contains(t, uri, "algorithm=SHA1")
	assert.Contains(t, uri, "digits=6")
	assert.Contains(t, uri, "period=30")
}
