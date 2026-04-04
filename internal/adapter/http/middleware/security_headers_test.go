package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSecurityHeaders(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	SecurityHeaders(next).ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	h := w.Header()
	assert.Equal(t, "nosniff", h.Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", h.Get("X-Frame-Options"))
	assert.Equal(t, "1; mode=block", h.Get("X-XSS-Protection"))
	assert.NotEmpty(t, h.Get("Strict-Transport-Security"), "Strict-Transport-Security should be set")
	assert.Equal(t, "no-store", h.Get("Cache-Control"))
	assert.NotEmpty(t, h.Get("Content-Security-Policy"), "Content-Security-Policy should be set")
	assert.NotEmpty(t, h.Get("Referrer-Policy"), "Referrer-Policy should be set")
}
