package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRateLimiter_AllowsUnderLimit(t *testing.T) {
	rl := NewRateLimiter(5, 1*time.Minute)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		w := httptest.NewRecorder()
		rl.Middleware(next).ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	}
}

func TestRateLimiter_BlocksOverLimit(t *testing.T) {
	rl := NewRateLimiter(3, 1*time.Minute)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Use up the limit
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		w := httptest.NewRecorder()
		rl.Middleware(next).ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	}

	// Next request should be blocked
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	w := httptest.NewRecorder()
	rl.Middleware(next).ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.NotEmpty(t, w.Header().Get("Retry-After"))
}

func TestRateLimiter_DifferentIPs(t *testing.T) {
	rl := NewRateLimiter(2, 1*time.Minute)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// IP 1: 2 requests (at limit)
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		req.RemoteAddr = "1.1.1.1:1"
		w := httptest.NewRecorder()
		rl.Middleware(next).ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	}

	// IP 2: should still be allowed
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.RemoteAddr = "2.2.2.2:1"
	w := httptest.NewRecorder()
	rl.Middleware(next).ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRateLimiter_IgnoresXForwardedFor(t *testing.T) {
	rl := NewRateLimiter(1, 1*time.Minute)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// First request with XFF header — should use RemoteAddr, not XFF
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.RemoteAddr = "10.0.0.1:5555"
	req.Header.Set("X-Forwarded-For", "203.0.113.50, 70.41.3.18")
	w := httptest.NewRecorder()
	rl.Middleware(next).ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Same RemoteAddr should be blocked regardless of different XFF
	req = httptest.NewRequest(http.MethodPost, "/login", nil)
	req.RemoteAddr = "10.0.0.1:5555"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	w = httptest.NewRecorder()
	rl.Middleware(next).ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestExtractClientIP(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		remote   string
		expected string
	}{
		// extractClientIP now always uses RemoteAddr (XFF/X-Real-IP are ignored for security)
		{"XFF_ignored", map[string]string{"X-Forwarded-For": "1.2.3.4, 5.6.7.8"}, "9.9.9.9:1234", "9.9.9.9"},
		{"XRealIP_ignored", map[string]string{"X-Real-IP": "10.0.0.1"}, "9.9.9.9:1234", "9.9.9.9"},
		{"RemoteAddr", map[string]string{}, "192.168.1.1:8080", "192.168.1.1"},
		{"RemoteAddr_no_port", map[string]string{}, "192.168.1.1", "192.168.1.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			if tt.remote != "" {
				req.RemoteAddr = tt.remote
			}
			assert.Equal(t, tt.expected, extractClientIP(req))
		})
	}
}

func TestRateLimiter_PurgeExpired(t *testing.T) {
	rl := NewRateLimiter(10, 50*time.Millisecond)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Add a request
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.RemoteAddr = "1.1.1.1:1"
	w := httptest.NewRecorder()
	rl.Middleware(next).ServeHTTP(w, req)

	// Wait for window to expire
	time.Sleep(100 * time.Millisecond)

	// Purge should remove expired entries
	rl.purgeExpired()

	rl.mu.Lock()
	count := len(rl.requests)
	rl.mu.Unlock()
	assert.Equal(t, 0, count)
}
