package middleware

import (
	"net/http"
	"strings"
	"sync"
	"time"

	apperrors "github.com/authplex/pkg/sdk/errors"
	"github.com/authplex/pkg/sdk/httputil"
)

// RateLimiter is middleware that limits requests per IP using a sliding window.
type RateLimiter struct {
	mu       sync.Mutex
	requests map[string][]time.Time
	limit    int
	window   time.Duration
	done     chan struct{}
}

// NewRateLimiter creates a new rate limiter.
// limit: max requests per window. window: time window duration.
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		requests: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
		done:     make(chan struct{}),
	}
	go rl.cleanup()
	return rl
}

// Stop terminates the cleanup goroutine.
func (rl *RateLimiter) Stop() {
	close(rl.done)
}

// Middleware returns an http.Handler that enforces rate limits.
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := extractClientIP(r)

		if !rl.allow(key) {
			w.Header().Set("Retry-After", "60")
			httputil.WriteError(w, apperrors.New(apperrors.ErrBadRequest, "rate limit exceeded")) //nolint:errcheck
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (rl *RateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-rl.window)

	// Filter to only requests within the window
	times := rl.requests[key]
	var valid []time.Time
	for _, t := range times {
		if t.After(windowStart) {
			valid = append(valid, t)
		}
	}

	if len(valid) >= rl.limit {
		rl.requests[key] = valid
		return false
	}

	rl.requests[key] = append(valid, now)
	return true
}

func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			rl.purgeExpired()
		case <-rl.done:
			return
		}
	}
}

// purgeExpired removes expired entries. Exported for testing.
func (rl *RateLimiter) purgeExpired() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	cutoff := time.Now().Add(-rl.window)
	for key, times := range rl.requests {
		var valid []time.Time
		for _, t := range times {
			if t.After(cutoff) {
				valid = append(valid, t)
			}
		}
		if len(valid) == 0 {
			delete(rl.requests, key)
		} else {
			rl.requests[key] = valid
		}
	}
}

func extractClientIP(r *http.Request) string {
	// Use RemoteAddr for rate limiting — it reflects the actual TCP connection
	// and cannot be spoofed. X-Forwarded-For and X-Real-IP are user-controlled
	// headers that an attacker can set to bypass rate limits.
	addr := r.RemoteAddr
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		return addr[:idx]
	}
	return addr
}
