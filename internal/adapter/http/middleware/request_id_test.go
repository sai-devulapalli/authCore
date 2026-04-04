package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequestID_GeneratesID(t *testing.T) {
	var capturedID string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedID = RequestIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	RequestID(next).ServeHTTP(w, req)

	// Response header must be set
	responseID := w.Header().Get("X-Request-ID")
	require.NotEmpty(t, responseID, "X-Request-ID response header should be set")

	// Context ID must match response header
	assert.Equal(t, responseID, capturedID, "context ID should match response header")
}

func TestRequestID_PreservesExistingID(t *testing.T) {
	const existingID = "my-existing-request-id-12345"

	var capturedID string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedID = RequestIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Request-ID", existingID)
	w := httptest.NewRecorder()

	RequestID(next).ServeHTTP(w, req)

	// Response header must preserve the provided ID
	assert.Equal(t, existingID, w.Header().Get("X-Request-ID"))

	// Context must also carry the same ID
	assert.Equal(t, existingID, capturedID)
}

func TestRequestIDFromContext_NotSet(t *testing.T) {
	id := RequestIDFromContext(context.Background())
	assert.Empty(t, id, "should return empty string when no ID in context")
}

func TestRequestIDFromContext_WithValue(t *testing.T) {
	const wantID = "test-request-id"

	// Exercise via middleware to ensure the key round-trips correctly
	var capturedID string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedID = RequestIDFromContext(r.Context())
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Request-ID", wantID)
	RequestID(next).ServeHTTP(httptest.NewRecorder(), req)

	assert.Equal(t, wantID, capturedID)
}
