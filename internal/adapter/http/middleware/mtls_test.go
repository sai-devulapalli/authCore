package middleware

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMTLS_NoCert_Required(t *testing.T) {
	m := NewMTLS(true)
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("should not be called")
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// No TLS
	w := httptest.NewRecorder()
	m.Middleware(next).ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestMTLS_NoCert_Optional(t *testing.T) {
	m := NewMTLS(false)
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	m.Middleware(next).ServeHTTP(w, req)

	assert.True(t, called)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestMTLS_WithCert(t *testing.T) {
	m := NewMTLS(true)
	var capturedCN, capturedSAN string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedCN = r.Header.Get("X-Client-Cert-CN")
		capturedSAN = r.Header.Get("X-Client-Cert-SAN")
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{
			{
				Subject:  pkix.Name{CommonName: "payment-service"},
				DNSNames: []string{"payment.internal"},
			},
		},
	}

	w := httptest.NewRecorder()
	m.Middleware(next).ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "payment-service", capturedCN)
	assert.Equal(t, "payment.internal", capturedSAN)
}

func TestExtractClientIdentity_CN(t *testing.T) {
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: "my-service"}}
	assert.Equal(t, "my-service", extractClientIdentity(cert))
}

func TestExtractClientIdentity_SAN(t *testing.T) {
	cert := &x509.Certificate{DNSNames: []string{"api.internal"}}
	assert.Equal(t, "api.internal", extractClientIdentity(cert))
}

func TestExtractClientIdentity_Email(t *testing.T) {
	cert := &x509.Certificate{EmailAddresses: []string{"svc@company.com"}}
	assert.Equal(t, "svc@company.com", extractClientIdentity(cert))
}

func TestExtractClientIdentity_Unknown(t *testing.T) {
	cert := &x509.Certificate{}
	assert.Equal(t, "unknown", extractClientIdentity(cert))
}
