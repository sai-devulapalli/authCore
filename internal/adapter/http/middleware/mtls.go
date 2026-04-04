package middleware

import (
	"crypto/x509"
	"net/http"

	apperrors "github.com/authplex/pkg/sdk/errors"
	"github.com/authplex/pkg/sdk/httputil"
)

// MTLS is middleware that verifies client TLS certificates for M2M authentication.
// It extracts the client certificate's Common Name (CN) or Subject Alternative Name
// and makes it available as the authenticated client identity.
type MTLS struct {
	// RequireClientCert: if true, reject requests without a verified client cert.
	// If false, mTLS is optional (verify if present, pass through if not).
	requireClientCert bool
}

// NewMTLS creates a new mTLS middleware.
func NewMTLS(requireClientCert bool) *MTLS {
	return &MTLS{requireClientCert: requireClientCert}
}

// Middleware returns an http.Handler that verifies client certificates.
// The TLS handshake and certificate verification is handled by Go's crypto/tls;
// this middleware checks the result and extracts the client identity.
func (m *MTLS) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if TLS connection has verified client certificates
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			if m.requireClientCert {
				httputil.WriteError(w, apperrors.New(apperrors.ErrUnauthorized, "client certificate required")) //nolint:errcheck
				return
			}
			// Optional mTLS — continue without cert
			next.ServeHTTP(w, r)
			return
		}

		// Extract client identity from the first verified certificate
		cert := r.TLS.PeerCertificates[0]
		clientID := extractClientIdentity(cert)

		// Set client identity as header for downstream handlers
		r.Header.Set("X-Client-Cert-CN", clientID)
		if len(cert.DNSNames) > 0 {
			r.Header.Set("X-Client-Cert-SAN", cert.DNSNames[0])
		}

		next.ServeHTTP(w, r)
	})
}

// extractClientIdentity returns the CN or first SAN from a certificate.
func extractClientIdentity(cert *x509.Certificate) string {
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}
	if len(cert.DNSNames) > 0 {
		return cert.DNSNames[0]
	}
	if len(cert.EmailAddresses) > 0 {
		return cert.EmailAddresses[0]
	}
	return "unknown"
}

// TLSConfigHelper provides helper documentation for setting up mTLS.
// To enable mTLS, configure the http.Server's TLSConfig:
//
//	caCertPool := x509.NewCertPool()
//	caCertPool.AppendCertsFromPEM(caCertPEM)
//
//	srv := &http.Server{
//	    TLSConfig: &tls.Config{
//	        ClientCAs:  caCertPool,
//	        ClientAuth: tls.RequireAndVerifyClientCert, // or tls.VerifyClientCertIfGiven
//	    },
//	}
//	srv.ListenAndServeTLS("server.crt", "server.key")
