package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"

	"github.com/authplex/internal/domain/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testClaims() token.Claims {
	return token.Claims{
		Issuer:    "https://auth.example.com",
		Subject:   "user-123",
		Audience:  []string{"client-1"},
		ExpiresAt: 1700000000,
		IssuedAt:  1699996400,
		JWTID:     "jti-abc",
	}
}

func TestJWTSigner_RSA256_Structure(t *testing.T) {
	gen := NewKeyGenerator()
	signer := NewJWTSigner()

	privPEM, _, err := gen.GenerateRSA()
	require.NoError(t, err)

	jwt, err := signer.Sign(testClaims(), "rsa-kid-1", privPEM, "RS256")

	require.NoError(t, err)
	parts := strings.Split(jwt, ".")
	assert.Len(t, parts, 3)

	// Verify header
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)
	var header map[string]string
	require.NoError(t, json.Unmarshal(headerJSON, &header))
	assert.Equal(t, "RS256", header["alg"])
	assert.Equal(t, "JWT", header["typ"])
	assert.Equal(t, "rsa-kid-1", header["kid"])

	// Verify payload
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims token.Claims
	require.NoError(t, json.Unmarshal(payloadJSON, &claims))
	assert.Equal(t, "https://auth.example.com", claims.Issuer)
	assert.Equal(t, "user-123", claims.Subject)
}

func TestJWTSigner_RSA256_VerifySignature(t *testing.T) {
	gen := NewKeyGenerator()
	signer := NewJWTSigner()

	privPEM, pubPEM, err := gen.GenerateRSA()
	require.NoError(t, err)

	jwt, err := signer.Sign(testClaims(), "kid-1", privPEM, "RS256")
	require.NoError(t, err)

	parts := strings.Split(jwt, ".")
	signingInput := parts[0] + "." + parts[1]
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)

	// Parse public key and verify
	block, _ := pem.Decode(pubPEM)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)

	rsaPub := pub.(*rsa.PublicKey)
	hash := sha256.Sum256([]byte(signingInput))
	err = rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hash[:], signature)
	assert.NoError(t, err)
}

func TestJWTSigner_ES256_Structure(t *testing.T) {
	gen := NewKeyGenerator()
	signer := NewJWTSigner()

	privPEM, _, err := gen.GenerateEC()
	require.NoError(t, err)

	jwt, err := signer.Sign(testClaims(), "ec-kid-1", privPEM, "ES256")

	require.NoError(t, err)
	parts := strings.Split(jwt, ".")
	assert.Len(t, parts, 3)

	// Verify header
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)
	var header map[string]string
	require.NoError(t, json.Unmarshal(headerJSON, &header))
	assert.Equal(t, "ES256", header["alg"])
	assert.Equal(t, "ec-kid-1", header["kid"])
}

func TestJWTSigner_ES256_VerifySignature(t *testing.T) {
	gen := NewKeyGenerator()
	signer := NewJWTSigner()

	privPEM, pubPEM, err := gen.GenerateEC()
	require.NoError(t, err)

	jwt, err := signer.Sign(testClaims(), "kid-1", privPEM, "ES256")
	require.NoError(t, err)

	parts := strings.Split(jwt, ".")
	signingInput := parts[0] + "." + parts[1]
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)

	// Decode EC signature (r || s, each 32 bytes)
	assert.Len(t, sigBytes, 64)
	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])

	// Parse public key and verify
	block, _ := pem.Decode(pubPEM)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)

	ecPub := pub.(*ecdsa.PublicKey)
	assert.Equal(t, elliptic.P256(), ecPub.Curve)

	hash := sha256.Sum256([]byte(signingInput))
	assert.True(t, ecdsa.Verify(ecPub, hash[:], r, s))
}

func TestJWTSigner_UnsupportedAlgorithm(t *testing.T) {
	gen := NewKeyGenerator()
	signer := NewJWTSigner()

	privPEM, _, err := gen.GenerateRSA()
	require.NoError(t, err)

	_, err = signer.Sign(testClaims(), "kid-1", privPEM, "PS256")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported algorithm")
}

func TestJWTSigner_InvalidPEM(t *testing.T) {
	signer := NewJWTSigner()

	_, err := signer.Sign(testClaims(), "kid-1", []byte("not-pem"), "RS256")
	require.Error(t, err)
}

func TestJWTSigner_RS256_WithECKey_Fails(t *testing.T) {
	gen := NewKeyGenerator()
	signer := NewJWTSigner()

	privPEM, _, err := gen.GenerateEC()
	require.NoError(t, err)

	_, err = signer.Sign(testClaims(), "kid-1", privPEM, "RS256")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "RSA private key")
}

func TestJWTSigner_ES256_WithRSAKey_Fails(t *testing.T) {
	gen := NewKeyGenerator()
	signer := NewJWTSigner()

	privPEM, _, err := gen.GenerateRSA()
	require.NoError(t, err)

	_, err = signer.Sign(testClaims(), "kid-1", privPEM, "ES256")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "EC private key")
}
