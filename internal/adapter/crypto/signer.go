package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"

	"github.com/authplex/internal/domain/token"
)

// JWTSigner implements token.Signer using Go stdlib crypto.
type JWTSigner struct{}

// NewJWTSigner creates a new JWTSigner.
func NewJWTSigner() *JWTSigner {
	return &JWTSigner{}
}

var _ token.Signer = (*JWTSigner)(nil)

type jwtHeader struct {
	ALG string `json:"alg"`
	TYP string `json:"typ"`
	KID string `json:"kid"`
}

// Sign creates a signed JWT from claims using the provided key and algorithm.
func (s *JWTSigner) Sign(claims token.Claims, kid string, privateKeyPEM []byte, algorithm string) (string, error) {
	header := jwtHeader{
		ALG: algorithm,
		TYP: "JWT",
		KID: kid,
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JWT header: %w", err)
	}

	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JWT payload: %w", err)
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := headerB64 + "." + payloadB64

	privKey, err := parsePrivateKey(privateKeyPEM)
	if err != nil {
		return "", err
	}

	signature, err := signPayload(signingInput, privKey, algorithm)
	if err != nil {
		return "", err
	}

	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)
	return signingInput + "." + signatureB64, nil
}

func parsePrivateKey(pemBytes []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return key, nil
}

func signPayload(input string, key crypto.PrivateKey, algorithm string) ([]byte, error) {
	hash := sha256.Sum256([]byte(input))

	switch algorithm {
	case "RS256":
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("RS256 requires an RSA private key")
		}
		return rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, hash[:])

	case "ES256":
		ecKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("ES256 requires an EC private key")
		}
		r, s, err := ecdsa.Sign(rand.Reader, ecKey, hash[:])
		if err != nil {
			return nil, fmt.Errorf("ECDSA sign failed: %w", err)
		}
		// Fixed-length encoding per RFC 7518 Section 3.4
		return encodeECDSASignature(r, s, 32), nil

	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

// encodeECDSASignature encodes r,s as fixed-size concatenation (RFC 7518 Section 3.4).
func encodeECDSASignature(r, s *big.Int, byteLen int) []byte {
	sig := make([]byte, byteLen*2)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[byteLen-len(rBytes):byteLen], rBytes)
	copy(sig[2*byteLen-len(sBytes):], sBytes)
	return sig
}
