package crypto

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"

	"github.com/authplex/internal/domain/jwk"
)

// JWKConverter implements jwk.Converter, transforming PEM public keys to PublicJWK.
type JWKConverter struct{}

// NewJWKConverter creates a new JWKConverter.
func NewJWKConverter() *JWKConverter {
	return &JWKConverter{}
}

var _ jwk.Converter = (*JWKConverter)(nil)

// PEMToPublicJWK parses a PEM-encoded public key and returns a PublicJWK.
func (c *JWKConverter) PEMToPublicJWK(publicKeyPEM []byte, kid string, alg string) (jwk.PublicJWK, error) {
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return jwk.PublicJWK{}, fmt.Errorf("failed to decode PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return jwk.PublicJWK{}, fmt.Errorf("failed to parse public key: %w", err)
	}

	switch key := pub.(type) {
	case *rsa.PublicKey:
		return rsaToJWK(key, kid, alg), nil
	case *ecdsa.PublicKey:
		return ecToJWK(key, kid, alg)
	default:
		return jwk.PublicJWK{}, fmt.Errorf("unsupported public key type: %T", pub)
	}
}

func rsaToJWK(key *rsa.PublicKey, kid string, alg string) jwk.PublicJWK {
	return jwk.PublicJWK{
		KTY: "RSA",
		Use: "sig",
		KID: kid,
		ALG: alg,
		N:   base64URLEncodeBigInt(key.N),
		E:   base64URLEncodeInt(key.E),
	}
}

func ecToJWK(key *ecdsa.PublicKey, kid string, alg string) (jwk.PublicJWK, error) {
	params := key.Curve.Params()
	byteLen := (params.BitSize + 7) / 8

	xBytes := padLeft(key.X.Bytes(), byteLen)
	yBytes := padLeft(key.Y.Bytes(), byteLen)

	return jwk.PublicJWK{
		KTY: "EC",
		Use: "sig",
		KID: kid,
		ALG: alg,
		CRV: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(xBytes),
		Y:   base64.RawURLEncoding.EncodeToString(yBytes),
	}, nil
}

func base64URLEncodeBigInt(n *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(n.Bytes())
}

func base64URLEncodeInt(e int) string {
	// RSA public exponent is typically 65537 (3 bytes)
	b := big.NewInt(int64(e))
	return base64.RawURLEncoding.EncodeToString(b.Bytes())
}

func padLeft(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	padded := make([]byte, size)
	copy(padded[size-len(b):], b)
	return padded
}
