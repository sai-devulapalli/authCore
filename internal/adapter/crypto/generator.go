package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"github.com/authplex/internal/domain/jwk"
)

const rsaKeyBits = 2048

// KeyGenerator implements jwk.Generator using Go stdlib crypto.
type KeyGenerator struct{}

// NewKeyGenerator creates a new KeyGenerator.
func NewKeyGenerator() *KeyGenerator {
	return &KeyGenerator{}
}

var _ jwk.Generator = (*KeyGenerator)(nil)

// GenerateRSA generates an RSA-2048 key pair and returns PEM-encoded bytes.
func (g *KeyGenerator) GenerateRSA() ([]byte, []byte, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		return nil, nil, err
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, nil, err
	}
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privDER,
	})

	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	})

	return privPEM, pubPEM, nil
}

// GenerateEC generates an EC P-256 key pair and returns PEM-encoded bytes.
func (g *KeyGenerator) GenerateEC() ([]byte, []byte, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, nil, err
	}
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privDER,
	})

	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	})

	return privPEM, pubPEM, nil
}
