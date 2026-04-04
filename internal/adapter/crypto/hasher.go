package crypto

import (
	"github.com/authplex/internal/domain/client"
	"github.com/authplex/internal/domain/user"
	"golang.org/x/crypto/bcrypt"
)

const bcryptCost = 12

// BcryptHasher implements client.SecretHasher using bcrypt.
type BcryptHasher struct{}

// NewBcryptHasher creates a new BcryptHasher.
func NewBcryptHasher() *BcryptHasher {
	return &BcryptHasher{}
}

var _ client.SecretHasher = (*BcryptHasher)(nil)
var _ user.PasswordHasher = (*BcryptHasher)(nil)

// Hash generates a bcrypt hash of the given secret.
func (h *BcryptHasher) Hash(secret string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(secret), bcryptCost)
}

// Verify compares a secret with a bcrypt hash.
func (h *BcryptHasher) Verify(secret string, hash []byte) error {
	return bcrypt.CompareHashAndPassword(hash, []byte(secret))
}
