package cache

import (
	"bytes"
	"context"
	"sync"

	"github.com/authplex/internal/domain/mfa"
	apperrors "github.com/authplex/pkg/sdk/errors"
)

// InMemoryWebAuthnRepository implements mfa.WebAuthnRepository.
type InMemoryWebAuthnRepository struct {
	mu          sync.Mutex
	credentials map[string]mfa.WebAuthnCredential
}

// NewInMemoryWebAuthnRepository creates a new in-memory WebAuthn credential repository.
func NewInMemoryWebAuthnRepository() *InMemoryWebAuthnRepository {
	return &InMemoryWebAuthnRepository{credentials: make(map[string]mfa.WebAuthnCredential)}
}

var _ mfa.WebAuthnRepository = (*InMemoryWebAuthnRepository)(nil)

func (r *InMemoryWebAuthnRepository) Store(_ context.Context, cred mfa.WebAuthnCredential) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.credentials[cred.ID] = cred
	return nil
}

func (r *InMemoryWebAuthnRepository) GetBySubject(_ context.Context, tenantID, subject string) ([]mfa.WebAuthnCredential, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var result []mfa.WebAuthnCredential
	for _, c := range r.credentials {
		if c.TenantID == tenantID && c.Subject == subject {
			result = append(result, c)
		}
	}
	return result, nil
}

func (r *InMemoryWebAuthnRepository) GetByCredentialID(_ context.Context, credentialID []byte) (mfa.WebAuthnCredential, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.credentials {
		if bytes.Equal(c.CredentialID, credentialID) {
			return c, nil
		}
	}
	return mfa.WebAuthnCredential{}, apperrors.New(apperrors.ErrNotFound, "WebAuthn credential not found")
}

func (r *InMemoryWebAuthnRepository) UpdateSignCount(_ context.Context, id string, signCount uint32) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.credentials[id]
	if !ok {
		return apperrors.New(apperrors.ErrNotFound, "WebAuthn credential not found")
	}
	c.SignCount = signCount
	r.credentials[id] = c
	return nil
}

func (r *InMemoryWebAuthnRepository) Delete(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.credentials, id)
	return nil
}
