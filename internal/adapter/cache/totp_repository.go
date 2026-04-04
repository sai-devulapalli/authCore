package cache

import (
	"context"
	"sync"

	"github.com/authplex/internal/domain/mfa"
	apperrors "github.com/authplex/pkg/sdk/errors"
)

// InMemoryTOTPRepository implements mfa.TOTPRepository.
type InMemoryTOTPRepository struct {
	mu          sync.Mutex
	enrollments map[string]mfa.TOTPEnrollment
}

// NewInMemoryTOTPRepository creates a new in-memory TOTP repository.
func NewInMemoryTOTPRepository() *InMemoryTOTPRepository {
	return &InMemoryTOTPRepository{enrollments: make(map[string]mfa.TOTPEnrollment)}
}

var _ mfa.TOTPRepository = (*InMemoryTOTPRepository)(nil)

func (r *InMemoryTOTPRepository) Store(_ context.Context, e mfa.TOTPEnrollment) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.enrollments[e.ID] = e
	return nil
}

func (r *InMemoryTOTPRepository) GetBySubject(_ context.Context, tenantID, subject string) (mfa.TOTPEnrollment, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.enrollments {
		if e.TenantID == tenantID && e.Subject == subject {
			return e, nil
		}
	}
	return mfa.TOTPEnrollment{}, apperrors.New(apperrors.ErrNotFound, "TOTP enrollment not found")
}

func (r *InMemoryTOTPRepository) Confirm(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.enrollments[id]
	if !ok {
		return apperrors.New(apperrors.ErrNotFound, "enrollment not found")
	}
	e.Confirmed = true
	r.enrollments[id] = e
	return nil
}

func (r *InMemoryTOTPRepository) Delete(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.enrollments, id)
	return nil
}
