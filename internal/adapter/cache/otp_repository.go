package cache

import (
	"context"
	"sync"

	"github.com/authplex/internal/domain/otp"
	apperrors "github.com/authplex/pkg/sdk/errors"
)

// InMemoryOTPRepository implements otp.Repository.
type InMemoryOTPRepository struct {
	mu   sync.Mutex
	otps map[string]otp.OTP // key: tenantID + ":" + identifier
}

// NewInMemoryOTPRepository creates a new in-memory OTP repository.
func NewInMemoryOTPRepository() *InMemoryOTPRepository {
	return &InMemoryOTPRepository{otps: make(map[string]otp.OTP)}
}

var _ otp.Repository = (*InMemoryOTPRepository)(nil)

func key(identifier, tenantID string) string {
	return tenantID + ":" + identifier
}

func (r *InMemoryOTPRepository) Store(_ context.Context, o otp.OTP) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.otps[key(o.Identifier, o.TenantID)] = o
	return nil
}

func (r *InMemoryOTPRepository) Get(_ context.Context, identifier, tenantID string) (otp.OTP, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	o, ok := r.otps[key(identifier, tenantID)]
	if !ok {
		return otp.OTP{}, apperrors.New(apperrors.ErrNotFound, "OTP not found")
	}
	return o, nil
}

func (r *InMemoryOTPRepository) IncrementAttempts(_ context.Context, identifier, tenantID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := key(identifier, tenantID)
	o, ok := r.otps[k]
	if !ok {
		return apperrors.New(apperrors.ErrNotFound, "OTP not found")
	}
	o.Attempts++
	r.otps[k] = o
	return nil
}

func (r *InMemoryOTPRepository) Delete(_ context.Context, identifier, tenantID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.otps, key(identifier, tenantID))
	return nil
}
