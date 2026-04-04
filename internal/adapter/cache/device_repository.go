package cache

import (
	"context"
	"sync"

	"github.com/authplex/internal/domain/token"
	apperrors "github.com/authplex/pkg/sdk/errors"
)

// InMemoryDeviceRepository implements token.DeviceCodeRepository.
type InMemoryDeviceRepository struct {
	mu      sync.Mutex
	devices map[string]token.DeviceCode // keyed by device_code
}

// NewInMemoryDeviceRepository creates a new in-memory device code repository.
func NewInMemoryDeviceRepository() *InMemoryDeviceRepository {
	return &InMemoryDeviceRepository{devices: make(map[string]token.DeviceCode)}
}

var _ token.DeviceCodeRepository = (*InMemoryDeviceRepository)(nil)

func (r *InMemoryDeviceRepository) Store(_ context.Context, dc token.DeviceCode) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.devices[dc.DeviceCode] = dc
	return nil
}

func (r *InMemoryDeviceRepository) GetByDeviceCode(_ context.Context, deviceCode string) (token.DeviceCode, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	dc, ok := r.devices[deviceCode]
	if !ok {
		return token.DeviceCode{}, apperrors.New(apperrors.ErrNotFound, "device code not found")
	}
	return dc, nil
}

func (r *InMemoryDeviceRepository) GetByUserCode(_ context.Context, userCode string) (token.DeviceCode, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, dc := range r.devices {
		if dc.UserCode == userCode {
			return dc, nil
		}
	}
	return token.DeviceCode{}, apperrors.New(apperrors.ErrNotFound, "device code not found")
}

func (r *InMemoryDeviceRepository) Authorize(_ context.Context, userCode string, subject string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, dc := range r.devices {
		if dc.UserCode == userCode {
			dc.Subject = subject
			dc.Authorized = true
			r.devices[k] = dc
			return nil
		}
	}
	return apperrors.New(apperrors.ErrNotFound, "device code not found")
}

func (r *InMemoryDeviceRepository) Deny(_ context.Context, userCode string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, dc := range r.devices {
		if dc.UserCode == userCode {
			dc.Denied = true
			r.devices[k] = dc
			return nil
		}
	}
	return apperrors.New(apperrors.ErrNotFound, "device code not found")
}
