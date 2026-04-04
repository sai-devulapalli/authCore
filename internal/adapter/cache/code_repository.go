package cache

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/authplex/internal/domain/token"
	apperrors "github.com/authplex/pkg/sdk/errors"
)

// InMemoryCodeRepository implements token.CodeRepository using an in-memory map.
// Used for development and testing. Production will use Redis.
type InMemoryCodeRepository struct {
	mu    sync.Mutex
	codes map[string]storedCode
}

type storedCode struct {
	data      []byte
	expiresAt time.Time
}

// NewInMemoryCodeRepository creates a new in-memory code repository.
func NewInMemoryCodeRepository() *InMemoryCodeRepository {
	return &InMemoryCodeRepository{codes: make(map[string]storedCode)}
}

var _ token.CodeRepository = (*InMemoryCodeRepository)(nil)

// Store saves an authorization code with its associated data.
func (r *InMemoryCodeRepository) Store(_ context.Context, code token.AuthorizationCode) error {
	data, err := json.Marshal(code)
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to marshal auth code", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.codes[code.Code] = storedCode{
		data:      data,
		expiresAt: code.ExpiresAt,
	}
	return nil
}

// Consume atomically retrieves and deletes an authorization code.
func (r *InMemoryCodeRepository) Consume(_ context.Context, code string) (token.AuthorizationCode, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	stored, ok := r.codes[code]
	if !ok {
		return token.AuthorizationCode{}, apperrors.New(apperrors.ErrNotFound, "authorization code not found")
	}
	delete(r.codes, code)

	if time.Now().UTC().After(stored.expiresAt) {
		return token.AuthorizationCode{}, apperrors.New(apperrors.ErrBadRequest, "authorization code has expired")
	}

	var ac token.AuthorizationCode
	if err := json.Unmarshal(stored.data, &ac); err != nil {
		return token.AuthorizationCode{}, apperrors.Wrap(apperrors.ErrInternal, "failed to unmarshal auth code", err)
	}
	return ac, nil
}
