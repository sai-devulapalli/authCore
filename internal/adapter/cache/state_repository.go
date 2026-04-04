package cache

import (
	"context"
	"sync"

	"github.com/authplex/internal/domain/identity"
	apperrors "github.com/authplex/pkg/sdk/errors"
)

// InMemoryStateRepository implements identity.StateRepository.
type InMemoryStateRepository struct {
	mu     sync.Mutex
	states map[string]identity.OAuthState
}

// NewInMemoryStateRepository creates a new in-memory state repository.
func NewInMemoryStateRepository() *InMemoryStateRepository {
	return &InMemoryStateRepository{states: make(map[string]identity.OAuthState)}
}

var _ identity.StateRepository = (*InMemoryStateRepository)(nil)

func (r *InMemoryStateRepository) Store(_ context.Context, s identity.OAuthState) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.states[s.State] = s
	return nil
}

func (r *InMemoryStateRepository) Consume(_ context.Context, state string) (identity.OAuthState, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.states[state]
	if !ok {
		return identity.OAuthState{}, apperrors.New(apperrors.ErrNotFound, "state not found")
	}
	delete(r.states, state)
	if s.IsExpired() {
		return identity.OAuthState{}, apperrors.New(apperrors.ErrBadRequest, "state has expired")
	}
	return s, nil
}
