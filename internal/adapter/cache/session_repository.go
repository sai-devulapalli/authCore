package cache

import (
	"context"
	"sync"

	"github.com/authplex/internal/domain/user"
	apperrors "github.com/authplex/pkg/sdk/errors"
)

// InMemorySessionRepository implements user.SessionRepository.
type InMemorySessionRepository struct {
	mu       sync.Mutex
	sessions map[string]user.Session
}

// NewInMemorySessionRepository creates a new in-memory session repository.
func NewInMemorySessionRepository() *InMemorySessionRepository {
	return &InMemorySessionRepository{sessions: make(map[string]user.Session)}
}

var _ user.SessionRepository = (*InMemorySessionRepository)(nil)

func (r *InMemorySessionRepository) Create(_ context.Context, s user.Session) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions[s.ID] = s
	return nil
}

func (r *InMemorySessionRepository) GetByID(_ context.Context, id string) (user.Session, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sessions[id]
	if !ok {
		return user.Session{}, apperrors.New(apperrors.ErrNotFound, "session not found")
	}
	return s, nil
}

func (r *InMemorySessionRepository) Delete(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.sessions, id)
	return nil
}

func (r *InMemorySessionRepository) DeleteByUserID(_ context.Context, userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, s := range r.sessions {
		if s.UserID == userID {
			delete(r.sessions, id)
		}
	}
	return nil
}
