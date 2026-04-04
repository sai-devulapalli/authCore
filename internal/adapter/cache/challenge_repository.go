package cache

import (
	"context"
	"sync"

	"github.com/authplex/internal/domain/mfa"
	apperrors "github.com/authplex/pkg/sdk/errors"
)

// InMemoryChallengeRepository implements mfa.ChallengeRepository.
type InMemoryChallengeRepository struct {
	mu         sync.Mutex
	challenges map[string]mfa.MFAChallenge
}

// NewInMemoryChallengeRepository creates a new in-memory challenge repository.
func NewInMemoryChallengeRepository() *InMemoryChallengeRepository {
	return &InMemoryChallengeRepository{challenges: make(map[string]mfa.MFAChallenge)}
}

var _ mfa.ChallengeRepository = (*InMemoryChallengeRepository)(nil)

func (r *InMemoryChallengeRepository) Store(_ context.Context, c mfa.MFAChallenge) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.challenges[c.ID] = c
	return nil
}

func (r *InMemoryChallengeRepository) GetByID(_ context.Context, id string) (mfa.MFAChallenge, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.challenges[id]
	if !ok {
		return mfa.MFAChallenge{}, apperrors.New(apperrors.ErrNotFound, "challenge not found")
	}
	return c, nil
}

func (r *InMemoryChallengeRepository) MarkVerified(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.challenges[id]
	if !ok {
		return apperrors.New(apperrors.ErrNotFound, "challenge not found")
	}
	c.Verified = true
	r.challenges[id] = c
	return nil
}

func (r *InMemoryChallengeRepository) Delete(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.challenges, id)
	return nil
}
