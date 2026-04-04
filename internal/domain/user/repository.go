package user

import "context"

// Repository is the port interface for user persistence.
type Repository interface {
	Create(ctx context.Context, u User) error
	GetByID(ctx context.Context, id, tenantID string) (User, error)
	GetByEmail(ctx context.Context, email, tenantID string) (User, error)
	GetByPhone(ctx context.Context, phone, tenantID string) (User, error)
	Update(ctx context.Context, u User) error
	Delete(ctx context.Context, id, tenantID string) error
	HardDelete(ctx context.Context, id, tenantID string) error // GDPR right to erasure
	IncrementTokenVersion(ctx context.Context, id, tenantID string) error
	ListByTenant(ctx context.Context, tenantID string, offset, limit int) ([]User, int, error)
}

// SessionRepository is the port interface for session persistence.
type SessionRepository interface {
	Create(ctx context.Context, s Session) error
	GetByID(ctx context.Context, id string) (Session, error)
	Delete(ctx context.Context, id string) error
	DeleteByUserID(ctx context.Context, userID string) error
}
