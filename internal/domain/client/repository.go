package client

import "context"

// Repository is the port interface for client persistence.
type Repository interface {
	Create(ctx context.Context, c Client) error
	GetByID(ctx context.Context, id string, tenantID string) (Client, error)
	Update(ctx context.Context, c Client) error
	Delete(ctx context.Context, id string, tenantID string) error
	List(ctx context.Context, tenantID string, offset, limit int) ([]Client, int, error)
	UpdateAPIKey(ctx context.Context, clientID, tenantID string, apiKeyHash []byte) error
	GetByAPIKeyHash(ctx context.Context, apiKeyHash []byte, tenantID string) (Client, error)
}
