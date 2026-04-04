package token

import "context"

// UserValidator is the port interface for validating user credentials.
// AuthPlex is headless; the implementing adapter calls an external user store
// or delegates to a configurable webhook.
type UserValidator interface {
	ValidateCredentials(ctx context.Context, tenantID, username, password string) (subject string, err error)
}
