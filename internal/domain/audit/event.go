package audit

import "time"

// EventType categorizes audit events.
type EventType string

const (
	EventLoginSuccess     EventType = "login_success"
	EventLoginFailure     EventType = "login_failure"
	EventRegister         EventType = "register"
	EventPasswordReset    EventType = "password_reset"
	EventOTPRequested     EventType = "otp_requested"
	EventOTPVerified      EventType = "otp_verified"
	EventOTPFailed        EventType = "otp_failed"
	EventMFAEnrolled      EventType = "mfa_enrolled"
	EventMFAVerified      EventType = "mfa_verified"
	EventMFAFailed        EventType = "mfa_failed"
	EventTokenIssued      EventType = "token_issued"
	EventTokenRefreshed   EventType = "token_refreshed"
	EventTokenRevoked     EventType = "token_revoked"
	EventSessionCreated   EventType = "session_created"
	EventSessionRevoked   EventType = "session_revoked"
	EventTenantCreated    EventType = "tenant_created"
	EventTenantUpdated    EventType = "tenant_updated"
	EventTenantDeleted    EventType = "tenant_deleted"
	EventClientCreated    EventType = "client_created"
	EventClientDeleted    EventType = "client_deleted"
	EventRoleCreated      EventType = "role_created"
	EventRoleAssigned     EventType = "role_assigned"
	EventRoleRevoked      EventType = "role_revoked"
	EventProviderCreated  EventType = "provider_created"
	EventProviderDeleted  EventType = "provider_deleted"
	EventAdminAPIAccess   EventType = "admin_api_access"
	EventAgentTokenIssued EventType = "agent_token_issued"
)

// Event represents a single audit log entry.
type Event struct {
	ID           string
	TenantID     string
	ActorID      string // user ID, client ID, or "system"
	ActorType    string // "user", "admin", "system", "client"
	Action       EventType
	ResourceType string // "user", "client", "tenant", "role", "session", "token"
	ResourceID   string
	IPAddress    string
	UserAgent    string
	Details      map[string]any
	Timestamp    time.Time
}
