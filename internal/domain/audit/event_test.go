package audit

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEventTypes(t *testing.T) {
	assert.Equal(t, EventType("login_success"), EventLoginSuccess)
	assert.Equal(t, EventType("login_failure"), EventLoginFailure)
	assert.Equal(t, EventType("register"), EventRegister)
	assert.Equal(t, EventType("token_issued"), EventTokenIssued)
	assert.Equal(t, EventType("role_assigned"), EventRoleAssigned)
}

func TestEvent_Fields(t *testing.T) {
	e := Event{
		ID:           "e1",
		TenantID:     "t1",
		ActorID:      "user-123",
		ActorType:    "user",
		Action:       EventLoginSuccess,
		ResourceType: "session",
		ResourceID:   "sess-abc",
	}

	assert.Equal(t, "e1", e.ID)
	assert.Equal(t, EventLoginSuccess, e.Action)
	assert.Equal(t, "user", e.ActorType)
}
