package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/authplex/internal/domain/audit"
	apperrors "github.com/authplex/pkg/sdk/errors"
)

// AuditRepository implements audit.Repository using PostgreSQL.
type AuditRepository struct {
	db *sql.DB
}

// NewAuditRepository creates a new PostgreSQL-backed audit repository.
func NewAuditRepository(db *sql.DB) *AuditRepository {
	return &AuditRepository{db: db}
}

var _ audit.Repository = (*AuditRepository)(nil)

// Store persists an audit event.
func (r *AuditRepository) Store(ctx context.Context, event audit.Event) error {
	ctx, cancel := WithQueryTimeout(ctx)
	defer cancel()
	var detailsJSON []byte
	if event.Details != nil {
		var err error
		detailsJSON, err = json.Marshal(event.Details)
		if err != nil {
			return apperrors.Wrap(apperrors.ErrInternal, "failed to marshal audit details", err)
		}
	}

	query := `INSERT INTO audit_events (id, tenant_id, actor_id, actor_type, action, resource_type, resource_id, ip_address, user_agent, details, timestamp)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`

	_, err := r.db.ExecContext(ctx, query,
		event.ID,
		event.TenantID,
		event.ActorID,
		event.ActorType,
		string(event.Action),
		event.ResourceType,
		event.ResourceID,
		event.IPAddress,
		event.UserAgent,
		detailsJSON,
		event.Timestamp,
	)
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to store audit event", err)
	}
	return nil
}

// Query retrieves audit events matching the filter.
func (r *AuditRepository) Query(ctx context.Context, filter audit.QueryFilter) ([]audit.Event, error) {
	ctx, cancel := WithQueryTimeout(ctx)
	defer cancel()
	query := `SELECT id, tenant_id, actor_id, actor_type, action, resource_type, resource_id, ip_address, user_agent, details, timestamp
		FROM audit_events WHERE 1=1`

	args := []any{}
	argIdx := 1

	if filter.TenantID != "" {
		query += ` AND tenant_id = $` + itoa(argIdx)
		args = append(args, filter.TenantID)
		argIdx++
	}
	if filter.ActorID != "" {
		query += ` AND actor_id = $` + itoa(argIdx)
		args = append(args, filter.ActorID)
		argIdx++
	}
	if filter.Action != "" {
		query += ` AND action = $` + itoa(argIdx)
		args = append(args, string(filter.Action))
		argIdx++
	}
	if filter.ResourceType != "" {
		query += ` AND resource_type = $` + itoa(argIdx)
		args = append(args, filter.ResourceType)
		argIdx++
	}
	if filter.ResourceID != "" {
		query += ` AND resource_id = $` + itoa(argIdx)
		args = append(args, filter.ResourceID)
		argIdx++
	}

	query += ` ORDER BY timestamp DESC`

	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	query += ` LIMIT $` + itoa(argIdx)
	args = append(args, limit)
	argIdx++

	if filter.Offset > 0 {
		query += ` OFFSET $` + itoa(argIdx)
		args = append(args, filter.Offset)
	}

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrInternal, "failed to query audit events", err)
	}
	defer rows.Close()

	var events []audit.Event
	for rows.Next() {
		var e audit.Event
		var action string
		var detailsJSON []byte
		var ts time.Time

		if scanErr := rows.Scan(
			&e.ID, &e.TenantID, &e.ActorID, &e.ActorType,
			&action, &e.ResourceType, &e.ResourceID,
			&e.IPAddress, &e.UserAgent, &detailsJSON, &ts,
		); scanErr != nil {
			return nil, apperrors.Wrap(apperrors.ErrInternal, "failed to scan audit event", scanErr)
		}

		e.Action = audit.EventType(action)
		e.Timestamp = ts

		if len(detailsJSON) > 0 {
			var details map[string]any
			if unmarshalErr := json.Unmarshal(detailsJSON, &details); unmarshalErr == nil {
				e.Details = details
			}
		}

		events = append(events, e)
	}

	if err := rows.Err(); err != nil {
		return nil, apperrors.Wrap(apperrors.ErrInternal, "audit rows iteration error", err)
	}

	return events, nil
}

// itoa converts an int to its string representation (simple helper to avoid strconv import).
func itoa(n int) string {
	if n < 10 {
		return string(rune('0' + n))
	}
	return string(rune('0'+n/10)) + string(rune('0'+n%10))
}
