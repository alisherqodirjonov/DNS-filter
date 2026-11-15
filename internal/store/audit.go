package store

import (
	"context"
	"fmt"
	"time"
)

// AuditEvent is one administrative action.
type AuditEvent struct {
	ID         int64
	Timestamp  time.Time
	Username   string
	Action     string
	ObjectType string
	ObjectID   string
	Result     string
}

// InsertAudit writes an administrative audit row.
// Callers must not include passwords, cookies, or session tokens in any field.
func (s *Store) InsertAudit(ctx context.Context, ev AuditEvent) error {
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO audit_events(timestamp, username, action, object_type, object_id, result)
		VALUES (?, ?, ?, ?, ?, ?)`,
		formatTime(ev.Timestamp), ev.Username, ev.Action, ev.ObjectType, ev.ObjectID, ev.Result)
	if err != nil {
		return fmt.Errorf("store: insert audit: %w", err)
	}
	return nil
}

// ListAudit returns a page of audit events, newest first, and the total count.
func (s *Store) ListAudit(ctx context.Context, limit, offset int) ([]AuditEvent, int, error) {
	if limit <= 0 || limit > 100 {
		return nil, 0, fmt.Errorf("store: audit limit must be between 1 and 100")
	}
	if offset < 0 {
		return nil, 0, fmt.Errorf("store: audit offset must be zero or greater")
	}
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_events`).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, timestamp, username, action, object_type, object_id, result
		FROM audit_events ORDER BY id DESC LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []AuditEvent
	for rows.Next() {
		var ev AuditEvent
		var ts string
		if err := rows.Scan(&ev.ID, &ts, &ev.Username, &ev.Action, &ev.ObjectType, &ev.ObjectID, &ev.Result); err != nil {
			return nil, 0, err
		}
		ev.Timestamp, err = parseTime(ts)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, ev)
	}
	return out, total, rows.Err()
}
