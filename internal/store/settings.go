package store

import (
	"context"
	"time"
)

// Setting is one value saved from the console, with who saved it and when.
type Setting struct {
	Key       string
	Value     string
	UpdatedAt time.Time
	UpdatedBy string
}

// ListSettings returns every saved setting keyed by name.
func (s *Store) ListSettings(ctx context.Context) (map[string]Setting, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key, value, updated_at, updated_by FROM settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]Setting{}
	for rows.Next() {
		var item Setting
		var updated string
		if err := rows.Scan(&item.Key, &item.Value, &updated, &item.UpdatedBy); err != nil {
			return nil, err
		}
		if item.UpdatedAt, err = parseTime(updated); err != nil {
			return nil, err
		}
		out[item.Key] = item
	}
	return out, rows.Err()
}

// SaveSettings writes the given values in one transaction.
func (s *Store) SaveSettings(ctx context.Context, values map[string]string, username string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := formatTime(time.Now())
	for key, value := range values {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO settings(key, value, updated_at, updated_by) VALUES (?, ?, ?, ?)
			ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at,
				updated_by = excluded.updated_by`, key, value, now, username); err != nil {
			return err
		}
	}
	return tx.Commit()
}
