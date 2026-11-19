package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// Event is one DNS query recorded by the filter.
type Event struct {
	ID                int64
	Timestamp         time.Time
	ClientIP          string
	QName             string
	QType             string
	Transport         string
	Action            string
	RCode             string
	UpstreamLatencyMS *int64
	MatchedSource     string
	MatchedDomain     string
}

// EventFilter selects a page of query events.
type EventFilter struct {
	QName  string
	Action string
	Limit  int
	Offset int
}

// ActionCounts are per-decision totals taken from the daily counters.
type ActionCounts struct {
	Allowed int
	Blocked int
	Errors  int
}

// Total is the number of answered queries.
func (c ActionCounts) Total() int {
	return c.Allowed + c.Blocked + c.Errors
}

// RecordQuery counts a query on its day and, when keep is true, also stores the event row.
// Counters are kept for every query so totals stay right whatever the logging mode.
func (s *Store) RecordQuery(ctx context.Context, ev Event, keep bool) error {
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO query_counts(day, action, count) VALUES (?, ?, 1)
		ON CONFLICT(day, action) DO UPDATE SET count = count + 1`,
		day(ev.Timestamp), ev.Action); err != nil {
		return fmt.Errorf("store: count query: %w", err)
	}
	if keep {
		if _, err := insertEvent(ctx, tx, ev); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// CountsSince sums the daily counters from the day of since onward.
func (s *Store) CountsSince(ctx context.Context, since time.Time) (ActionCounts, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT action, SUM(count) FROM query_counts WHERE day >= ? GROUP BY action`, day(since))
	if err != nil {
		return ActionCounts{}, err
	}
	defer rows.Close()
	var c ActionCounts
	for rows.Next() {
		var action string
		var n int
		if err := rows.Scan(&action, &n); err != nil {
			return ActionCounts{}, err
		}
		switch action {
		case "ALLOWED":
			c.Allowed = n
		case "BLOCKED":
			c.Blocked = n
		case "ERROR":
			c.Errors = n
		}
	}
	return c, rows.Err()
}

// InsertEvent writes one query event and returns its id. It does not touch the counters.
func (s *Store) InsertEvent(ctx context.Context, ev Event) (int64, error) {
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	return insertEvent(ctx, s.db, ev)
}

type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func insertEvent(ctx context.Context, db execer, ev Event) (int64, error) {
	var latency any
	if ev.UpstreamLatencyMS != nil {
		latency = *ev.UpstreamLatencyMS
	}
	res, err := db.ExecContext(ctx, `
		INSERT INTO query_events(
			timestamp, client_ip, qname, qtype, transport, action, rcode,
			upstream_latency_ms, matched_source, matched_domain
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		formatTime(ev.Timestamp), ev.ClientIP, ev.QName, ev.QType, ev.Transport, ev.Action, ev.RCode,
		latency, nullString(ev.MatchedSource), nullString(ev.MatchedDomain))
	if err != nil {
		return 0, fmt.Errorf("store: insert event: %w", err)
	}
	return res.LastInsertId()
}

// ListEvents returns a page of events, newest first, and the total matching rows.
func (s *Store) ListEvents(ctx context.Context, f EventFilter) ([]Event, int, error) {
	if f.Limit <= 0 || f.Limit > 100 {
		return nil, 0, fmt.Errorf("store: event limit must be between 1 and 100")
	}
	if f.Offset < 0 {
		return nil, 0, fmt.Errorf("store: event offset must be zero or greater")
	}
	where, args := eventWhere(f)
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM query_events`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	q := eventSelect + where + ` ORDER BY id DESC LIMIT ? OFFSET ?`
	rows, err := s.db.QueryContext(ctx, q, append(append([]any{}, args...), f.Limit, f.Offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		ev, err := scanEvent(rows.Scan)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, ev)
	}
	return out, total, rows.Err()
}

// DeleteEventsBefore removes query events older than cutoff, and counter days before the
// cutoff's day, and returns the number of events deleted.
func (s *Store) DeleteEventsBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM query_events WHERE timestamp < ?`, formatTime(cutoff))
	if err != nil {
		return 0, err
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM query_counts WHERE day < ?`, day(cutoff)); err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func day(t time.Time) string {
	return t.UTC().Format("2006-01-02")
}

func eventWhere(f EventFilter) (string, []any) {
	var clauses []string
	var args []any
	if f.QName != "" {
		clauses = append(clauses, `qname LIKE ? ESCAPE '\'`)
		args = append(args, "%"+escapeLike(f.QName)+"%")
	}
	if f.Action != "" {
		clauses = append(clauses, `action = ?`)
		args = append(args, f.Action)
	}
	if len(clauses) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

func escapeLike(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return s
}

const eventSelect = `
	SELECT id, timestamp, client_ip, qname, qtype, transport, action, rcode,
		upstream_latency_ms, matched_source, matched_domain
	FROM query_events`

func scanEvent(scan func(dest ...any) error) (Event, error) {
	var ev Event
	var ts string
	var latency sql.NullInt64
	var source, domain sql.NullString
	err := scan(&ev.ID, &ts, &ev.ClientIP, &ev.QName, &ev.QType, &ev.Transport, &ev.Action, &ev.RCode,
		&latency, &source, &domain)
	if err != nil {
		return Event{}, err
	}
	ev.Timestamp, err = parseTime(ts)
	if err != nil {
		return Event{}, err
	}
	if latency.Valid {
		v := latency.Int64
		ev.UpstreamLatencyMS = &v
	}
	if source.Valid {
		ev.MatchedSource = source.String
	}
	if domain.Valid {
		ev.MatchedDomain = domain.String
	}
	return ev, nil
}

func nullString(v string) any {
	if v == "" {
		return nil
	}
	return v
}
