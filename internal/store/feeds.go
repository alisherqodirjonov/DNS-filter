package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// Feed is the status of one configured threat list.
type Feed struct {
	ID            int64
	Name          string
	Source        string
	Format        string
	Status        string
	LastSyncAt    *time.Time
	LastError     string
	DomainsCount  int
	RejectedCount int
}

// FeedDomain is one normalized name loaded from a feed.
type FeedDomain struct {
	FeedName string
	Domain   string
}

// UpsertFeed inserts a feed or refreshes its source and format.
// An existing status and domain set are left in place until a sync finishes.
func (s *Store) UpsertFeed(ctx context.Context, name, source, format string) (Feed, error) {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO feeds(name, source, format, status)
		VALUES (?, ?, ?, 'pending')
		ON CONFLICT(name) DO UPDATE SET source = excluded.source, format = excluded.format`,
		name, source, format)
	if err != nil {
		return Feed{}, fmt.Errorf("store: upsert feed: %w", err)
	}
	return s.FeedByName(ctx, name)
}

// CreateFeed adds a feed managed from the console. A taken name is ErrConflict.
func (s *Store) CreateFeed(ctx context.Context, name, source, format string) (Feed, error) {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO feeds(name, source, format, status) VALUES (?, ?, ?, 'pending')`,
		name, source, format)
	if err != nil {
		if isUnique(err) {
			return Feed{}, fmt.Errorf("%w: feed %s", ErrConflict, name)
		}
		return Feed{}, fmt.Errorf("store: create feed: %w", err)
	}
	return s.FeedByName(ctx, name)
}

// DeleteFeed removes a feed and every domain it loaded.
func (s *Store) DeleteFeed(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM feeds WHERE id = ?`, id)
	if err != nil {
		return err
	}
	return requireRow(res)
}

// FeedByName loads a feed by its unique name.
func (s *Store) FeedByName(ctx context.Context, name string) (Feed, error) {
	row := s.db.QueryRowContext(ctx, feedSelect+` WHERE name = ?`, name)
	return scanFeed(row)
}

// FeedByID loads a feed by primary key.
func (s *Store) FeedByID(ctx context.Context, id int64) (Feed, error) {
	row := s.db.QueryRowContext(ctx, feedSelect+` WHERE id = ?`, id)
	return scanFeed(row)
}

// ListFeeds returns every feed in name order.
func (s *Store) ListFeeds(ctx context.Context) ([]Feed, error) {
	rows, err := s.db.QueryContext(ctx, feedSelect+` ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Feed
	for rows.Next() {
		f, err := scanFeedRows(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// DeleteFeedsNotNamed removes feeds that are no longer in the configuration.
// An empty name list removes every feed.
func (s *Store) DeleteFeedsNotNamed(ctx context.Context, names []string) error {
	if len(names) == 0 {
		_, err := s.db.ExecContext(ctx, `DELETE FROM feeds`)
		return err
	}
	placeholders := make([]string, len(names))
	args := make([]any, len(names))
	for i, name := range names {
		placeholders[i] = "?"
		args[i] = name
	}
	q := `DELETE FROM feeds WHERE name NOT IN (` + strings.Join(placeholders, ",") + `)`
	_, err := s.db.ExecContext(ctx, q, args...)
	return err
}

// ReplaceFeedDomains swaps in a successfully parsed feed inside one transaction.
func (s *Store) ReplaceFeedDomains(ctx context.Context, feedID int64, domains []string, rejected int) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM feed_domains WHERE feed_id = ?`, feedID); err != nil {
		return err
	}
	for _, domain := range domains {
		if _, err := tx.ExecContext(ctx, `INSERT INTO feed_domains(feed_id, domain) VALUES (?, ?)`, feedID, domain); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE feeds
		SET status = 'ok', last_sync_at = ?, last_error = '', domains_count = ?, rejected_count = ?
		WHERE id = ?`, formatTime(time.Now()), len(domains), rejected, feedID); err != nil {
		return err
	}
	return tx.Commit()
}

// MarkFeedError records a failed sync and leaves previously loaded domains in place.
func (s *Store) MarkFeedError(ctx context.Context, feedID int64, message string) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE feeds SET status = 'error', last_error = ? WHERE id = ?`, message, feedID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ListFeedDomains returns every loaded feed name and domain.
func (s *Store) ListFeedDomains(ctx context.Context) ([]FeedDomain, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT f.name, d.domain
		FROM feed_domains d
		JOIN feeds f ON f.id = d.feed_id
		ORDER BY f.name, d.domain`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FeedDomain
	for rows.Next() {
		var fd FeedDomain
		if err := rows.Scan(&fd.FeedName, &fd.Domain); err != nil {
			return nil, err
		}
		out = append(out, fd)
	}
	return out, rows.Err()
}

// CountFeedDomains returns the number of loaded feed names.
func (s *Store) CountFeedDomains(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM feed_domains`).Scan(&n)
	return n, err
}

const feedSelect = `
	SELECT id, name, source, format, status, last_sync_at, last_error, domains_count, rejected_count
	FROM feeds`

func scanFeed(row *sql.Row) (Feed, error) {
	f, err := scanFeedValues(row.Scan)
	if err == sql.ErrNoRows {
		return Feed{}, ErrNotFound
	}
	return f, err
}

func scanFeedRows(rows *sql.Rows) (Feed, error) {
	return scanFeedValues(rows.Scan)
}

func scanFeedValues(scan func(dest ...any) error) (Feed, error) {
	var f Feed
	var synced sql.NullString
	err := scan(&f.ID, &f.Name, &f.Source, &f.Format, &f.Status, &synced, &f.LastError, &f.DomainsCount, &f.RejectedCount)
	if err != nil {
		return Feed{}, err
	}
	if synced.Valid {
		t, err := parseTime(synced.String)
		if err != nil {
			return Feed{}, err
		}
		f.LastSyncAt = &t
	}
	return f, nil
}
