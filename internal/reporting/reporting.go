// Package reporting builds the dashboard figures from SQLite.
package reporting

import (
	"context"
	"database/sql"
	"math"
	"time"

	"dnsfilter/internal/store"
)

// Summary is the set of figures shown on the dashboard.
type Summary struct {
	Total             int
	Allowed           int
	Blocked           int
	Errors            int
	BlockRatio        float64
	FeedDomains       int
	TopBlockedDomains []DomainCount
	TopBlockedClients []ClientCount
	Feeds             []store.Feed
	Recent            []store.Event
}

// DomainCount is one row in the top blocked names list.
type DomainCount struct {
	QName string
	Count int
}

// ClientCount is one row in the top blocked clients list.
type ClientCount struct {
	ClientIP string
	Count    int
}

// LoadSummary calculates dashboard figures from the events still in SQLite.
func LoadSummary(ctx context.Context, st *store.Store) (Summary, error) {
	var sum Summary
	err := st.DB().QueryRowContext(ctx, `
		SELECT
			COUNT(*),
			COALESCE(SUM(CASE WHEN action = 'ALLOWED' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN action = 'BLOCKED' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN action = 'ERROR' THEN 1 ELSE 0 END), 0)
		FROM query_events`).Scan(&sum.Total, &sum.Allowed, &sum.Blocked, &sum.Errors)
	if err != nil {
		return Summary{}, err
	}
	if sum.Total > 0 {
		sum.BlockRatio = math.Round((float64(sum.Blocked)/float64(sum.Total))*1000) / 10
	}
	sum.FeedDomains, err = st.CountFeedDomains(ctx)
	if err != nil {
		return Summary{}, err
	}
	sum.Feeds, err = st.ListFeeds(ctx)
	if err != nil {
		return Summary{}, err
	}
	sum.TopBlockedDomains, err = topDomains(ctx, st.DB())
	if err != nil {
		return Summary{}, err
	}
	sum.TopBlockedClients, err = topClients(ctx, st.DB())
	if err != nil {
		return Summary{}, err
	}
	sum.Recent, _, err = st.ListEvents(ctx, store.EventFilter{Limit: 8})
	if err != nil {
		return Summary{}, err
	}
	if sum.Recent == nil {
		sum.Recent = []store.Event{}
	}
	return sum, nil
}

func topDomains(ctx context.Context, db *sql.DB) ([]DomainCount, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT qname, COUNT(*)
		FROM query_events
		WHERE action = 'BLOCKED'
		GROUP BY qname
		ORDER BY COUNT(*) DESC, qname
		LIMIT 5`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DomainCount
	for rows.Next() {
		var row DomainCount
		if err := rows.Scan(&row.QName, &row.Count); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func topClients(ctx context.Context, db *sql.DB) ([]ClientCount, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT client_ip, COUNT(*)
		FROM query_events
		WHERE action = 'BLOCKED'
		GROUP BY client_ip
		ORDER BY COUNT(*) DESC, client_ip
		LIMIT 5`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ClientCount
	for rows.Next() {
		var row ClientCount
		if err := rows.Scan(&row.ClientIP, &row.Count); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// LastFeedSync is the newest successful or attempted sync time, if any feed has one.
func LastFeedSync(feeds []store.Feed) *time.Time {
	var latest *time.Time
	for i := range feeds {
		if feeds[i].LastSyncAt == nil {
			continue
		}
		if latest == nil || feeds[i].LastSyncAt.After(*latest) {
			t := *feeds[i].LastSyncAt
			latest = &t
		}
	}
	return latest
}
