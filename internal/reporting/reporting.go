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

// LoadSummary calculates dashboard figures. Totals come from the daily counters starting on
// the day of since, so they include queries the logging mode did not store. The top lists
// and recent queries come from the stored log rows.
func LoadSummary(ctx context.Context, st *store.Store, since time.Time) (Summary, error) {
	var sum Summary
	counts, err := st.CountsSince(ctx, since)
	if err != nil {
		return Summary{}, err
	}
	sum.Total, sum.Allowed, sum.Blocked, sum.Errors = counts.Total(), counts.Allowed, counts.Blocked, counts.Errors
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
