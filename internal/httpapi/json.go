package httpapi

import (
	"time"

	"dnsfilter/internal/reporting"
	"dnsfilter/internal/store"
)

type eventResponse struct {
	ID                int64     `json:"id"`
	Timestamp         time.Time `json:"timestamp"`
	ClientIP          string    `json:"client_ip"`
	QName             string    `json:"qname"`
	QType             string    `json:"qtype"`
	Transport         string    `json:"transport"`
	Action            string    `json:"action"`
	RCode             string    `json:"rcode"`
	UpstreamLatencyMS *int64    `json:"upstream_latency_ms"`
	MatchedSource     *string   `json:"matched_source"`
	MatchedDomain     *string   `json:"matched_domain"`
}

type ruleResponse struct {
	ID          int64     `json:"id"`
	Domain      string    `json:"domain"`
	RuleType    string    `json:"rule_type"`
	MatchType   string    `json:"match_type"`
	Description string    `json:"description"`
	CreatedBy   string    `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
}

type feedResponse struct {
	ID            int64      `json:"id"`
	Name          string     `json:"name"`
	Source        string     `json:"source"`
	Format        string     `json:"format"`
	Status        string     `json:"status"`
	LastSyncAt    *time.Time `json:"last_sync_at"`
	LastError     string     `json:"last_error"`
	DomainsCount  int        `json:"domains_count"`
	RejectedCount int        `json:"rejected_count"`
}

type auditResponse struct {
	ID         int64     `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	Username   string    `json:"username"`
	Action     string    `json:"action"`
	ObjectType string    `json:"object_type"`
	ObjectID   string    `json:"object_id"`
	Result     string    `json:"result"`
}

type domainCount struct {
	QName string `json:"qname"`
	Count int    `json:"count"`
}

type clientCount struct {
	ClientIP string `json:"client_ip"`
	Count    int    `json:"count"`
}

type summaryJSON struct {
	Total             int             `json:"total"`
	Allowed           int             `json:"allowed"`
	Blocked           int             `json:"blocked"`
	Errors            int             `json:"errors"`
	BlockRatio        float64         `json:"block_ratio"`
	FeedDomains       int             `json:"feed_domains"`
	TopBlockedDomains []domainCount   `json:"top_blocked_domains"`
	TopBlockedClients []clientCount   `json:"top_blocked_clients"`
	Feeds             []feedResponse  `json:"feeds"`
	Recent            []eventResponse `json:"recent_events"`
}

func toEvent(ev store.Event) eventResponse {
	return eventResponse{
		ID: ev.ID, Timestamp: ev.Timestamp, ClientIP: ev.ClientIP, QName: ev.QName,
		QType: ev.QType, Transport: ev.Transport, Action: ev.Action, RCode: ev.RCode,
		UpstreamLatencyMS: ev.UpstreamLatencyMS,
		MatchedSource:     nullString(ev.MatchedSource),
		MatchedDomain:     nullString(ev.MatchedDomain),
	}
}

func toRule(rule store.Rule) ruleResponse {
	return ruleResponse{
		ID: rule.ID, Domain: rule.Domain, RuleType: rule.RuleType, MatchType: rule.MatchType,
		Description: rule.Description, CreatedBy: rule.CreatedBy, CreatedAt: rule.CreatedAt,
	}
}

func toFeed(feed store.Feed) feedResponse {
	return feedResponse{
		ID: feed.ID, Name: feed.Name, Source: feed.Source, Format: feed.Format, Status: feed.Status,
		LastSyncAt: feed.LastSyncAt, LastError: feed.LastError, DomainsCount: feed.DomainsCount,
		RejectedCount: feed.RejectedCount,
	}
}

func toFeeds(list []store.Feed) []feedResponse {
	out := make([]feedResponse, 0, len(list))
	for _, feed := range list {
		out = append(out, toFeed(feed))
	}
	return out
}

func feedOrNil(feed store.Feed, err error) any {
	if err != nil {
		return nil
	}
	return toFeed(feed)
}

func summaryResponse(sum reporting.Summary) summaryJSON {
	domains := make([]domainCount, 0, len(sum.TopBlockedDomains))
	for _, row := range sum.TopBlockedDomains {
		domains = append(domains, domainCount{QName: row.QName, Count: row.Count})
	}
	clients := make([]clientCount, 0, len(sum.TopBlockedClients))
	for _, row := range sum.TopBlockedClients {
		clients = append(clients, clientCount{ClientIP: row.ClientIP, Count: row.Count})
	}
	recent := make([]eventResponse, 0, len(sum.Recent))
	for _, ev := range sum.Recent {
		recent = append(recent, toEvent(ev))
	}
	return summaryJSON{
		Total: sum.Total, Allowed: sum.Allowed, Blocked: sum.Blocked, Errors: sum.Errors,
		BlockRatio: sum.BlockRatio, FeedDomains: sum.FeedDomains,
		TopBlockedDomains: domains, TopBlockedClients: clients,
		Feeds: toFeeds(sum.Feeds), Recent: recent,
	}
}

func nullString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}
