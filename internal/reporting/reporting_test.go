package reporting_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"dnsfilter/internal/reporting"
	"dnsfilter/internal/store"
)

func TestSummaryCountsRatioAndTops(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "dns.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	latency := int64(4)
	insert(t, st, store.Event{ClientIP: "192.0.2.10", QName: "example.com", QType: "A", Transport: "udp", Action: "ALLOWED", RCode: "NOERROR", UpstreamLatencyMS: &latency})
	insert(t, st, store.Event{ClientIP: "192.0.2.10", QName: "example.com", QType: "AAAA", Transport: "udp", Action: "ALLOWED", RCode: "NOERROR", UpstreamLatencyMS: &latency})
	insert(t, st, store.Event{ClientIP: "192.0.2.10", QName: "malware-demo.test", QType: "A", Transport: "udp", Action: "BLOCKED", RCode: "REFUSED", MatchedSource: "demo-local", MatchedDomain: "malware-demo.test"})
	insert(t, st, store.Event{ClientIP: "192.0.2.11", QName: "malware-demo.test", QType: "A", Transport: "tcp", Action: "BLOCKED", RCode: "REFUSED", MatchedSource: "demo-local", MatchedDomain: "malware-demo.test"})
	insert(t, st, store.Event{ClientIP: "192.0.2.11", QName: "phishing-demo.test", QType: "A", Transport: "udp", Action: "BLOCKED", RCode: "REFUSED", MatchedSource: "demo-local", MatchedDomain: "phishing-demo.test"})
	insert(t, st, store.Event{ClientIP: "192.0.2.12", QName: "example.com", QType: "A", Transport: "udp", Action: "ERROR", RCode: "SERVFAIL"})

	if _, err := st.UpsertFeed(ctx, "demo-local", "/tmp/list.txt", "domains"); err != nil {
		t.Fatal(err)
	}
	feed, err := st.FeedByName(ctx, "demo-local")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.ReplaceFeedDomains(ctx, feed.ID, []string{"malware-demo.test", "phishing-demo.test"}, 0); err != nil {
		t.Fatal(err)
	}

	sum, err := reporting.LoadSummary(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Total != 6 || sum.Allowed != 2 || sum.Blocked != 3 || sum.Errors != 1 {
		t.Fatalf("counts = %+v", sum)
	}
	if sum.BlockRatio != 50 {
		t.Fatalf("ratio = %v", sum.BlockRatio)
	}
	if sum.FeedDomains != 2 || len(sum.Feeds) != 1 || sum.Feeds[0].Status != "ok" {
		t.Fatalf("feeds = %+v domains=%d", sum.Feeds, sum.FeedDomains)
	}
	if len(sum.TopBlockedDomains) != 2 || sum.TopBlockedDomains[0].QName != "malware-demo.test" || sum.TopBlockedDomains[0].Count != 2 {
		t.Fatalf("domains = %+v", sum.TopBlockedDomains)
	}
	if len(sum.TopBlockedClients) != 2 || sum.TopBlockedClients[0].ClientIP != "192.0.2.10" && sum.TopBlockedClients[0].ClientIP != "192.0.2.11" {
		t.Fatalf("clients = %+v", sum.TopBlockedClients)
	}
	if sum.TopBlockedClients[0].Count != 2 {
		t.Fatalf("top client = %+v", sum.TopBlockedClients[0])
	}
	if len(sum.Recent) != 6 {
		t.Fatalf("recent = %d", len(sum.Recent))
	}
	if reporting.LastFeedSync(sum.Feeds) == nil {
		t.Fatal("expected a feed sync time")
	}

	page, total, err := st.ListEvents(ctx, store.EventFilter{QName: "malware-demo.test", Action: "BLOCKED", Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(page) != 1 {
		t.Fatalf("page total=%d len=%d", total, len(page))
	}
}

func insert(t *testing.T, st *store.Store, ev store.Event) {
	t.Helper()
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	if _, err := st.InsertEvent(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
}
