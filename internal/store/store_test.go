package store_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"dnsfilter/internal/store"
)

func TestOpenMigratesAndSurvivesReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "data", "dnsfilter.db")
	st := openStore(t, path)
	names := tableNames(t, st)
	want := []string{
		"audit_events", "feed_domains", "feeds", "query_events",
		"rules", "schema_migrations", "sessions", "users",
	}
	for _, name := range want {
		if !names[name] {
			t.Errorf("missing table %s", name)
		}
	}

	var fk, busy int
	if err := st.DB().QueryRow(`PRAGMA foreign_keys`).Scan(&fk); err != nil {
		t.Fatal(err)
	}
	if fk != 1 {
		t.Fatalf("foreign_keys = %d", fk)
	}
	if err := st.DB().QueryRow(`PRAGMA busy_timeout`).Scan(&busy); err != nil {
		t.Fatal(err)
	}
	if busy < 5000 {
		t.Fatalf("busy_timeout = %d", busy)
	}

	if _, err := st.CreateUser(ctx, "admin", "hash", "admin"); err != nil {
		t.Fatal(err)
	}
	st.Close()

	st = openStore(t, path)
	n, err := st.UserCount(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("users = %d", n)
	}
}

func TestForeignKeyAndUniqueRule(t *testing.T) {
	ctx := context.Background()
	st := openStore(t, filepath.Join(t.TempDir(), "dnsfilter.db"))

	_, err := st.DB().Exec(`INSERT INTO feed_domains(feed_id, domain) VALUES (99, 'example.test')`)
	if err == nil {
		t.Fatal("expected foreign key failure")
	}

	if _, err := st.CreateUser(ctx, "ada", "hash", "guest"); err == nil {
		t.Fatal("expected role check to fail")
	}

	if _, err := st.CreateRule(ctx, "example.test", "deny", "exact", "lab", "ada"); err != nil {
		t.Fatal(err)
	}
	_, err = st.CreateRule(ctx, "example.test", "deny", "exact", "again", "ada")
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate rule error = %v", err)
	}
}

func TestSessionsRulesFeedsAndEvents(t *testing.T) {
	ctx := context.Background()
	st := openStore(t, filepath.Join(t.TempDir(), "dnsfilter.db"))

	user, err := st.CreateUser(ctx, "ada", "hash-not-a-password", "admin")
	if err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(time.Hour).UTC()
	if err := st.CreateSession(ctx, "abc123hash", user.ID, "csrf-value", exp); err != nil {
		t.Fatal(err)
	}
	sess, err := st.SessionByTokenHash(ctx, "abc123hash", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if sess.Username != "ada" || sess.Role != "admin" || sess.CSRFToken != "csrf-value" {
		t.Fatalf("session = %+v", sess)
	}
	if _, err := st.SessionByTokenHash(ctx, "abc123hash", exp.Add(time.Second)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired session error = %v", err)
	}

	rule, err := st.CreateRule(ctx, "example.test", "allow", "suffix", "exception", "ada")
	if err != nil {
		t.Fatal(err)
	}
	rules, err := st.ListRules(ctx)
	if err != nil || len(rules) != 1 || rules[0].ID != rule.ID {
		t.Fatalf("rules = %+v err=%v", rules, err)
	}
	if err := st.DeleteRule(ctx, rule.ID); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteRule(ctx, rule.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("second delete = %v", err)
	}

	feed, err := st.UpsertFeed(ctx, "demo-local", "/tmp/list.txt", "domains")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.ReplaceFeedDomains(ctx, feed.ID, []string{"malware-demo.test", "phishing-demo.test"}, 1); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkFeedError(ctx, feed.ID, "read failed"); err != nil {
		t.Fatal(err)
	}
	domains, err := st.ListFeedDomains(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(domains) != 2 {
		t.Fatalf("domains after failed mark = %+v", domains)
	}
	got, err := st.FeedByID(ctx, feed.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "error" || got.DomainsCount != 2 || got.LastError != "read failed" {
		t.Fatalf("feed = %+v", got)
	}

	latency := int64(12)
	old := time.Now().Add(-48 * time.Hour).UTC()
	if _, err := st.InsertEvent(ctx, store.Event{
		Timestamp: old, ClientIP: "192.0.2.10", QName: "old.example", QType: "A",
		Transport: "udp", Action: "ALLOWED", RCode: "NOERROR", UpstreamLatencyMS: &latency,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertEvent(ctx, store.Event{
		ClientIP: "192.0.2.10", QName: "malware-demo.test", QType: "A",
		Transport: "tcp", Action: "BLOCKED", RCode: "REFUSED",
		MatchedSource: "demo-local", MatchedDomain: "malware-demo.test",
	}); err != nil {
		t.Fatal(err)
	}
	events, total, err := st.ListEvents(ctx, store.EventFilter{QName: "malware", Action: "BLOCKED", Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(events) != 1 || events[0].MatchedSource != "demo-local" || events[0].UpstreamLatencyMS != nil {
		t.Fatalf("events total=%d %+v", total, events)
	}
	n, err := st.DeleteEventsBefore(ctx, time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("deleted = %d", n)
	}

	if err := st.InsertAudit(ctx, store.AuditEvent{
		Username: "ada", Action: "login_success", ObjectType: "session", Result: "success",
	}); err != nil {
		t.Fatal(err)
	}
	audit, total, err := st.ListAudit(ctx, 50, 0)
	if err != nil || total != 1 || audit[0].Action != "login_success" {
		t.Fatalf("audit total=%d %+v err=%v", total, audit, err)
	}

	var stored string
	if err := st.DB().QueryRow(`SELECT token_hash FROM sessions`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != "abc123hash" {
		t.Fatalf("stored token hash = %s", stored)
	}
}

func openStore(t *testing.T, path string) *store.Store {
	t.Helper()
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func tableNames(t *testing.T, st *store.Store) map[string]bool {
	t.Helper()
	rows, err := st.DB().Query(`SELECT name FROM sqlite_master WHERE type = 'table'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	names := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		names[name] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return names
}

// Keep sql imported if a future assertion needs driver errors directly.
var _ = sql.ErrNoRows
