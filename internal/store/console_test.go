package store_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"dnsfilter/internal/store"
	"dnsfilter/migrations"
)

func TestUpgradeFromFirstSchemaKeepsDataAndBackfillsCounts(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "old.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range strings.Split(migrations.All[0].SQL, ";") {
		if strings.TrimSpace(stmt) == "" {
			continue
		}
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	mustExec(t, db, `INSERT INTO schema_migrations(version, applied_at) VALUES (1, '2026-11-01T00:00:00Z')`)
	mustExec(t, db, `INSERT INTO users(username, password_hash, role, created_at) VALUES ('ada', 'h', 'admin', '2026-11-01T00:00:00Z')`)
	for _, row := range []string{
		`('2026-11-16T10:00:00Z', 'ALLOWED')`, `('2026-11-16T11:00:00Z', 'BLOCKED')`,
		`('2026-11-17T09:00:00Z', 'BLOCKED')`, `('2026-11-17T09:30:00Z', 'ERROR')`,
	} {
		mustExec(t, db, `INSERT INTO query_events(timestamp, action, client_ip, qname, qtype, transport, rcode)
			VALUES `+strings.Replace(row, ")", ", '192.0.2.1', 'x.test', 'A', 'udp', 'NOERROR')", 1))
	}
	db.Close()

	st := openStore(t, path)
	user, err := st.UserByUsername(ctx, "ada")
	if err != nil || user.MustChangePassword {
		t.Fatalf("user after upgrade = %+v err=%v", user, err)
	}
	counts, err := st.CountsSince(ctx, time.Date(2026, 11, 16, 23, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if counts != (store.ActionCounts{Allowed: 1, Blocked: 2, Errors: 1}) {
		t.Fatalf("backfilled counts = %+v", counts)
	}
	counts, err = st.CountsSince(ctx, time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC))
	if err != nil || counts.Total() != 2 {
		t.Fatalf("counts from 17th = %+v err=%v", counts, err)
	}
	var versions int
	if err := st.DB().QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&versions); err != nil || versions != len(migrations.All) {
		t.Fatalf("versions = %d err=%v", versions, err)
	}
}

func TestRecordQueryCountsEveryQueryAndKeepsRowsOnRequest(t *testing.T) {
	ctx := context.Background()
	st := openStore(t, filepath.Join(t.TempDir(), "dnsfilter.db"))
	now := time.Now().UTC()
	ev := store.Event{Timestamp: now, ClientIP: "192.0.2.9", QName: "a.test", QType: "A", Transport: "udp", Action: "ALLOWED", RCode: "NOERROR"}
	if err := st.RecordQuery(ctx, ev, false); err != nil {
		t.Fatal(err)
	}
	ev.Action, ev.RCode = "BLOCKED", "REFUSED"
	if err := st.RecordQuery(ctx, ev, true); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordQuery(ctx, ev, true); err != nil {
		t.Fatal(err)
	}
	counts, err := st.CountsSince(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if counts != (store.ActionCounts{Allowed: 1, Blocked: 2}) {
		t.Fatalf("counts = %+v", counts)
	}
	_, total, err := st.ListEvents(ctx, store.EventFilter{Limit: 10})
	if err != nil || total != 2 {
		t.Fatalf("stored rows = %d err=%v", total, err)
	}

	old := now.AddDate(0, 0, -10)
	if err := st.RecordQuery(ctx, store.Event{Timestamp: old, ClientIP: "192.0.2.9", QName: "b.test", QType: "A", Transport: "udp", Action: "ERROR", RCode: "SERVFAIL"}, true); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DeleteEventsBefore(ctx, now.AddDate(0, 0, -7)); err != nil {
		t.Fatal(err)
	}
	counts, err = st.CountsSince(ctx, old)
	if err != nil || counts.Errors != 0 || counts.Total() != 3 {
		t.Fatalf("counts after retention = %+v err=%v", counts, err)
	}
}

func TestAccountsSettingsAndConsoleFeeds(t *testing.T) {
	ctx := context.Background()
	st := openStore(t, filepath.Join(t.TempDir(), "dnsfilter.db"))

	admin, err := st.CreateUser(ctx, "admin", "h1", "admin", true)
	if err != nil || !admin.MustChangePassword {
		t.Fatalf("admin = %+v err=%v", admin, err)
	}
	if _, err := st.CreateUser(ctx, "admin", "h2", "analyst", false); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate user error = %v", err)
	}
	analyst, err := st.CreateUser(ctx, "bea", "h3", "analyst", false)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := st.AdminCount(ctx); err != nil || n != 1 {
		t.Fatalf("admins = %d err=%v", n, err)
	}
	users, err := st.ListUsers(ctx)
	if err != nil || len(users) != 2 || users[0].Username != "admin" {
		t.Fatalf("users = %+v err=%v", users, err)
	}

	exp := time.Now().Add(time.Hour)
	for _, hash := range []string{"keep", "drop"} {
		if err := st.CreateSession(ctx, hash, admin.ID, "csrf", exp); err != nil {
			t.Fatal(err)
		}
	}
	sess, err := st.SessionByTokenHash(ctx, "keep", time.Now())
	if err != nil || !sess.MustChangePassword || sess.TokenHash != "keep" {
		t.Fatalf("session = %+v err=%v", sess, err)
	}
	if err := st.SetPassword(ctx, admin.ID, "h4", false); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteUserSessions(ctx, admin.ID, "keep"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SessionByTokenHash(ctx, "drop", time.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("other session error = %v", err)
	}
	sess, err = st.SessionByTokenHash(ctx, "keep", time.Now())
	if err != nil || sess.MustChangePassword {
		t.Fatalf("kept session = %+v err=%v", sess, err)
	}
	if err := st.SetPassword(ctx, 999, "h", false); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing user error = %v", err)
	}
	if err := st.CreateSession(ctx, "bea-session", analyst.ID, "csrf", exp); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteUser(ctx, analyst.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SessionByTokenHash(ctx, "bea-session", time.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted user's session error = %v", err)
	}

	if err := st.SaveSettings(ctx, map[string]string{"blocked_rcode": "NXDOMAIN", "log_mode": "blocked"}, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveSettings(ctx, map[string]string{"log_mode": "none"}, "admin"); err != nil {
		t.Fatal(err)
	}
	settings, err := st.ListSettings(ctx)
	if err != nil || len(settings) != 2 || settings["log_mode"].Value != "none" || settings["blocked_rcode"].UpdatedBy != "admin" {
		t.Fatalf("settings = %+v err=%v", settings, err)
	}

	feed, err := st.CreateFeed(ctx, "lab-list", "/srv/lists/lab.txt", "domains")
	if err != nil || feed.Status != "pending" {
		t.Fatalf("feed = %+v err=%v", feed, err)
	}
	if _, err := st.CreateFeed(ctx, "lab-list", "/other", "domains"); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate feed error = %v", err)
	}
	if err := st.ReplaceFeedDomains(ctx, feed.ID, []string{"x.test"}, 0); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteFeed(ctx, feed.ID); err != nil {
		t.Fatal(err)
	}
	if n, err := st.CountFeedDomains(ctx); err != nil || n != 0 {
		t.Fatalf("feed domains after delete = %d err=%v", n, err)
	}
	if err := st.DeleteFeed(ctx, feed.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("second feed delete = %v", err)
	}
}

func mustExec(t *testing.T, db *sql.DB, q string) {
	t.Helper()
	if _, err := db.Exec(q); err != nil {
		t.Fatalf("%v\n%s", err, q)
	}
}
