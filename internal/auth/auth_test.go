package auth_test

import (
	"bytes"
	"context"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dnsfilter/internal/auth"
	"dnsfilter/internal/store"
)

func TestBootstrapAndLogin(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	var logs bytes.Buffer
	svc := auth.New(st, slog.New(slog.NewTextHandler(&logs, nil)))

	err := svc.Bootstrap(ctx, "", "", "", "")
	if err == nil || !strings.Contains(err.Error(), "DNSFILTER_BOOTSTRAP_ADMIN_USER") {
		t.Fatalf("empty bootstrap error = %v", err)
	}
	if err := svc.Bootstrap(ctx, "admin", "short", "", ""); err == nil {
		t.Fatal("expected a short password to be rejected")
	}
	if err := svc.Bootstrap(ctx, "admin", "lab-admin-pass", "analyst", ""); err == nil {
		t.Fatal("expected a half-set analyst to be rejected")
	}
	if err := svc.Bootstrap(ctx, "admin", "lab-admin-pass", "analyst", "lab-analyst-pass"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(logs.String(), "lab-admin-pass") || strings.Contains(logs.String(), "lab-analyst-pass") {
		t.Fatalf("password leaked into log: %s", logs.String())
	}
	if err := svc.Bootstrap(ctx, "other", "another-password", "", ""); err != nil {
		t.Fatal(err)
	}
	count, err := st.UserCount(ctx)
	if err != nil || count != 2 {
		t.Fatalf("users = %d err=%v", count, err)
	}

	if _, err := svc.Login(ctx, "admin", "wrong-password", "192.0.2.5"); err != auth.ErrCredentials {
		t.Fatalf("bad password error = %v", err)
	}
	if strings.Contains(logs.String(), "wrong-password") {
		t.Fatal("failed password was logged")
	}
	result, err := svc.Login(ctx, "admin", "lab-admin-pass", "192.0.2.5")
	if err != nil {
		t.Fatal(err)
	}
	if result.Role != auth.RoleAdmin || result.Token == "" || result.CSRF == "" {
		t.Fatalf("login = %+v", result)
	}
	stored := auth.HashToken(result.Token)
	if stored == result.Token {
		t.Fatal("session token was stored in the clear")
	}
	var hash string
	if err := st.DB().QueryRow(`SELECT token_hash FROM sessions`).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if hash != stored || strings.Contains(hash, result.Token) {
		t.Fatal("database does not hold only the token hash")
	}
	sess, err := svc.Session(ctx, result.Token)
	if err != nil || sess.Username != "admin" || sess.CSRFToken != result.CSRF {
		t.Fatalf("session = %+v err=%v", sess, err)
	}
	if err := svc.Logout(ctx, result.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Session(ctx, result.Token); err != auth.ErrUnauthenticated {
		t.Fatalf("session after logout = %v", err)
	}
}

func TestExpiredSessionAndRateLimit(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	svc := auth.New(st, nil)
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	svc.Now = func() time.Time { return now }
	if err := svc.Bootstrap(ctx, "admin", "lab-admin-pass", "", ""); err != nil {
		t.Fatal(err)
	}
	result, err := svc.Login(ctx, "admin", "lab-admin-pass", "192.0.2.8")
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(auth.SessionTTL + time.Minute)
	if _, err := svc.Session(ctx, result.Token); err != auth.ErrUnauthenticated {
		t.Fatalf("expired session error = %v", err)
	}

	for i := 0; i < 5; i++ {
		if _, err := svc.Login(ctx, "admin", "wrong-password", "192.0.2.9"); err != auth.ErrCredentials {
			t.Fatalf("attempt %d error = %v", i, err)
		}
	}
	if _, err := svc.Login(ctx, "admin", "lab-admin-pass", "192.0.2.9"); err != auth.ErrRateLimited {
		t.Fatalf("rate limit error = %v", err)
	}
	if _, err := svc.Login(ctx, "admin", "lab-admin-pass", "192.0.2.10"); err != nil {
		t.Fatalf("other client was limited: %v", err)
	}
}

func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "dns.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}
