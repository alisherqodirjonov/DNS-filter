package auth_test

import (
	"bytes"
	"context"
	"errors"
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

	err := svc.Bootstrap(ctx, "admin", "", "", "")
	if err == nil || !strings.Contains(err.Error(), "DNSFILTER_BOOTSTRAP_ADMIN_PASSWORD") {
		t.Fatalf("half-set admin error = %v", err)
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

func TestDefaultAdminMustChangePassword(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	var logs bytes.Buffer
	svc := auth.New(st, slog.New(slog.NewTextHandler(&logs, nil)))
	if err := svc.Bootstrap(ctx, "", "", "", ""); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "level=WARN") || !strings.Contains(logs.String(), "default administrator") {
		t.Fatalf("missing default account warning: %s", logs.String())
	}
	first, err := svc.Login(ctx, auth.DefaultAdminUser, auth.DefaultAdminPassword, "192.0.2.20")
	if err != nil {
		t.Fatal(err)
	}
	if !first.MustChangePassword || first.Role != auth.RoleAdmin {
		t.Fatalf("default login = %+v", first)
	}
	second, err := svc.Login(ctx, auth.DefaultAdminUser, auth.DefaultAdminPassword, "192.0.2.21")
	if err != nil {
		t.Fatal(err)
	}
	sess, err := svc.Session(ctx, first.Token)
	if err != nil || !sess.MustChangePassword {
		t.Fatalf("session = %+v err=%v", sess, err)
	}

	if err := svc.ChangePassword(ctx, sess, "not-it", "a-new-lab-pass"); err != auth.ErrWrongPassword {
		t.Fatalf("wrong current error = %v", err)
	}
	var input *auth.InputError
	if err := svc.ChangePassword(ctx, sess, auth.DefaultAdminPassword, "short"); !errors.As(err, &input) {
		t.Fatalf("short password error = %v", err)
	}
	if err := svc.ChangePassword(ctx, sess, auth.DefaultAdminPassword, "a-new-lab-pass"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(logs.String(), "a-new-lab-pass") {
		t.Fatal("new password was logged")
	}
	sess, err = svc.Session(ctx, first.Token)
	if err != nil || sess.MustChangePassword {
		t.Fatalf("session after change = %+v err=%v", sess, err)
	}
	if _, err := svc.Session(ctx, second.Token); err != auth.ErrUnauthenticated {
		t.Fatalf("other session after change = %v", err)
	}
	if _, err := svc.Login(ctx, auth.DefaultAdminUser, auth.DefaultAdminPassword, "192.0.2.22"); err != auth.ErrCredentials {
		t.Fatalf("old password error = %v", err)
	}
	if _, err := svc.Login(ctx, auth.DefaultAdminUser, "a-new-lab-pass", "192.0.2.22"); err != nil {
		t.Fatal(err)
	}
}

func TestAdminManagesAccounts(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	svc := auth.New(st, nil)
	if err := svc.Bootstrap(ctx, "ada", "lab-admin-pass", "", ""); err != nil {
		t.Fatal(err)
	}
	login, err := svc.Login(ctx, "ada", "lab-admin-pass", "192.0.2.30")
	if err != nil || login.MustChangePassword {
		t.Fatalf("env admin login = %+v err=%v", login, err)
	}
	actor, err := svc.Session(ctx, login.Token)
	if err != nil {
		t.Fatal(err)
	}

	var input *auth.InputError
	for _, c := range [][3]string{
		{"bad name!", "temporary-pass", auth.RoleAnalyst},
		{"bea", "temporary-pass", "owner"},
		{"bea", "short", auth.RoleAnalyst},
	} {
		if _, err := svc.CreateAccount(ctx, actor, c[0], c[1], c[2]); !errors.As(err, &input) {
			t.Fatalf("CreateAccount(%v) error = %v", c, err)
		}
	}
	bea, err := svc.CreateAccount(ctx, actor, "bea", "temporary-pass", auth.RoleAnalyst)
	if err != nil || !bea.MustChangePassword {
		t.Fatalf("created = %+v err=%v", bea, err)
	}
	if _, err := svc.CreateAccount(ctx, actor, "bea", "temporary-pass", auth.RoleAnalyst); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate error = %v", err)
	}
	beaLogin, err := svc.Login(ctx, "bea", "temporary-pass", "192.0.2.31")
	if err != nil || !beaLogin.MustChangePassword {
		t.Fatalf("bea login = %+v err=%v", beaLogin, err)
	}

	if _, err := svc.ResetPassword(ctx, actor, actor.UserID, "another-temp-pass"); err != auth.ErrSelf {
		t.Fatalf("self reset error = %v", err)
	}
	if _, err := svc.ResetPassword(ctx, actor, bea.ID, "another-temp-pass"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Session(ctx, beaLogin.Token); err != auth.ErrUnauthenticated {
		t.Fatalf("bea session after reset = %v", err)
	}
	if _, err := svc.Login(ctx, "bea", "another-temp-pass", "192.0.2.31"); err != nil {
		t.Fatal(err)
	}

	if _, err := svc.DeleteAccount(ctx, actor, actor.UserID); err != auth.ErrSelf {
		t.Fatalf("self delete error = %v", err)
	}
	if _, err := svc.DeleteAccount(ctx, actor, bea.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.DeleteAccount(ctx, actor, bea.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("second delete error = %v", err)
	}

	// A second admin cannot remove the only other admin once it is the last one.
	cy, err := svc.CreateAccount(ctx, actor, "cy", "temporary-pass", auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteUser(ctx, actor.UserID); err != nil {
		t.Fatal(err)
	}
	ghost := store.Session{UserID: 999, Username: "ghost", Role: auth.RoleAdmin}
	if _, err := svc.DeleteAccount(ctx, ghost, cy.ID); err != auth.ErrLastAdmin {
		t.Fatalf("last admin error = %v", err)
	}

	audit, _, err := st.ListAudit(ctx, 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, ev := range audit {
		seen[ev.Action] = true
	}
	for _, action := range []string{"user_create", "password_reset", "user_delete"} {
		if !seen[action] {
			t.Errorf("missing audit action %s", action)
		}
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
