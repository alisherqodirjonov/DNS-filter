package settings_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"dnsfilter/internal/settings"
	"dnsfilter/internal/store"
)

func defaults() settings.Values {
	return settings.Values{
		BlockedRCode: "REFUSED", Upstream: "1.1.1.1:53", UpstreamTimeout: 2 * time.Second,
		Retention: 7 * 24 * time.Hour, SyncInterval: 6 * time.Hour,
		LogMode: settings.LogAll, FeedsSource: settings.FeedsFromFile,
	}
}

func TestUpdateSavesOnlyChangesAndSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "dns.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := settings.Load(ctx, st, defaults())
	if err != nil {
		t.Fatal(err)
	}
	if svc.Current() != defaults() {
		t.Fatalf("fresh values = %+v", svc.Current())
	}
	changed := svc.Changed()

	rcode, upstream, mode := "nxdomain", "192.0.2.53:5300", "blocked"
	same, timeout := 6, 5
	keys, err := svc.Update(ctx, settings.Patch{
		BlockedRCode: &rcode, Upstream: &upstream, LogMode: &mode,
		SyncIntervalHours: &same, UpstreamTimeoutSeconds: &timeout,
	}, "ada")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{settings.KeyBlockedRCode, settings.KeyUpstream, settings.KeyUpstreamTimeout, settings.KeyLogMode}
	if len(keys) != len(want) {
		t.Fatalf("changed keys = %v", keys)
	}
	for i := range want {
		if keys[i] != want[i] {
			t.Fatalf("changed keys = %v", keys)
		}
	}
	select {
	case <-changed:
	default:
		t.Fatal("change channel was not closed")
	}
	got := svc.Current()
	if got.BlockedRCode != "NXDOMAIN" || got.Upstream != upstream || got.UpstreamTimeout != 5*time.Second || got.LogMode != settings.LogBlocked {
		t.Fatalf("values = %+v", got)
	}
	if _, ok := svc.Saved()[settings.KeySyncInterval]; ok {
		t.Fatal("unchanged sync interval was saved")
	}
	if svc.Saved()[settings.KeyBlockedRCode].UpdatedBy != "ada" {
		t.Fatalf("saved = %+v", svc.Saved())
	}
	if keys, err := svc.Update(ctx, settings.Patch{BlockedRCode: &rcode}, "ada"); err != nil || len(keys) != 0 {
		t.Fatalf("repeat update keys=%v err=%v", keys, err)
	}
	if err := svc.UseConsoleFeeds(ctx, "ada"); err != nil {
		t.Fatal(err)
	}
	st.Close()

	st, err = store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	svc, err = settings.Load(ctx, st, defaults())
	if err != nil {
		t.Fatal(err)
	}
	got = svc.Current()
	if got.BlockedRCode != "NXDOMAIN" || got.LogMode != settings.LogBlocked || got.FeedsSource != settings.FeedsFromConsole || got.SyncInterval != 6*time.Hour {
		t.Fatalf("values after restart = %+v", got)
	}
}

func TestUpdateRejectsBadValuesWithoutSaving(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "dns.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	svc, err := settings.Load(ctx, st, defaults())
	if err != nil {
		t.Fatal(err)
	}
	good := "NXDOMAIN"
	bad := []settings.Patch{
		{BlockedRCode: ptr("NOERROR")},
		{Upstream: ptr("not an address")},
		{Upstream: ptr("1.1.1.1:0")},
		{UpstreamTimeoutSeconds: ptr(0)},
		{RetentionDays: ptr(4000)},
		{SyncIntervalHours: ptr(0)},
		{LogMode: ptr("some")},
		{BlockedRCode: &good, LogMode: ptr("verbose")},
	}
	for i, p := range bad {
		_, err := svc.Update(ctx, p, "ada")
		var verr *settings.Error
		if !errors.As(err, &verr) || verr.Message == "" {
			t.Fatalf("case %d error = %v", i, err)
		}
	}
	if svc.Current() != defaults() || len(svc.Saved()) != 0 {
		t.Fatalf("values changed after rejected updates: %+v %+v", svc.Current(), svc.Saved())
	}
}

func TestKeepEvent(t *testing.T) {
	cases := []struct {
		mode, action string
		keep         bool
	}{
		{settings.LogAll, "ALLOWED", true},
		{settings.LogAll, "ERROR", true},
		{settings.LogBlocked, "BLOCKED", true},
		{settings.LogBlocked, "ALLOWED", false},
		{settings.LogBlocked, "ERROR", false},
		{settings.LogNone, "BLOCKED", false},
	}
	for _, c := range cases {
		if got := (settings.Values{LogMode: c.mode}).KeepEvent(c.action); got != c.keep {
			t.Errorf("mode %s action %s keep = %v", c.mode, c.action, got)
		}
	}
}

func ptr[T any](v T) *T { return &v }
