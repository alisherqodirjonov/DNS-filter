package feeds_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"dnsfilter/internal/config"
	"dnsfilter/internal/feeds"
	"dnsfilter/internal/store"
)

func TestParseDomainsAndHosts(t *testing.T) {
	body := []byte(strings.Join([]string{
		"# comment",
		"",
		"  Malware-Demo.TEST.  ",
		"malware-demo.test",
		"not a domain",
		"phishing-demo.test",
	}, "\n"))
	parsed, err := feeds.ParseBytes(body, feeds.FormatDomains)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Rejected != 1 {
		t.Fatalf("rejected = %d", parsed.Rejected)
	}
	if strings.Join(parsed.Domains, ",") != "malware-demo.test,phishing-demo.test" {
		t.Fatalf("domains = %v", parsed.Domains)
	}

	hosts := []byte(strings.Join([]string{
		"# hosts comment",
		"",
		"0.0.0.0 c2-demo.test # lab",
		"127.0.0.1 phishing-demo.test",
		"10.1.1.1 ignored.test",
		"0.0.0.0",
		"not-a-hosts-line",
	}, "\n"))
	parsed, err = feeds.ParseBytes(hosts, feeds.FormatHosts)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(parsed.Domains, ",") != "c2-demo.test,phishing-demo.test" {
		t.Fatalf("hosts domains = %v", parsed.Domains)
	}
	if parsed.Rejected != 3 {
		t.Fatalf("hosts rejected = %d", parsed.Rejected)
	}

	demo, err := os.ReadFile(filepath.Join("..", "..", "testdata", "demo-blocklist.txt"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err = feeds.ParseBytes(demo, feeds.FormatDomains)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(parsed.Domains, ",") != "malware-demo.test,phishing-demo.test,c2-demo.test" || parsed.Rejected != 0 {
		t.Fatalf("demo feed = %+v", parsed)
	}
}

func TestMalformedFeedKeepsLastGoodDomains(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	good := filepath.Join(dir, "good.txt")
	bad := filepath.Join(dir, "bad.txt")
	if err := os.WriteFile(good, []byte("malware-demo.test\nphishing-demo.test\nc2-demo.test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bad, []byte("this is not a domain\n!!!\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	st := openStore(t, filepath.Join(dir, "dns.db"))
	svc := &feeds.Service{Store: st}
	if err := svc.SyncSource(ctx, config.FeedSource{Name: "demo", Path: good, Format: feeds.FormatDomains}); err != nil {
		t.Fatal(err)
	}
	if err := svc.SyncSource(ctx, config.FeedSource{Name: "demo", Path: bad, Format: feeds.FormatDomains}); err == nil {
		t.Fatal("expected malformed feed to fail")
	}
	domains, err := st.ListFeedDomains(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(domains) != 3 {
		t.Fatalf("domains after failure = %+v", domains)
	}
	feed, err := st.FeedByName(ctx, "demo")
	if err != nil {
		t.Fatal(err)
	}
	if feed.Status != "error" || feed.DomainsCount != 3 || feed.LastError == "" {
		t.Fatalf("feed = %+v", feed)
	}
	missing := filepath.Join(dir, "missing.txt")
	if err := svc.SyncSource(ctx, config.FeedSource{Name: "demo", Path: missing, Format: feeds.FormatDomains}); err == nil {
		t.Fatal("expected missing file to fail")
	}
	domains, err = st.ListFeedDomains(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(domains) != 3 {
		t.Fatalf("domains after missing file = %+v", domains)
	}
}

func TestHTTPSFeedAndRejectedHTTP(t *testing.T) {
	ctx := context.Background()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "http://feeds.example/list.txt", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("malware-demo.test\n# note\n"))
	}))
	defer srv.Close()

	st := openStore(t, filepath.Join(t.TempDir(), "dns.db"))
	client := feeds.NewHTTPClient(2 * time.Second)
	client.Transport = srv.Client().Transport
	svc := &feeds.Service{Store: st, Client: client}
	if err := svc.SyncSource(ctx, config.FeedSource{Name: "remote", URL: srv.URL + "/list.txt", Format: feeds.FormatDomains}); err != nil {
		t.Fatal(err)
	}
	n, err := st.CountFeedDomains(ctx)
	if err != nil || n != 1 {
		t.Fatalf("count = %d err=%v", n, err)
	}

	plain := &feeds.Service{Store: st, Client: &http.Client{Transport: failTransport{}}}
	err = plain.SyncSource(ctx, config.FeedSource{Name: "remote", URL: "http://feeds.example/list.txt", Format: feeds.FormatDomains})
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("http error = %v", err)
	}
	n, err = st.CountFeedDomains(ctx)
	if err != nil || n != 1 {
		t.Fatalf("domains after rejected http = %d err=%v", n, err)
	}

	err = svc.SyncSource(ctx, config.FeedSource{Name: "remote", URL: srv.URL + "/redirect", Format: feeds.FormatDomains})
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("redirect error = %v", err)
	}
	n, _ = st.CountFeedDomains(ctx)
	if n != 1 {
		t.Fatalf("redirect wiped domains, count = %d", n)
	}
}

func TestBodyLimitAndScheduler(t *testing.T) {
	ctx := context.Background()
	st := openStore(t, filepath.Join(t.TempDir(), "dns.db"))
	dir := t.TempDir()
	path := filepath.Join(dir, "big.txt")
	if err := os.WriteFile(path, []byte(strings.Repeat("a", 80)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	good := filepath.Join(dir, "good.txt")
	if err := os.WriteFile(good, []byte("c2-demo.test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	svc := &feeds.Service{Store: st, MaxBytes: 32}
	if err := svc.SyncSource(ctx, config.FeedSource{Name: "demo", Path: good, Format: feeds.FormatDomains}); err != nil {
		t.Fatal(err)
	}
	if err := svc.SyncSource(ctx, config.FeedSource{Name: "demo", Path: path, Format: feeds.FormatDomains}); err == nil {
		t.Fatal("expected oversized feed to fail")
	}
	n, err := st.CountFeedDomains(ctx)
	if err != nil || n != 1 {
		t.Fatalf("count = %d err=%v", n, err)
	}

	var calls atomic.Int32
	runCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go feeds.Schedule(runCtx, 20*time.Millisecond, func(context.Context) { calls.Add(1) })
	deadline := time.Now().Add(time.Second)
	for calls.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if calls.Load() < 2 {
		t.Fatalf("scheduler calls = %d", calls.Load())
	}
}

type failTransport struct{}

func (failTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, os.ErrClosed
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
