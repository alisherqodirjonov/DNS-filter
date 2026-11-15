package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadExampleConfig(t *testing.T) {
	path := filepath.Join("..", "..", "config.example.json")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load(example): %v", err)
	}
	if cfg.DNS.ListenUDP != "127.0.0.1:5353" || cfg.DNS.ListenTCP != "127.0.0.1:5353" {
		t.Fatalf("listen = %s / %s", cfg.DNS.ListenUDP, cfg.DNS.ListenTCP)
	}
	if cfg.DNS.Upstream != "1.1.1.1:53" {
		t.Fatalf("upstream = %s", cfg.DNS.Upstream)
	}
	if cfg.DNS.UpstreamTimeout != 3*time.Second {
		t.Fatalf("timeout = %s", cfg.DNS.UpstreamTimeout)
	}
	if cfg.DNS.BlockedRCode != "REFUSED" {
		t.Fatalf("rcode = %s", cfg.DNS.BlockedRCode)
	}
	if cfg.HTTP.Listen != "127.0.0.1:8080" {
		t.Fatalf("http = %s", cfg.HTTP.Listen)
	}
	if !cfg.LoopbackHTTP() {
		t.Fatal("example admin listener is not loopback")
	}
	if cfg.Logging.Retention != 7*24*time.Hour {
		t.Fatalf("retention = %s", cfg.Logging.Retention)
	}
	if cfg.Feeds.SyncInterval != 24*time.Hour {
		t.Fatalf("sync = %s", cfg.Feeds.SyncInterval)
	}
	if len(cfg.Feeds.Sources) != 1 {
		t.Fatalf("sources = %d", len(cfg.Feeds.Sources))
	}
	src := cfg.Feeds.Sources[0]
	if src.Name != "demo-local" || src.Format != "domains" || src.URL != "" {
		t.Fatalf("source = %+v", src)
	}
	if !strings.HasSuffix(src.Path, filepath.Join("testdata", "demo-blocklist.txt")) {
		t.Fatalf("feed path = %s", src.Path)
	}
	if !filepath.IsAbs(cfg.Database.Path) {
		t.Fatalf("database path %s is not absolute", cfg.Database.Path)
	}
}

func TestResolvesRelativePathsAgainstConfigDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	body := `{
	  "dns": {"listen_udp":"127.0.0.1:5353","listen_tcp":"127.0.0.1:5353","upstream":"127.0.0.1:53","upstream_timeout_seconds":3,"blocked_rcode":"REFUSED"},
	  "http": {"listen":"[::1]:8080"},
	  "database": {"path":"./data/dnsfilter.db"},
	  "logging": {"retention_days":7},
	  "feeds": {"sync_interval_hours":24,"sources":[{"name":"local","path":"./lists/a.txt","format":"hosts"}]}
	}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Database.Path != filepath.Join(dir, "data", "dnsfilter.db") {
		t.Fatalf("db = %s", cfg.Database.Path)
	}
	if cfg.Feeds.Sources[0].Path != filepath.Join(dir, "lists", "a.txt") {
		t.Fatalf("feed = %s", cfg.Feeds.Sources[0].Path)
	}
	if !cfg.LoopbackHTTP() {
		t.Fatal("::1 should be loopback")
	}
}

func TestRejectsInvalidConfig(t *testing.T) {
	base := map[string]any{
		"dns": map[string]any{
			"listen_udp":               "127.0.0.1:5353",
			"listen_tcp":               "127.0.0.1:5353",
			"upstream":                 "1.1.1.1:53",
			"upstream_timeout_seconds": 3,
			"blocked_rcode":            "REFUSED",
		},
		"http":     map[string]any{"listen": "127.0.0.1:8080"},
		"database": map[string]any{"path": "./data/dnsfilter.db"},
		"logging":  map[string]any{"retention_days": 7},
		"feeds": map[string]any{
			"sync_interval_hours": 24,
			"sources": []any{
				map[string]any{"name": "demo", "path": "./list.txt", "format": "domains"},
			},
		},
	}

	cases := []struct {
		name    string
		mutate  func(map[string]any)
		wantErr string
	}{
		{
			name: "listen address",
			mutate: func(m map[string]any) {
				m["dns"].(map[string]any)["listen_udp"] = "5353"
			},
			wantErr: "dns.listen_udp",
		},
		{
			name: "upstream",
			mutate: func(m map[string]any) {
				m["dns"].(map[string]any)["upstream"] = "1.1.1.1"
			},
			wantErr: "dns.upstream",
		},
		{
			name: "timeout",
			mutate: func(m map[string]any) {
				m["dns"].(map[string]any)["upstream_timeout_seconds"] = 0
			},
			wantErr: "upstream_timeout_seconds",
		},
		{
			name: "rcode",
			mutate: func(m map[string]any) {
				m["dns"].(map[string]any)["blocked_rcode"] = "NOERROR"
			},
			wantErr: "blocked_rcode",
		},
		{
			name: "feed format",
			mutate: func(m map[string]any) {
				m["feeds"].(map[string]any)["sources"] = []any{
					map[string]any{"name": "demo", "path": "./list.txt", "format": "adblock"},
				}
			},
			wantErr: "format",
		},
		{
			name: "plain http feed",
			mutate: func(m map[string]any) {
				m["feeds"].(map[string]any)["sources"] = []any{
					map[string]any{"name": "demo", "url": "http://feeds.example/list.txt", "format": "domains"},
				}
			},
			wantErr: "https",
		},
		{
			name: "both path and url",
			mutate: func(m map[string]any) {
				m["feeds"].(map[string]any)["sources"] = []any{
					map[string]any{"name": "demo", "path": "./a.txt", "url": "https://feeds.example/a.txt", "format": "domains"},
				}
			},
			wantErr: "exactly one",
		},
		{
			name: "neither path nor url",
			mutate: func(m map[string]any) {
				m["feeds"].(map[string]any)["sources"] = []any{
					map[string]any{"name": "demo", "format": "domains"},
				}
			},
			wantErr: "exactly one",
		},
		{
			name: "duplicate feed",
			mutate: func(m map[string]any) {
				m["feeds"].(map[string]any)["sources"] = []any{
					map[string]any{"name": "demo", "path": "./a.txt", "format": "domains"},
					map[string]any{"name": "demo", "path": "./b.txt", "format": "hosts"},
				}
			},
			wantErr: "duplicate",
		},
		{
			name: "unknown field",
			mutate: func(m map[string]any) {
				m["cache"] = true
			},
			wantErr: "unknown field",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := cloneMap(base)
			tc.mutate(m)
			path := writeJSON(t, m)
			_, err := Load(path)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tc.wantErr)) {
				t.Fatalf("error %q does not mention %q", err, tc.wantErr)
			}
		})
	}
}

func cloneMap(in map[string]any) map[string]any {
	// The test mutations replace nested maps, so a shallow copy of the top level
	// is not enough when two cases share a nested map. Rebuild from JSON instead
	// by copying each known section before the caller replaces one of them.
	out := map[string]any{}
	for k, v := range in {
		out[k] = v
	}
	dns := map[string]any{}
	for k, v := range in["dns"].(map[string]any) {
		dns[k] = v
	}
	out["dns"] = dns
	feeds := map[string]any{}
	for k, v := range in["feeds"].(map[string]any) {
		feeds[k] = v
	}
	out["feeds"] = feeds
	return out
}

func writeJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := jsonMarshal(v)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}
