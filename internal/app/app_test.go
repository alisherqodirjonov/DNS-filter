package app_test

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"dnsfilter/internal/app"
	"dnsfilter/internal/config"
)

// lockedBuffer lets the test read slog output while Run writes it.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func TestRunOpensDatabaseAndShutsDown(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	dnsAddr := freeLoopback(t)
	httpAddr := freeLoopback(t)
	t.Setenv("DNSFILTER_BOOTSTRAP_ADMIN_USER", "admin")
	t.Setenv("DNSFILTER_BOOTSTRAP_ADMIN_PASSWORD", "lab-admin-pass")
	body := fmt.Sprintf("{"+
		`"dns":{"listen_udp":%q,"listen_tcp":%q,"upstream":"127.0.0.1:53","upstream_timeout_seconds":3,"blocked_rcode":"REFUSED"},`+
		`"http":{"listen":%q},`+
		`"database":{"path":"./data/dnsfilter.db"},`+
		`"logging":{"retention_days":7},`+
		`"feeds":{"sync_interval_hours":24,"sources":[{"name":"demo","path":"./list.txt","format":"domains"}]}`+
		"}", dnsAddr, dnsAddr, httpAddr)
	if err := os.WriteFile(cfgPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	var buf lockedBuffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- app.Run(ctx, cfg, logger)
	}()

	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(buf.String(), "admin panel listening") {
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	if !strings.Contains(buf.String(), "database ready") || !strings.Contains(buf.String(), "admin panel listening") {
		t.Fatalf("log = %s", buf.String())
	}
	if _, err := os.Stat(cfg.Database.Path); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown timed out")
	}
	if !strings.Contains(buf.String(), "shutting down") {
		t.Fatalf("log = %s", buf.String())
	}
}

func TestRunReleasesDatabaseWhenListenFails(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	list := filepath.Join(dir, "list.txt")
	if err := os.WriteFile(list, []byte("malware-demo.test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dnsAddr := freeLoopback(t)
	httpAddr := freeLoopback(t)
	held, err := net.ListenPacket("udp", dnsAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	t.Setenv("DNSFILTER_BOOTSTRAP_ADMIN_USER", "admin")
	t.Setenv("DNSFILTER_BOOTSTRAP_ADMIN_PASSWORD", "lab-admin-pass")
	body := fmt.Sprintf("{"+
		`"dns":{"listen_udp":%q,"listen_tcp":%q,"upstream":"127.0.0.1:53","upstream_timeout_seconds":3,"blocked_rcode":"REFUSED"},`+
		`"http":{"listen":%q},`+
		`"database":{"path":"./data/dnsfilter.db"},`+
		`"logging":{"retention_days":7},`+
		`"feeds":{"sync_interval_hours":24,"sources":[{"name":"demo","path":%q,"format":"domains"}]}`+
		"}", dnsAddr, dnsAddr, httpAddr, filepath.ToSlash(list))
	if err := os.WriteFile(cfgPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var buf lockedBuffer
	err = app.Run(context.Background(), cfg, slog.New(slog.NewTextHandler(&buf, nil)))
	if err == nil || !strings.Contains(err.Error(), "address already in use") {
		t.Fatalf("run error = %v", err)
	}
	if strings.Contains(buf.String(), "database is closed") {
		t.Fatalf("worker used a closed database:\n%s", buf.String())
	}
}

func freeLoopback(t *testing.T) string {
	t.Helper()
	for i := 0; i < 10; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := ln.Addr().(*net.TCPAddr).Port
		ln.Close()
		addr := fmt.Sprintf("127.0.0.1:%d", port)
		udp, err := net.ListenPacket("udp", addr)
		if err != nil {
			continue
		}
		udp.Close()
		return addr
	}
	t.Fatal("no free loopback port")
	return ""
}
