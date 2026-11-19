package app_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"

	"dnsfilter/internal/app"
	"dnsfilter/internal/auth"
	"dnsfilter/internal/config"
	"dnsfilter/internal/dnstest"
)

func TestEndToEndFilter(t *testing.T) {
	fake, err := dnstest.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fake.Close() })

	dir := t.TempDir()
	list := filepath.Join(dir, "list.txt")
	if err := os.WriteFile(list, []byte("malware-demo.test\nphishing-demo.test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dnsAddr := freeLoopback(t)
	httpAddr := freeLoopback(t)
	cfgPath := filepath.Join(dir, "config.json")
	raw := []byte(`{
	  "dns": {"listen_udp":"` + dnsAddr + `","listen_tcp":"` + dnsAddr + `","upstream":"` + fake.Addr + `","upstream_timeout_seconds":1,"blocked_rcode":"REFUSED"},
	  "http": {"listen":"` + httpAddr + `"},
	  "database": {"path":"./data/dnsfilter.db"},
	  "logging": {"retention_days":7},
	  "feeds": {"sync_interval_hours":24,"sources":[{"name":"demo-local","path":"` + filepath.ToSlash(list) + `","format":"domains"}]}
	}`)
	if err := os.WriteFile(cfgPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("DNSFILTER_BOOTSTRAP_ADMIN_USER", "admin")
	t.Setenv("DNSFILTER_BOOTSTRAP_ADMIN_PASSWORD", "lab-admin-pass")
	t.Setenv("DNSFILTER_BOOTSTRAP_ANALYST_USER", "analyst")
	t.Setenv("DNSFILTER_BOOTSTRAP_ANALYST_PASSWORD", "lab-analyst-pass")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- app.Run(ctx, cfg, nil) }()
	waitReady(t, "http://"+httpAddr+"/api/v1/health")

	if resp := exchange(t, dnsAddr, "udp", "example.com."); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("allowed udp rcode = %d", resp.Rcode)
	}
	if resp := exchange(t, dnsAddr, "tcp", "example.com."); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("allowed tcp rcode = %d", resp.Rcode)
	}
	before := fake.UDPHits.Load() + fake.TCPHits.Load()
	blocked := exchange(t, dnsAddr, "udp", "malware-demo.test.")
	if blocked.Rcode != dns.RcodeRefused || len(blocked.Answer) != 0 {
		t.Fatalf("blocked = rcode %d answers %d", blocked.Rcode, len(blocked.Answer))
	}
	if fake.UDPHits.Load()+fake.TCPHits.Load() != before {
		t.Fatal("blocked query was forwarded")
	}
	if resp := exchange(t, dnsAddr, "udp", "notexample.test."); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("boundary rcode = %d", resp.Rcode)
	}

	conn, err := net.Dial("udp", dnsAddr)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = conn.Write([]byte{9, 8, 7, 6, 5})
	conn.Close()
	if resp := exchange(t, dnsAddr, "udp", "example.com."); resp.Rcode != dns.RcodeSuccess {
		t.Fatal("server did not survive a malformed packet")
	}

	fake.SetTruncateUDP(true)
	truncated := exchange(t, dnsAddr, "udp", "example.com.")
	fake.SetTruncateUDP(false)
	if truncated.Rcode != dns.RcodeSuccess || truncated.Truncated {
		t.Fatalf("truncated retry = rcode %d tc %v", truncated.Rcode, truncated.Truncated)
	}

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}
	base := "http://" + httpAddr
	admin := login(t, client, base, "admin", "lab-admin-pass")
	analystJar, _ := cookiejar.New(nil)
	analystClient := &http.Client{Jar: analystJar, Timeout: 5 * time.Second}
	analyst := login(t, analystClient, base, "analyst", "lab-analyst-pass")
	status, _ := doJSON(t, analystClient, http.MethodPost, base+"/api/v1/rules", analyst, map[string]string{
		"domain": "example.test", "rule_type": "deny", "match_type": "exact",
	})
	if status != http.StatusForbidden {
		t.Fatalf("analyst create = %d", status)
	}

	status, _ = doJSON(t, client, http.MethodPost, base+"/api/v1/rules", admin, map[string]string{
		"domain": "malware-demo.test", "rule_type": "allow", "match_type": "exact", "description": "lab exception",
	})
	if status != http.StatusCreated {
		t.Fatalf("allow create = %d", status)
	}
	if resp := exchange(t, dnsAddr, "udp", "malware-demo.test."); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("allow rule did not take effect, rcode = %d", resp.Rcode)
	}

	status, eventsBody := doJSON(t, client, http.MethodGet, base+"/api/v1/events?qname=malware-demo.test&limit=20", admin, nil)
	if status != http.StatusOK || !bytes.Contains(eventsBody, []byte(`"qname":"malware-demo.test"`)) {
		t.Fatalf("events = %d %s", status, eventsBody)
	}
	if !bytes.Contains(eventsBody, []byte(`"action":"BLOCKED"`)) || !bytes.Contains(eventsBody, []byte(`"action":"ALLOWED"`)) {
		t.Fatalf("events missing both outcomes: %s", eventsBody)
	}

	// Settings changed in the console apply to the next query, without a restart.
	status, raw = doJSON(t, client, http.MethodPut, base+"/api/v1/settings", admin, map[string]any{
		"blocked_rcode": "NXDOMAIN", "log_mode": "none",
	})
	if status != http.StatusOK {
		t.Fatalf("settings update = %d %s", status, raw)
	}
	storedBefore, totalBefore := logRows(t, client, base, admin), summaryTotal(t, client, base, admin)
	if resp := exchange(t, dnsAddr, "udp", "phishing-demo.test."); resp.Rcode != dns.RcodeNameError {
		t.Fatalf("blocked rcode after change = %d", resp.Rcode)
	}
	exchange(t, dnsAddr, "udp", "example.com.")
	if got := logRows(t, client, base, admin); got != storedBefore {
		t.Fatalf("log rows with logging off = %d, want %d", got, storedBefore)
	}
	if got := summaryTotal(t, client, base, admin); got != totalBefore+2 {
		t.Fatalf("overview total with logging off = %d, want %d", got, totalBefore+2)
	}

	status, raw = doJSON(t, client, http.MethodPut, base+"/api/v1/settings", admin, map[string]any{"log_mode": "blocked"})
	if status != http.StatusOK {
		t.Fatalf("settings update = %d %s", status, raw)
	}
	exchange(t, dnsAddr, "udp", "example.com.")
	exchange(t, dnsAddr, "tcp", "phishing-demo.test.")
	status, raw = doJSON(t, client, http.MethodGet, base+"/api/v1/events?limit=1", admin, nil)
	if status != http.StatusOK || !bytes.Contains(raw, []byte(`"qname":"phishing-demo.test","qtype":"A","transport":"tcp","action":"BLOCKED","rcode":"NXDOMAIN"`)) {
		t.Fatalf("newest row with blocked-only logging = %s", raw)
	}
	if got := logRows(t, client, base, admin); got != storedBefore+1 {
		t.Fatalf("log rows with blocked-only logging = %d, want %d", got, storedBefore+1)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown timed out")
	}
}

func logRows(t *testing.T, client *http.Client, base string, who identity) int {
	t.Helper()
	var out struct {
		Total int `json:"total"`
	}
	getInto(t, client, base+"/api/v1/events?limit=1", who, &out)
	return out.Total
}

func summaryTotal(t *testing.T, client *http.Client, base string, who identity) int {
	t.Helper()
	var out struct {
		Total int `json:"total"`
	}
	getInto(t, client, base+"/api/v1/dashboard/summary", who, &out)
	return out.Total
}

func getInto(t *testing.T, client *http.Client, url string, who identity, dst any) {
	t.Helper()
	status, raw := doJSON(t, client, http.MethodGet, url, who, nil)
	if status != http.StatusOK {
		t.Fatalf("GET %s = %d %s", url, status, raw)
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		t.Fatal(err)
	}
}

func waitReady(t *testing.T, url string) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(30 * time.Millisecond)
	}
	t.Fatalf("service did not become ready at %s", url)
}

func exchange(t *testing.T, addr, network, name string) *dns.Msg {
	t.Helper()
	msg := new(dns.Msg)
	msg.SetQuestion(name, dns.TypeA)
	client := &dns.Client{Net: network, Timeout: 3 * time.Second}
	resp, _, err := client.Exchange(msg, addr)
	if err != nil {
		t.Fatalf("%s %s: %v", network, name, err)
	}
	return resp
}

type identity struct {
	csrf string
}

func login(t *testing.T, client *http.Client, base, username, password string) identity {
	t.Helper()
	status, raw := doJSON(t, client, http.MethodPost, base+"/api/v1/auth/login", identity{}, map[string]string{
		"username": username, "password": password,
	})
	if status != http.StatusOK {
		t.Fatalf("login %s = %d %s", username, status, raw)
	}
	var payload struct {
		CSRF string `json:"csrf_token"`
		Role string `json:"role"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.CSRF == "" {
		t.Fatal("login did not return a csrf token")
	}
	return identity{csrf: payload.CSRF}
}

func doJSON(t *testing.T, client *http.Client, method, url string, who identity, payload any) (int, []byte) {
	t.Helper()
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatal(err)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if who.csrf != "" && method != http.MethodGet {
		req.Header.Set(auth.CSRFHeader, who.csrf)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, raw
}
