package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dnsfilter/internal/auth"
	"dnsfilter/internal/config"
	"dnsfilter/internal/feeds"
	"dnsfilter/internal/httpapi"
	"dnsfilter/internal/policy"
	"dnsfilter/internal/settings"
	"dnsfilter/internal/store"
	"dnsfilter/web"
)

func TestHealthLoginRolesAndRules(t *testing.T) {
	ctx := context.Background()
	env := newEnv(t)
	srv := httptest.NewServer(env.api.Handler())
	defer srv.Close()

	health := get(t, srv.Client(), srv.URL+"/api/v1/health", "")
	if health.StatusCode != http.StatusOK || !strings.Contains(body(t, health), `"status":"ok"`) {
		t.Fatalf("health = %d %s", health.StatusCode, body(t, health))
	}
	if health.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("CORS header was set")
	}

	bad := postJSON(t, srv.Client(), srv.URL+"/api/v1/auth/login", "", "", map[string]string{
		"username": "admin", "password": "wrong-password",
	})
	if bad.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad login = %d", bad.StatusCode)
	}
	if strings.Contains(env.logs.String(), "wrong-password") {
		t.Fatal("password was written to the log")
	}

	admin := signIn(t, srv, "admin", "lab-admin-pass")
	if !admin.cookie.HttpOnly || admin.cookie.Path != "/" || admin.cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie = %#v", admin.cookie)
	}
	if strings.Contains(admin.raw, admin.cookie.Value) {
		t.Fatal("raw session token was returned in the JSON body")
	}
	me := get(t, srv.Client(), srv.URL+"/api/v1/me", admin.cookie.Value)
	if me.StatusCode != http.StatusOK || !strings.Contains(body(t, me), `"role":"admin"`) {
		t.Fatalf("me = %d %s", me.StatusCode, body(t, me))
	}

	noCSRF := postJSON(t, srv.Client(), srv.URL+"/api/v1/rules", admin.cookie.Value, "", map[string]string{
		"domain": "c2-demo.test", "rule_type": "deny", "match_type": "exact",
	})
	if noCSRF.StatusCode != http.StatusForbidden {
		t.Fatalf("missing csrf = %d %s", noCSRF.StatusCode, body(t, noCSRF))
	}
	badOriginReq, err := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/rules", bytes.NewReader([]byte(`{"domain":"c2-demo.test","rule_type":"deny","match_type":"exact"}`)))
	if err != nil {
		t.Fatal(err)
	}
	badOriginReq.Header.Set("Content-Type", "application/json")
	badOriginReq.Header.Set("Origin", "https://evil.example")
	badOriginReq.Header.Set(auth.CSRFHeader, admin.csrf)
	badOriginReq.AddCookie(admin.cookie)
	badOrigin, err := srv.Client().Do(badOriginReq)
	if err != nil {
		t.Fatal(err)
	}
	if badOrigin.StatusCode != http.StatusForbidden {
		t.Fatalf("bad origin = %d", badOrigin.StatusCode)
	}

	created := postJSON(t, srv.Client(), srv.URL+"/api/v1/rules", admin.cookie.Value, admin.csrf, map[string]string{
		"domain": "C2-Demo.TEST.", "rule_type": "deny", "match_type": "exact", "description": "lab",
	})
	if created.StatusCode != http.StatusCreated {
		t.Fatalf("create = %d %s", created.StatusCode, body(t, created))
	}
	if env.engine.Decide("c2-demo.test").Action != policy.ActionBlocked {
		t.Fatal("new rule was not applied to the running policy")
	}
	var createdRule struct {
		ID int64 `json:"id"`
	}
	decode(t, created, &createdRule)

	analyst := signIn(t, srv, "analyst", "lab-analyst-pass")
	events := get(t, srv.Client(), srv.URL+"/api/v1/events", analyst.cookie.Value)
	if events.StatusCode != http.StatusOK {
		t.Fatalf("analyst events = %d", events.StatusCode)
	}
	summary := get(t, srv.Client(), srv.URL+"/api/v1/dashboard/summary", analyst.cookie.Value)
	if summary.StatusCode != http.StatusOK {
		t.Fatalf("analyst summary = %d", summary.StatusCode)
	}
	denied := postJSON(t, srv.Client(), srv.URL+"/api/v1/rules", analyst.cookie.Value, analyst.csrf, map[string]string{
		"domain": "other.test", "rule_type": "deny", "match_type": "exact",
	})
	if denied.StatusCode != http.StatusForbidden {
		t.Fatalf("analyst create = %d", denied.StatusCode)
	}
	syncDenied := postJSON(t, srv.Client(), srv.URL+"/api/v1/feeds/1/sync", analyst.cookie.Value, analyst.csrf, nil)
	if syncDenied.StatusCode != http.StatusForbidden {
		t.Fatalf("analyst sync = %d %s", syncDenied.StatusCode, body(t, syncDenied))
	}
	auditDenied := get(t, srv.Client(), srv.URL+"/api/v1/audit", analyst.cookie.Value)
	if auditDenied.StatusCode != http.StatusForbidden {
		t.Fatalf("analyst audit = %d", auditDenied.StatusCode)
	}
	huge := get(t, srv.Client(), srv.URL+"/api/v1/events?limit=1000", analyst.cookie.Value)
	if huge.StatusCode != http.StatusBadRequest {
		t.Fatalf("huge page = %d", huge.StatusCode)
	}

	synced := postJSON(t, srv.Client(), srv.URL+"/api/v1/feeds/"+itoa(env.feedID)+"/sync", admin.cookie.Value, admin.csrf, nil)
	syncedBody := body(t, synced)
	if synced.StatusCode != http.StatusOK || !strings.Contains(syncedBody, `"domains_count":3`) {
		t.Fatalf("sync = %d %s", synced.StatusCode, syncedBody)
	}
	if env.engine.Decide("malware-demo.test").MatchedSource != "demo-local" {
		t.Fatalf("feed decision = %+v", env.engine.Decide("malware-demo.test"))
	}

	logout := postJSON(t, srv.Client(), srv.URL+"/api/v1/auth/logout", admin.cookie.Value, admin.csrf, nil)
	if logout.StatusCode != http.StatusOK {
		t.Fatalf("logout = %d %s", logout.StatusCode, body(t, logout))
	}
	after := get(t, srv.Client(), srv.URL+"/api/v1/me", admin.cookie.Value)
	if after.StatusCode != http.StatusUnauthorized {
		t.Fatalf("me after logout = %d", after.StatusCode)
	}

	del := deleteReq(t, srv.Client(), srv.URL+"/api/v1/rules/"+itoa(createdRule.ID), analyst.cookie.Value, analyst.csrf)
	if del.StatusCode != http.StatusForbidden {
		t.Fatalf("analyst delete = %d", del.StatusCode)
	}
	_ = ctx
}

func TestSecureCookieAndLocalAssets(t *testing.T) {
	env := newEnv(t)
	srv := httptest.NewTLSServer(env.api.Handler())
	defer srv.Close()
	client := srv.Client()
	session := signInURL(t, client, srv.URL, "admin", "lab-admin-pass")
	if !session.cookie.Secure {
		t.Fatal("cookie was not marked Secure on HTTPS")
	}
	page, err := client.Get(srv.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	text := body(t, page)
	if !strings.Contains(text, "Sign in") || strings.Contains(text, "innerHTML") {
		t.Fatal("login page is missing its form or contains innerHTML")
	}
	css, err := client.Get(srv.URL + "/static/css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	if css.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("static cache-control = %q", css.Header.Get("Cache-Control"))
	}
	css.Body.Close()
	err = fs.WalkDir(web.Files, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		raw, err := fs.ReadFile(web.Files, path)
		if err != nil {
			return err
		}
		text := strings.ReplaceAll(string(raw), "http://www.w3.org/2000/svg", "")
		if strings.Contains(text, "innerHTML") || strings.Contains(text, "http://") || strings.Contains(text, "https://") {
			t.Errorf("%s references a remote resource or innerHTML", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

type session struct {
	cookie *http.Cookie
	csrf   string
	raw    string
}

func signIn(t *testing.T, srv *httptest.Server, username, password string) session {
	t.Helper()
	return signInURL(t, srv.Client(), srv.URL, username, password)
}

func signInURL(t *testing.T, client *http.Client, base, username, password string) session {
	t.Helper()
	resp := postJSON(t, client, base+"/api/v1/auth/login", "", "", map[string]string{
		"username": username, "password": password,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login %s = %d %s", username, resp.StatusCode, body(t, resp))
	}
	var payload struct {
		CSRF string `json:"csrf_token"`
	}
	raw := body(t, resp)
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatal(err)
	}
	cookies := resp.Cookies()
	if len(cookies) != 1 || cookies[0].Name != auth.CookieName {
		t.Fatalf("cookies = %#v", cookies)
	}
	return session{cookie: cookies[0], csrf: payload.CSRF, raw: raw}
}

func newEnv(t *testing.T) *lab {
	t.Helper()
	dir := t.TempDir()
	list := filepath.Join(dir, "list.txt")
	if err := os.WriteFile(list, []byte("malware-demo.test\nphishing-demo.test\nc2-demo.test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "dns.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	accounts := auth.New(st, logger)
	if err := accounts.Bootstrap(context.Background(), "admin", "lab-admin-pass", "analyst", "lab-analyst-pass"); err != nil {
		t.Fatal(err)
	}
	engine := policy.NewEngine()
	feedSvc := &feeds.Service{
		Store: st,
		Sources: []config.FeedSource{{
			Name: "demo-local", Path: list, Format: feeds.FormatDomains,
		}},
		OnChange: func(ctx context.Context) error {
			rules, err := st.ListRules(ctx)
			if err != nil {
				return err
			}
			domains, err := st.ListFeedDomains(ctx)
			if err != nil {
				return err
			}
			var policyRules []policy.Rule
			for _, rule := range rules {
				policyRules = append(policyRules, policy.Rule{ID: rule.ID, Domain: rule.Domain, Kind: rule.RuleType, Match: rule.MatchType})
			}
			var feedRules []policy.FeedRule
			for _, domain := range domains {
				feedRules = append(feedRules, policy.FeedRule{Name: domain.FeedName, Domain: domain.Domain})
			}
			snap, err := policy.NewSnapshot(policyRules, feedRules)
			if err != nil {
				return err
			}
			engine.Replace(snap)
			return nil
		},
	}
	if err := feedSvc.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	feedsList, err := st.ListFeeds(context.Background())
	if err != nil || len(feedsList) != 1 {
		t.Fatalf("feeds = %+v err=%v", feedsList, err)
	}
	live, err := settings.Load(context.Background(), st, settings.Values{
		BlockedRCode: "REFUSED", Upstream: "192.0.2.53:53", UpstreamTimeout: 2 * time.Second,
		Retention: 7 * 24 * time.Hour, SyncInterval: 6 * time.Hour,
		LogMode: settings.LogAll, FeedsSource: settings.FeedsFromFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	api := &httpapi.API{
		Store: st, Auth: accounts, Feeds: feedSvc, Settings: live, Engine: engine, Logger: logger,
		Reload: feedSvc.OnChange,
	}
	return &lab{api: api, engine: engine, logs: &logs, feedID: feedsList[0].ID, store: st, settings: live, dir: dir}
}

type lab struct {
	api      *httpapi.API
	engine   *policy.Engine
	logs     *bytes.Buffer
	feedID   int64
	store    *store.Store
	settings *settings.Service
	dir      string
}

func postJSON(t *testing.T, client *http.Client, url, cookie, csrf string, payload any) *http.Response {
	t.Helper()
	var buf io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		buf = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(http.MethodPost, url, buf)
	if err != nil {
		t.Fatal(err)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: cookie})
	}
	if csrf != "" {
		req.Header.Set(auth.CSRFHeader, csrf)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func deleteReq(t *testing.T, client *http.Client, url, cookie, csrf string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: cookie})
	req.Header.Set(auth.CSRFHeader, csrf)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func get(t *testing.T, client *http.Client, url, cookie string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: cookie})
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func body(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func decode(t *testing.T, resp *http.Response, dst any) {
	t.Helper()
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
		t.Fatal(err)
	}
}

func itoa(id int64) string {
	return strconvFormat(id)
}

func strconvFormat(id int64) string {
	const digits = "0123456789"
	if id == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for id > 0 {
		i--
		buf[i] = digits[id%10]
		id /= 10
	}
	return string(buf[i:])
}
