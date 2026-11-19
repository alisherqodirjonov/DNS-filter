package httpapi_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dnsfilter/internal/auth"
	"dnsfilter/internal/settings"
)

func TestSettingsReadForAllAndEditableByAdmin(t *testing.T) {
	env := newEnv(t)
	srv := httptest.NewServer(env.api.Handler())
	defer srv.Close()
	admin := signIn(t, srv, "admin", "lab-admin-pass")
	analyst := signIn(t, srv, "analyst", "lab-analyst-pass")

	var view struct {
		Values struct {
			BlockedRCode string `json:"blocked_rcode"`
			LogMode      string `json:"log_mode"`
			Retention    int    `json:"retention_days"`
		} `json:"values"`
		File struct {
			BlockedRCode string `json:"blocked_rcode"`
		} `json:"file"`
		Saved map[string]struct {
			UpdatedBy string `json:"updated_by"`
		} `json:"saved"`
		FeedsSource string `json:"feeds_source"`
	}
	resp := get(t, srv.Client(), srv.URL+"/api/v1/settings", analyst.cookie.Value)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("analyst settings = %d", resp.StatusCode)
	}
	decode(t, resp, &view)
	if view.Values.BlockedRCode != "REFUSED" || view.Values.LogMode != "all" || view.Values.Retention != 7 || len(view.Saved) != 0 || view.FeedsSource != "file" {
		t.Fatalf("fresh settings = %+v", view)
	}

	denied := putJSON(t, srv, analyst, "/api/v1/settings", map[string]any{"log_mode": "none"})
	if denied.StatusCode != http.StatusForbidden {
		t.Fatalf("analyst update = %d", denied.StatusCode)
	}
	bad := putJSON(t, srv, admin, "/api/v1/settings", map[string]any{"blocked_rcode": "NOERROR"})
	if bad.StatusCode != http.StatusBadRequest || !strings.Contains(body(t, bad), `"field":"blocked_rcode"`) {
		t.Fatalf("bad rcode = %d", bad.StatusCode)
	}
	unknown := putJSON(t, srv, admin, "/api/v1/settings", map[string]any{"listen_udp": "0.0.0.0:53"})
	if unknown.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown field = %d", unknown.StatusCode)
	}
	ok := putJSON(t, srv, admin, "/api/v1/settings", map[string]any{"blocked_rcode": "NXDOMAIN", "log_mode": "blocked", "retention_days": 7})
	if ok.StatusCode != http.StatusOK {
		t.Fatalf("update = %d %s", ok.StatusCode, body(t, ok))
	}
	decode(t, ok, &view)
	if view.Values.BlockedRCode != "NXDOMAIN" || view.File.BlockedRCode != "REFUSED" || view.Values.LogMode != "blocked" {
		t.Fatalf("updated settings = %+v", view)
	}
	if len(view.Saved) != 2 || view.Saved["log_mode"].UpdatedBy != "admin" {
		t.Fatalf("saved = %+v", view.Saved)
	}
	if env.settings.Current().BlockedRCode != "NXDOMAIN" {
		t.Fatal("running settings did not change")
	}
	audit := auditActions(t, srv, admin)
	if audit["settings_update"] != "blocked_rcode,log_mode" {
		t.Fatalf("audit = %+v", audit)
	}
}

func TestDefaultAdminIsHeldUntilPasswordChanges(t *testing.T) {
	env := newEnv(t)
	if err := env.store.DeleteUser(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	if err := env.store.DeleteUser(t.Context(), 2); err != nil {
		t.Fatal(err)
	}
	if err := env.api.Auth.Bootstrap(t.Context(), "", "", "", ""); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(env.api.Handler())
	defer srv.Close()

	admin := signIn(t, srv, auth.DefaultAdminUser, auth.DefaultAdminPassword)
	if !strings.Contains(admin.raw, `"must_change_password":true`) {
		t.Fatalf("login body = %s", admin.raw)
	}
	for _, path := range []string{"/api/v1/dashboard/summary", "/api/v1/events", "/api/v1/settings", "/api/v1/users"} {
		resp := get(t, srv.Client(), srv.URL+path, admin.cookie.Value)
		text := body(t, resp)
		if resp.StatusCode != http.StatusForbidden || !strings.Contains(text, `"must_change_password":true`) {
			t.Fatalf("%s before change = %d %s", path, resp.StatusCode, text)
		}
	}
	rule := postJSON(t, srv.Client(), srv.URL+"/api/v1/rules", admin.cookie.Value, admin.csrf, map[string]string{
		"domain": "c2-demo.test", "rule_type": "deny", "match_type": "exact",
	})
	if rule.StatusCode != http.StatusForbidden {
		t.Fatalf("rule before change = %d", rule.StatusCode)
	}
	me := get(t, srv.Client(), srv.URL+"/api/v1/me", admin.cookie.Value)
	if me.StatusCode != http.StatusOK || !strings.Contains(body(t, me), `"must_change_password":true`) {
		t.Fatalf("me before change = %d", me.StatusCode)
	}

	wrong := postJSON(t, srv.Client(), srv.URL+"/api/v1/account/password", admin.cookie.Value, admin.csrf, map[string]string{
		"current_password": "nope", "new_password": "a-new-lab-pass",
	})
	if wrong.StatusCode != http.StatusBadRequest {
		t.Fatalf("wrong current = %d", wrong.StatusCode)
	}
	short := postJSON(t, srv.Client(), srv.URL+"/api/v1/account/password", admin.cookie.Value, admin.csrf, map[string]string{
		"current_password": auth.DefaultAdminPassword, "new_password": "short",
	})
	if short.StatusCode != http.StatusBadRequest || !strings.Contains(body(t, short), "at least 8") {
		t.Fatalf("short new = %d", short.StatusCode)
	}
	changed := postJSON(t, srv.Client(), srv.URL+"/api/v1/account/password", admin.cookie.Value, admin.csrf, map[string]string{
		"current_password": auth.DefaultAdminPassword, "new_password": "a-new-lab-pass",
	})
	if changed.StatusCode != http.StatusOK || !strings.Contains(body(t, changed), `"must_change_password":false`) {
		t.Fatalf("change = %d", changed.StatusCode)
	}
	if strings.Contains(env.logs.String(), "a-new-lab-pass") {
		t.Fatal("new password was written to the log")
	}
	summary := get(t, srv.Client(), srv.URL+"/api/v1/dashboard/summary", admin.cookie.Value)
	if summary.StatusCode != http.StatusOK {
		t.Fatalf("summary after change = %d", summary.StatusCode)
	}
}

func TestAdminManagesUsersOverAPI(t *testing.T) {
	env := newEnv(t)
	srv := httptest.NewServer(env.api.Handler())
	defer srv.Close()
	admin := signIn(t, srv, "admin", "lab-admin-pass")
	analyst := signIn(t, srv, "analyst", "lab-analyst-pass")

	if resp := get(t, srv.Client(), srv.URL+"/api/v1/users", analyst.cookie.Value); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("analyst list users = %d", resp.StatusCode)
	}
	created := postJSON(t, srv.Client(), srv.URL+"/api/v1/users", admin.cookie.Value, admin.csrf, map[string]string{
		"username": "bea", "password": "temporary-pass", "role": "analyst",
	})
	if created.StatusCode != http.StatusCreated {
		t.Fatalf("create user = %d %s", created.StatusCode, body(t, created))
	}
	var bea struct {
		ID         int64 `json:"id"`
		MustChange bool  `json:"must_change_password"`
	}
	decode(t, created, &bea)
	if !bea.MustChange {
		t.Fatal("new account is not asked to change its password")
	}
	if strings.Contains(env.logs.String(), "temporary-pass") {
		t.Fatal("temporary password was logged")
	}
	dup := postJSON(t, srv.Client(), srv.URL+"/api/v1/users", admin.cookie.Value, admin.csrf, map[string]string{
		"username": "bea", "password": "temporary-pass", "role": "analyst",
	})
	if dup.StatusCode != http.StatusConflict {
		t.Fatalf("duplicate user = %d", dup.StatusCode)
	}

	list := get(t, srv.Client(), srv.URL+"/api/v1/users", admin.cookie.Value)
	text := body(t, list)
	if list.StatusCode != http.StatusOK || strings.Contains(text, "password_hash") || strings.Contains(text, "$2a$") || !strings.Contains(text, `"username":"bea"`) {
		t.Fatalf("list users = %d %s", list.StatusCode, text)
	}

	reset := postJSON(t, srv.Client(), srv.URL+"/api/v1/users/"+itoa(bea.ID)+"/password", admin.cookie.Value, admin.csrf, map[string]string{"password": "second-temp-pass"})
	if reset.StatusCode != http.StatusOK {
		t.Fatalf("reset = %d %s", reset.StatusCode, body(t, reset))
	}
	self := postJSON(t, srv.Client(), srv.URL+"/api/v1/users/1/password", admin.cookie.Value, admin.csrf, map[string]string{"password": "second-temp-pass"})
	if self.StatusCode != http.StatusBadRequest {
		t.Fatalf("self reset = %d", self.StatusCode)
	}
	if resp := deleteReq(t, srv.Client(), srv.URL+"/api/v1/users/1", admin.cookie.Value, admin.csrf); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("self delete = %d", resp.StatusCode)
	}
	if resp := deleteReq(t, srv.Client(), srv.URL+"/api/v1/users/"+itoa(bea.ID), admin.cookie.Value, admin.csrf); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete = %d", resp.StatusCode)
	}
	audit := auditActions(t, srv, admin)
	for _, action := range []string{"user_create", "password_reset", "user_delete"} {
		if audit[action] != "bea" {
			t.Errorf("audit %s = %q", action, audit[action])
		}
	}
}

func TestConsoleFeedsTakeOverTheList(t *testing.T) {
	env := newEnv(t)
	srv := httptest.NewServer(env.api.Handler())
	defer srv.Close()
	admin := signIn(t, srv, "admin", "lab-admin-pass")
	analyst := signIn(t, srv, "analyst", "lab-analyst-pass")
	list := filepath.Join(env.dir, "extra.txt")
	if err := os.WriteFile(list, []byte("extra-demo.test\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	payload := map[string]string{"name": "extra", "path": list, "format": "domains"}
	if resp := postJSON(t, srv.Client(), srv.URL+"/api/v1/feeds", analyst.cookie.Value, analyst.csrf, payload); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("analyst add feed = %d", resp.StatusCode)
	}
	relative := postJSON(t, srv.Client(), srv.URL+"/api/v1/feeds", admin.cookie.Value, admin.csrf, map[string]string{"name": "extra", "path": "extra.txt", "format": "domains"})
	if relative.StatusCode != http.StatusBadRequest || !strings.Contains(body(t, relative), "absolute") {
		t.Fatalf("relative path = %d", relative.StatusCode)
	}
	if env.settings.Current().FeedsSource != settings.FeedsFromFile {
		t.Fatal("a rejected feed handed the list to the console")
	}
	added := postJSON(t, srv.Client(), srv.URL+"/api/v1/feeds", admin.cookie.Value, admin.csrf, payload)
	if added.StatusCode != http.StatusCreated {
		t.Fatalf("add feed = %d %s", added.StatusCode, body(t, added))
	}
	var created struct {
		Feed struct {
			ID     int64  `json:"id"`
			Status string `json:"status"`
		} `json:"feed"`
	}
	decode(t, added, &created)
	if created.Feed.Status != "ok" || env.engine.Decide("extra-demo.test").MatchedSource != "extra" {
		t.Fatalf("added feed = %+v decision=%+v", created.Feed, env.engine.Decide("extra-demo.test"))
	}
	if env.settings.Current().FeedsSource != settings.FeedsFromConsole {
		t.Fatal("feed list is not marked as console managed")
	}
	if resp := postJSON(t, srv.Client(), srv.URL+"/api/v1/feeds", admin.cookie.Value, admin.csrf, payload); resp.StatusCode != http.StatusConflict {
		t.Fatalf("duplicate feed = %d", resp.StatusCode)
	}
	if resp := deleteReq(t, srv.Client(), srv.URL+"/api/v1/feeds/"+itoa(env.feedID), admin.cookie.Value, admin.csrf); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete config feed = %d", resp.StatusCode)
	}
	if env.engine.Decide("malware-demo.test").MatchedSource != "" {
		t.Fatal("removed feed still blocks its names")
	}
	audit := auditActions(t, srv, admin)
	if audit["feed_create"] != "extra" || audit["feed_delete"] != "demo-local" {
		t.Fatalf("audit = %+v", audit)
	}
}

func TestPagesAndEventsRedirect(t *testing.T) {
	env := newEnv(t)
	srv := httptest.NewServer(env.api.Handler())
	defer srv.Close()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(srv.URL + "/events")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMovedPermanently || resp.Header.Get("Location") != "/logs" {
		t.Fatalf("/events = %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	for _, path := range []string{"/logs", "/settings", "/users", "/account"} {
		resp := get(t, srv.Client(), srv.URL+path, "")
		if resp.StatusCode != http.StatusOK || !strings.Contains(body(t, resp), `data-page="`+strings.TrimPrefix(path, "/")+`"`) {
			t.Fatalf("%s = %d", path, resp.StatusCode)
		}
	}
}

func putJSON(t *testing.T, srv *httptest.Server, s session, path string, payload any) *http.Response {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPut, srv.URL+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(auth.CSRFHeader, s.csrf)
	req.AddCookie(s.cookie)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// auditActions maps each audit action to the object of its newest row.
func auditActions(t *testing.T, srv *httptest.Server, admin session) map[string]string {
	t.Helper()
	resp := get(t, srv.Client(), srv.URL+"/api/v1/audit", admin.cookie.Value)
	var out struct {
		Audit []struct {
			Action   string    `json:"action"`
			ObjectID string    `json:"object_id"`
			At       time.Time `json:"timestamp"`
		} `json:"audit"`
	}
	decode(t, resp, &out)
	seen := map[string]string{}
	for _, row := range out.Audit {
		if _, ok := seen[row.Action]; !ok {
			seen[row.Action] = row.ObjectID
		}
	}
	return seen
}
