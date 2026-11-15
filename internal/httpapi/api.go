// Package httpapi is the management API and the server-rendered console.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"dnsfilter/internal/auth"
	"dnsfilter/internal/feeds"
	"dnsfilter/internal/policy"
	"dnsfilter/internal/reporting"
	"dnsfilter/internal/store"
	"dnsfilter/web"
)

// API serves the JSON API and the embedded console.
type API struct {
	Store  *store.Store
	Auth   *auth.Service
	Feeds  *feeds.Service
	Engine *policy.Engine
	Logger *slog.Logger
	Reload func(context.Context) error
	tmpl   *template.Template
	static http.Handler
}

// Handler returns the root handler with security headers applied.
func (a *API) Handler() http.Handler {
	if a.Logger == nil {
		a.Logger = slog.Default()
	}
	if a.tmpl == nil {
		tmpl, err := template.ParseFS(web.Files, "templates/*.html")
		if err != nil {
			panic(err)
		}
		a.tmpl = tmpl
	}
	if a.static == nil {
		sub, err := fs.Sub(web.Files, "static")
		if err != nil {
			panic(err)
		}
		a.static = http.FileServer(http.FS(sub))
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", a.home)
	mux.HandleFunc("GET /login", a.page("login"))
	mux.HandleFunc("GET /dashboard", a.page("dashboard"))
	mux.HandleFunc("GET /events", a.page("events"))
	mux.HandleFunc("GET /rules", a.page("rules"))
	mux.HandleFunc("GET /feeds", a.page("feeds"))
	mux.HandleFunc("GET /audit", a.page("audit"))
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		a.static.ServeHTTP(w, r)
	})))

	mux.HandleFunc("GET /api/v1/health", a.health)
	mux.HandleFunc("POST /api/v1/auth/login", a.login)
	mux.HandleFunc("POST /api/v1/auth/logout", a.logout)
	mux.HandleFunc("GET /api/v1/me", a.me)
	mux.HandleFunc("GET /api/v1/dashboard/summary", a.summary)
	mux.HandleFunc("GET /api/v1/events", a.events)
	mux.HandleFunc("GET /api/v1/rules", a.listRules)
	mux.HandleFunc("POST /api/v1/rules", a.createRule)
	mux.HandleFunc("DELETE /api/v1/rules/{id}", a.deleteRule)
	mux.HandleFunc("GET /api/v1/feeds", a.listFeeds)
	mux.HandleFunc("POST /api/v1/feeds/{id}/sync", a.syncFeed)
	mux.HandleFunc("GET /api/v1/audit", a.audit)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		securityHeaders(w)
		defer func() {
			if rec := recover(); rec != nil {
				a.Logger.Error("http handler recovered from panic", "panic", fmt.Sprint(rec), "path", r.URL.Path)
				writeError(w, http.StatusInternalServerError, "Something went wrong.")
			}
		}()
		mux.ServeHTTP(w, r)
	})
}

func (a *API) home(w http.ResponseWriter, r *http.Request) {
	if _, err := a.currentSession(r); err == nil {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (a *API) page(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		templateName := "app"
		if name == "login" {
			templateName = "login"
		}
		if err := a.tmpl.ExecuteTemplate(w, templateName, map[string]string{"Page": name}); err != nil {
			a.Logger.Error("render page", "page", name, "error", err.Error())
		}
	}
}

func (a *API) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *API) login(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := readJSON(w, r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "Send a username and password as JSON.")
		return
	}
	result, err := a.Auth.Login(r.Context(), body.Username, body.Password, clientIP(r))
	if errors.Is(err, auth.ErrRateLimited) {
		writeError(w, http.StatusTooManyRequests, "Too many sign-in attempts. Wait a few minutes and try again.")
		return
	}
	if err != nil {
		writeError(w, http.StatusUnauthorized, "That username and password did not match.")
		return
	}
	setSessionCookie(w, r, result.Token, result.Expires)
	writeJSON(w, http.StatusOK, userResponse(result.Username, result.Role, result.CSRF))
}

func (a *API) logout(w http.ResponseWriter, r *http.Request) {
	sess, ok := a.require(w, r, false)
	if !ok {
		return
	}
	cookie, _ := r.Cookie(auth.CookieName)
	raw := ""
	if cookie != nil {
		raw = cookie.Value
	}
	if err := a.Auth.Logout(r.Context(), raw); err != nil {
		a.Logger.Error("logout failed", "username", sess.Username, "error", err.Error())
		writeError(w, http.StatusInternalServerError, "The session could not be closed.")
		return
	}
	clearSessionCookie(w, r)
	writeJSON(w, http.StatusOK, map[string]string{"status": "signed out"})
}

func (a *API) me(w http.ResponseWriter, r *http.Request) {
	sess, ok := a.require(w, r, false)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, userResponse(sess.Username, sess.Role, sess.CSRFToken))
}

func (a *API) summary(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.require(w, r, false); !ok {
		return
	}
	sum, err := reporting.LoadSummary(r.Context(), a.Store)
	if err != nil {
		a.Logger.Error("summary query failed", "error", err.Error())
		writeError(w, http.StatusInternalServerError, "The summary could not be loaded.")
		return
	}
	writeJSON(w, http.StatusOK, summaryResponse(sum))
}

func (a *API) events(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.require(w, r, false); !ok {
		return
	}
	limit, offset, err := pageParams(r, 50)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	action := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("action")))
	if action != "" && action != "ALLOWED" && action != "BLOCKED" && action != "ERROR" {
		writeError(w, http.StatusBadRequest, "Action must be ALLOWED, BLOCKED, or ERROR.")
		return
	}
	qname := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("qname")))
	if len(qname) > 253 {
		writeError(w, http.StatusBadRequest, "That domain filter is too long.")
		return
	}
	events, total, err := a.Store.ListEvents(r.Context(), store.EventFilter{
		QName: qname, Action: action, Limit: limit, Offset: offset,
	})
	if err != nil {
		a.Logger.Error("event query failed", "error", err.Error())
		writeError(w, http.StatusInternalServerError, "The events could not be loaded.")
		return
	}
	out := make([]eventResponse, 0, len(events))
	for _, ev := range events {
		out = append(out, toEvent(ev))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"events": out, "total": total, "limit": limit, "offset": offset,
	})
}

func (a *API) listRules(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.require(w, r, false); !ok {
		return
	}
	rules, err := a.Store.ListRules(r.Context())
	if err != nil {
		a.Logger.Error("rule query failed", "error", err.Error())
		writeError(w, http.StatusInternalServerError, "The rules could not be loaded.")
		return
	}
	out := make([]ruleResponse, 0, len(rules))
	for _, rule := range rules {
		out = append(out, toRule(rule))
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": out})
}

func (a *API) createRule(w http.ResponseWriter, r *http.Request) {
	sess, ok := a.require(w, r, true)
	if !ok {
		return
	}
	var body struct {
		Domain      string `json:"domain"`
		RuleType    string `json:"rule_type"`
		MatchType   string `json:"match_type"`
		Description string `json:"description"`
	}
	if err := readJSON(w, r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "The rule could not be read. Check the form and try again.")
		return
	}
	domain, err := policy.Normalize(body.Domain)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Enter a domain name, such as example.test.")
		return
	}
	ruleType := strings.ToLower(strings.TrimSpace(body.RuleType))
	matchType := strings.ToLower(strings.TrimSpace(body.MatchType))
	if ruleType != policy.KindAllow && ruleType != policy.KindDeny {
		writeError(w, http.StatusBadRequest, "Rule type must be allow or deny.")
		return
	}
	if matchType != policy.MatchExact && matchType != policy.MatchSuffix {
		writeError(w, http.StatusBadRequest, "Match type must be exact or suffix.")
		return
	}
	description := strings.TrimSpace(body.Description)
	if len(description) > 200 {
		writeError(w, http.StatusBadRequest, "Keep the description under 200 characters.")
		return
	}
	rule, err := a.Store.CreateRule(r.Context(), domain, ruleType, matchType, description, sess.Username)
	if errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, "That rule already exists.")
		return
	}
	if err != nil {
		a.Logger.Error("create rule failed", "error", err.Error())
		writeError(w, http.StatusInternalServerError, "The rule could not be saved.")
		return
	}
	if err := a.reload(r.Context()); err != nil {
		a.Logger.Error("policy reload failed", "error", err.Error())
		writeError(w, http.StatusInternalServerError, "The rule was saved, but the filter did not pick it up. Restart the service.")
		return
	}
	_ = a.Store.InsertAudit(r.Context(), store.AuditEvent{
		Username: sess.Username, Action: "rule_create", ObjectType: "rule",
		ObjectID: strconv.FormatInt(rule.ID, 10), Result: "success",
	})
	writeJSON(w, http.StatusCreated, toRule(rule))
}

func (a *API) deleteRule(w http.ResponseWriter, r *http.Request) {
	sess, ok := a.require(w, r, true)
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		writeError(w, http.StatusBadRequest, "That rule id is not valid.")
		return
	}
	if err := a.Store.DeleteRule(r.Context(), id); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "That rule is no longer there.")
		return
	} else if err != nil {
		a.Logger.Error("delete rule failed", "error", err.Error())
		writeError(w, http.StatusInternalServerError, "The rule could not be deleted.")
		return
	}
	if err := a.reload(r.Context()); err != nil {
		a.Logger.Error("policy reload failed", "error", err.Error())
		writeError(w, http.StatusInternalServerError, "The rule was deleted, but the filter did not pick it up. Restart the service.")
		return
	}
	_ = a.Store.InsertAudit(r.Context(), store.AuditEvent{
		Username: sess.Username, Action: "rule_delete", ObjectType: "rule",
		ObjectID: strconv.FormatInt(id, 10), Result: "success",
	})
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) listFeeds(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.require(w, r, false); !ok {
		return
	}
	list, err := a.Store.ListFeeds(r.Context())
	if err != nil {
		a.Logger.Error("feed query failed", "error", err.Error())
		writeError(w, http.StatusInternalServerError, "The feeds could not be loaded.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"feeds": toFeeds(list)})
}

func (a *API) syncFeed(w http.ResponseWriter, r *http.Request) {
	sess, ok := a.require(w, r, true)
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		writeError(w, http.StatusBadRequest, "That feed id is not valid.")
		return
	}
	err = a.Feeds.SyncByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "That feed is not configured.")
		return
	}
	feed, feedErr := a.Store.FeedByID(r.Context(), id)
	if err != nil {
		_ = a.Store.InsertAudit(r.Context(), store.AuditEvent{
			Username: sess.Username, Action: "feed_sync", ObjectType: "feed",
			ObjectID: strconv.FormatInt(id, 10), Result: "failure",
		})
		a.Logger.Error("feed sync failed", "feed_id", id, "error", err.Error())
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"error": "The feed could not be refreshed. The last good list is still loaded.",
			"feed":  feedOrNil(feed, feedErr),
		})
		return
	}
	_ = a.Store.InsertAudit(r.Context(), store.AuditEvent{
		Username: sess.Username, Action: "feed_sync", ObjectType: "feed",
		ObjectID: strconv.FormatInt(id, 10), Result: "success",
	})
	writeJSON(w, http.StatusOK, map[string]any{"feed": toFeed(feed)})
}

func (a *API) audit(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.require(w, r, true); !ok {
		return
	}
	limit, offset, err := pageParams(r, 50)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	events, total, err := a.Store.ListAudit(r.Context(), limit, offset)
	if err != nil {
		a.Logger.Error("audit query failed", "error", err.Error())
		writeError(w, http.StatusInternalServerError, "The audit log could not be loaded.")
		return
	}
	out := make([]auditResponse, 0, len(events))
	for _, ev := range events {
		out = append(out, auditResponse{
			ID: ev.ID, Timestamp: ev.Timestamp, Username: ev.Username, Action: ev.Action,
			ObjectType: ev.ObjectType, ObjectID: ev.ObjectID, Result: ev.Result,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"audit": out, "total": total, "limit": limit, "offset": offset})
}

func (a *API) require(w http.ResponseWriter, r *http.Request, adminOnly bool) (store.Session, bool) {
	sess, err := a.currentSession(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Sign in to continue.")
		return store.Session{}, false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		if !originAllowed(r) || !auth.TokensEqual(r.Header.Get(auth.CSRFHeader), sess.CSRFToken) {
			writeError(w, http.StatusForbidden, "The request was rejected. Refresh the page and try again.")
			return store.Session{}, false
		}
	}
	if adminOnly && sess.Role != auth.RoleAdmin {
		writeError(w, http.StatusForbidden, "This action is limited to an administrator.")
		return store.Session{}, false
	}
	return sess, true
}

func (a *API) currentSession(r *http.Request) (store.Session, error) {
	cookie, err := r.Cookie(auth.CookieName)
	if err != nil || cookie.Value == "" {
		return store.Session{}, auth.ErrUnauthenticated
	}
	return a.Auth.Session(r.Context(), cookie.Value)
}

func (a *API) reload(ctx context.Context) error {
	if a.Reload == nil {
		return nil
	}
	return a.Reload(ctx)
}

func securityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
}

func originAllowed(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Host == "" || parsed.Host == "null" {
		return false
	}
	return strings.EqualFold(parsed.Host, r.Host)
}

func setSessionCookie(w http.ResponseWriter, r *http.Request, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     auth.CookieName,
		Value:    token,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   r.TLS != nil,
	})
}

func clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     auth.CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   r.TLS != nil,
	})
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || host == "" {
		return r.RemoteAddr
	}
	return host
}

func readJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func pageParams(r *http.Request, fallback int) (int, int, error) {
	limit := fallback
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 100 {
			return 0, 0, fmt.Errorf("limit must be between 1 and 100")
		}
		limit = n
	}
	offset := 0
	if raw := r.URL.Query().Get("offset"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 || n > 1_000_000 {
			return 0, 0, fmt.Errorf("offset must be zero or greater")
		}
		offset = n
	}
	return limit, offset, nil
}

func userResponse(username, role, csrf string) map[string]string {
	return map[string]string{"username": username, "role": role, "csrf_token": csrf}
}
