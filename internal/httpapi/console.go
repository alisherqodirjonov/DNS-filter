package httpapi

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"dnsfilter/internal/auth"
	"dnsfilter/internal/feeds"
	"dnsfilter/internal/settings"
	"dnsfilter/internal/store"
)

type settingValues struct {
	BlockedRCode           string `json:"blocked_rcode"`
	Upstream               string `json:"upstream"`
	UpstreamTimeoutSeconds int    `json:"upstream_timeout_seconds"`
	RetentionDays          int    `json:"retention_days"`
	SyncIntervalHours      int    `json:"feed_sync_interval_hours"`
	LogMode                string `json:"log_mode"`
}

type savedSetting struct {
	UpdatedAt time.Time `json:"updated_at"`
	UpdatedBy string    `json:"updated_by"`
}

type settingsJSON struct {
	Values      settingValues           `json:"values"`
	File        settingValues           `json:"file"`
	Saved       map[string]savedSetting `json:"saved"`
	FeedsSource string                  `json:"feeds_source"`
}

type userJSON struct {
	ID                 int64     `json:"id"`
	Username           string    `json:"username"`
	Role               string    `json:"role"`
	MustChangePassword bool      `json:"must_change_password"`
	CreatedAt          time.Time `json:"created_at"`
}

func toSettingValues(v settings.Values) settingValues {
	return settingValues{
		BlockedRCode:           v.BlockedRCode,
		Upstream:               v.Upstream,
		UpstreamTimeoutSeconds: int(v.UpstreamTimeout / time.Second),
		RetentionDays:          int(v.Retention / (24 * time.Hour)),
		SyncIntervalHours:      int(v.SyncInterval / time.Hour),
		LogMode:                v.LogMode,
	}
}

func (a *API) settingsResponse() settingsJSON {
	saved := map[string]savedSetting{}
	for key, item := range a.Settings.Saved() {
		if key == settings.KeyFeedsSource {
			continue
		}
		saved[key] = savedSetting{UpdatedAt: item.UpdatedAt, UpdatedBy: item.UpdatedBy}
	}
	cur := a.Settings.Current()
	return settingsJSON{
		Values:      toSettingValues(cur),
		File:        toSettingValues(a.Settings.Defaults()),
		Saved:       saved,
		FeedsSource: cur.FeedsSource,
	}
}

func (a *API) getSettings(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.require(w, r, false); !ok {
		return
	}
	writeJSON(w, http.StatusOK, a.settingsResponse())
}

func (a *API) updateSettings(w http.ResponseWriter, r *http.Request) {
	sess, ok := a.require(w, r, true)
	if !ok {
		return
	}
	var body struct {
		BlockedRCode           *string `json:"blocked_rcode"`
		Upstream               *string `json:"upstream"`
		UpstreamTimeoutSeconds *int    `json:"upstream_timeout_seconds"`
		RetentionDays          *int    `json:"retention_days"`
		SyncIntervalHours      *int    `json:"feed_sync_interval_hours"`
		LogMode                *string `json:"log_mode"`
	}
	if err := readJSON(w, r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "The settings could not be read. Check the form and try again.")
		return
	}
	changed, err := a.Settings.Update(r.Context(), settings.Patch{
		BlockedRCode:           body.BlockedRCode,
		Upstream:               body.Upstream,
		UpstreamTimeoutSeconds: body.UpstreamTimeoutSeconds,
		RetentionDays:          body.RetentionDays,
		SyncIntervalHours:      body.SyncIntervalHours,
		LogMode:                body.LogMode,
	}, sess.Username)
	var invalid *settings.Error
	if errors.As(err, &invalid) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": invalid.Message, "field": invalid.Field})
		return
	}
	if err != nil {
		a.Logger.Error("settings update failed", "error", err.Error())
		writeError(w, http.StatusInternalServerError, "The settings could not be saved.")
		return
	}
	if len(changed) > 0 {
		a.Logger.Info("settings changed", "username", sess.Username, "keys", strings.Join(changed, ","))
		_ = a.Store.InsertAudit(r.Context(), store.AuditEvent{
			Username: sess.Username, Action: "settings_update", ObjectType: "settings",
			ObjectID: strings.Join(changed, ","), Result: "success",
		})
	}
	writeJSON(w, http.StatusOK, a.settingsResponse())
}

func (a *API) changePassword(w http.ResponseWriter, r *http.Request) {
	sess, ok := a.require(w, r, false)
	if !ok {
		return
	}
	var body struct {
		Current string `json:"current_password"`
		New     string `json:"new_password"`
	}
	if err := readJSON(w, r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "Send the current and the new password.")
		return
	}
	err := a.Auth.ChangePassword(r.Context(), sess, body.Current, body.New)
	var input *auth.InputError
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, userResponse(sess.Username, sess.Role, sess.CSRFToken, false))
	case errors.Is(err, auth.ErrWrongPassword):
		writeError(w, http.StatusBadRequest, "The current password is not right.")
	case errors.Is(err, auth.ErrRateLimited):
		writeError(w, http.StatusTooManyRequests, "Too many wrong passwords. Wait a few minutes and try again.")
	case errors.As(err, &input):
		writeError(w, http.StatusBadRequest, input.Message)
	default:
		a.Logger.Error("password change failed", "username", sess.Username, "error", err.Error())
		writeError(w, http.StatusInternalServerError, "The password could not be changed.")
	}
}

func (a *API) listUsers(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.require(w, r, true); !ok {
		return
	}
	users, err := a.Store.ListUsers(r.Context())
	if err != nil {
		a.Logger.Error("user query failed", "error", err.Error())
		writeError(w, http.StatusInternalServerError, "The accounts could not be loaded.")
		return
	}
	out := make([]userJSON, 0, len(users))
	for _, u := range users {
		out = append(out, toUser(u))
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": out})
}

func (a *API) createUser(w http.ResponseWriter, r *http.Request) {
	sess, ok := a.require(w, r, true)
	if !ok {
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := readJSON(w, r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "The account could not be read. Check the form and try again.")
		return
	}
	user, err := a.Auth.CreateAccount(r.Context(), sess, body.Username, body.Password, strings.ToLower(strings.TrimSpace(body.Role)))
	if a.accountError(w, err, "The account could not be created.") {
		return
	}
	writeJSON(w, http.StatusCreated, toUser(user))
}

func (a *API) resetPassword(w http.ResponseWriter, r *http.Request) {
	sess, ok := a.require(w, r, true)
	if !ok {
		return
	}
	id, ok := pathID(w, r, "That account id is not valid.")
	if !ok {
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := readJSON(w, r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "Send the temporary password.")
		return
	}
	user, err := a.Auth.ResetPassword(r.Context(), sess, id, body.Password)
	if a.accountError(w, err, "The password could not be reset.") {
		return
	}
	writeJSON(w, http.StatusOK, toUser(user))
}

func (a *API) deleteUser(w http.ResponseWriter, r *http.Request) {
	sess, ok := a.require(w, r, true)
	if !ok {
		return
	}
	id, ok := pathID(w, r, "That account id is not valid.")
	if !ok {
		return
	}
	_, err := a.Auth.DeleteAccount(r.Context(), sess, id)
	if a.accountError(w, err, "The account could not be deleted.") {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// accountError writes the response for a failed account change and reports whether it did.
func (a *API) accountError(w http.ResponseWriter, err error, fallback string) bool {
	var input *auth.InputError
	switch {
	case err == nil:
		return false
	case errors.As(err, &input):
		writeError(w, http.StatusBadRequest, input.Message)
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, "That username is already taken.")
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "That account is no longer there.")
	case errors.Is(err, auth.ErrSelf):
		writeError(w, http.StatusBadRequest, "Use the Account page to change your own password.")
	case errors.Is(err, auth.ErrLastAdmin):
		writeError(w, http.StatusBadRequest, "At least one administrator account must remain.")
	default:
		a.Logger.Error("account change failed", "error", err.Error())
		writeError(w, http.StatusInternalServerError, fallback)
	}
	return true
}

func (a *API) createFeed(w http.ResponseWriter, r *http.Request) {
	sess, ok := a.require(w, r, true)
	if !ok {
		return
	}
	var body struct {
		Name   string `json:"name"`
		Path   string `json:"path"`
		URL    string `json:"url"`
		Format string `json:"format"`
	}
	if err := readJSON(w, r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "The feed could not be read. Check the form and try again.")
		return
	}
	src, err := feeds.CheckSource(body.Name, body.Path, body.URL, body.Format)
	var invalid *feeds.SourceError
	if errors.As(err, &invalid) {
		writeError(w, http.StatusBadRequest, invalid.Message)
		return
	}
	feed, err := a.Feeds.Add(r.Context(), src)
	if errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, "A feed with that name already exists.")
		return
	}
	if err != nil {
		a.Logger.Error("add feed failed", "feed", src.Name, "error", err.Error())
		writeError(w, http.StatusInternalServerError, "The feed could not be added.")
		return
	}
	if !a.consoleOwnsFeeds(w, r, sess) {
		return
	}
	_ = a.Store.InsertAudit(r.Context(), store.AuditEvent{
		Username: sess.Username, Action: "feed_create", ObjectType: "feed",
		ObjectID: feed.Name, Result: "success",
	})
	writeJSON(w, http.StatusCreated, map[string]any{"feed": toFeed(feed)})
}

func (a *API) deleteFeed(w http.ResponseWriter, r *http.Request) {
	sess, ok := a.require(w, r, true)
	if !ok {
		return
	}
	id, ok := pathID(w, r, "That feed id is not valid.")
	if !ok {
		return
	}
	feed, err := a.Feeds.Remove(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "That feed is no longer there.")
		return
	}
	if err != nil {
		a.Logger.Error("remove feed failed", "feed_id", id, "error", err.Error())
		writeError(w, http.StatusInternalServerError, "The feed was removed, but the filter did not pick it up. Restart the service.")
		return
	}
	if !a.consoleOwnsFeeds(w, r, sess) {
		return
	}
	_ = a.Store.InsertAudit(r.Context(), store.AuditEvent{
		Username: sess.Username, Action: "feed_delete", ObjectType: "feed",
		ObjectID: feed.Name, Result: "success",
	})
	w.WriteHeader(http.StatusNoContent)
}

// consoleOwnsFeeds records that config.json no longer decides the feed list, so a restart
// keeps console changes instead of copying the file's feeds back.
func (a *API) consoleOwnsFeeds(w http.ResponseWriter, r *http.Request, sess store.Session) bool {
	if err := a.Settings.UseConsoleFeeds(r.Context(), sess.Username); err != nil {
		a.Logger.Error("could not hand the feed list to the console", "error", err.Error())
		writeError(w, http.StatusInternalServerError, "The change was made, but it may be undone at the next restart. Try again.")
		return false
	}
	return true
}

func toUser(u store.User) userJSON {
	return userJSON{ID: u.ID, Username: u.Username, Role: u.Role, MustChangePassword: u.MustChangePassword, CreatedAt: u.CreatedAt}
}

func pathID(w http.ResponseWriter, r *http.Request, message string) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		writeError(w, http.StatusBadRequest, message)
		return 0, false
	}
	return id, true
}
