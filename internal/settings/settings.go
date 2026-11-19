// Package settings holds the operator-tunable values. Values saved from the console live in
// SQLite and win over config.json; anything never saved falls back to the file.
package settings

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"dnsfilter/internal/config"
	"dnsfilter/internal/store"
)

// Logging modes for query events. Counters are kept in every mode.
const (
	LogAll     = "all"
	LogBlocked = "blocked"
	LogNone    = "none"
)

// Where the feed list comes from. The console takes over after its first add or delete.
const (
	FeedsFromFile    = "file"
	FeedsFromConsole = "console"
)

// Keys in the settings table.
const (
	KeyBlockedRCode    = "blocked_rcode"
	KeyUpstream        = "upstream"
	KeyUpstreamTimeout = "upstream_timeout_seconds"
	KeyRetention       = "retention_days"
	KeySyncInterval    = "feed_sync_interval_hours"
	KeyLogMode         = "log_mode"
	KeyFeedsSource     = "feeds_source"
)

// Values is the effective configuration the filter runs with.
type Values struct {
	BlockedRCode    string
	Upstream        string
	UpstreamTimeout time.Duration
	Retention       time.Duration
	SyncInterval    time.Duration
	LogMode         string
	FeedsSource     string
}

// KeepEvent reports whether a query with this action should be stored as a log row.
func (v Values) KeepEvent(action string) bool {
	switch v.LogMode {
	case LogNone:
		return false
	case LogBlocked:
		return action == "BLOCKED"
	default:
		return true
	}
}

// Defaults are the values taken from config.json.
func Defaults(cfg *config.Config) Values {
	return Values{
		BlockedRCode:    cfg.DNS.BlockedRCode,
		Upstream:        cfg.DNS.Upstream,
		UpstreamTimeout: cfg.DNS.UpstreamTimeout,
		Retention:       cfg.Logging.Retention,
		SyncInterval:    cfg.Feeds.SyncInterval,
		LogMode:         LogAll,
		FeedsSource:     FeedsFromFile,
	}
}

// Patch carries the fields an operator submitted. Nil fields are left alone.
type Patch struct {
	BlockedRCode           *string
	Upstream               *string
	UpstreamTimeoutSeconds *int
	RetentionDays          *int
	SyncIntervalHours      *int
	LogMode                *string
}

// Error is a rejected value. Message is written for the person who typed it.
type Error struct {
	Field   string
	Message string
}

func (e *Error) Error() string { return e.Message }

// Service serves the current values and saves changes. Readers never block.
type Service struct {
	store    *store.Store
	defaults Values
	mu       sync.Mutex
	state    atomic.Pointer[state]
}

type state struct {
	values  Values
	saved   map[string]store.Setting
	changed chan struct{}
}

// Load reads saved values over the defaults. A saved value that no longer validates is ignored.
func Load(ctx context.Context, st *store.Store, defaults Values) (*Service, error) {
	saved, err := st.ListSettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("settings: load: %w", err)
	}
	s := &Service{store: st, defaults: defaults}
	s.state.Store(&state{values: merge(defaults, saved), saved: saved, changed: make(chan struct{})})
	return s, nil
}

// Current returns the effective values.
func (s *Service) Current() Values {
	return s.state.Load().values
}

// Defaults returns the values from config.json.
func (s *Service) Defaults() Values {
	return s.defaults
}

// Saved returns the values stored from the console, keyed by setting name.
func (s *Service) Saved() map[string]store.Setting {
	saved := s.state.Load().saved
	out := make(map[string]store.Setting, len(saved))
	for k, v := range saved {
		out[k] = v
	}
	return out
}

// Changed returns a channel that is closed at the next successful update.
func (s *Service) Changed() <-chan struct{} {
	return s.state.Load().changed
}

// Update validates and saves the submitted fields that differ from the current values.
// It returns the keys that changed.
func (s *Service) Update(ctx context.Context, p Patch, username string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur := s.state.Load().values
	values, err := p.encode(cur)
	if err != nil {
		return nil, err
	}
	return s.save(ctx, values, username)
}

// UseConsoleFeeds records that the console now owns the feed list.
func (s *Service) UseConsoleFeeds(ctx context.Context, username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Load().values.FeedsSource == FeedsFromConsole {
		return nil
	}
	_, err := s.save(ctx, map[string]string{KeyFeedsSource: FeedsFromConsole}, username)
	return err
}

func (s *Service) save(ctx context.Context, values map[string]string, username string) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	if err := s.store.SaveSettings(ctx, values, username); err != nil {
		return nil, fmt.Errorf("settings: save: %w", err)
	}
	saved, err := s.store.ListSettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("settings: reload: %w", err)
	}
	old := s.state.Load()
	s.state.Store(&state{values: merge(s.defaults, saved), saved: saved, changed: make(chan struct{})})
	close(old.changed)
	keys := make([]string, 0, len(values))
	for _, key := range orderedKeys {
		if _, ok := values[key]; ok {
			keys = append(keys, key)
		}
	}
	return keys, nil
}

var orderedKeys = []string{
	KeyBlockedRCode, KeyUpstream, KeyUpstreamTimeout, KeyRetention, KeySyncInterval, KeyLogMode, KeyFeedsSource,
}

func (p Patch) encode(cur Values) (map[string]string, error) {
	out := map[string]string{}
	if p.BlockedRCode != nil {
		code := strings.ToUpper(strings.TrimSpace(*p.BlockedRCode))
		if !config.ValidBlockedRCode(code) {
			return nil, &Error{KeyBlockedRCode, "Blocked answer must be REFUSED, NXDOMAIN, or SERVFAIL."}
		}
		if code != cur.BlockedRCode {
			out[KeyBlockedRCode] = code
		}
	}
	if p.Upstream != nil {
		addr := strings.TrimSpace(*p.Upstream)
		if err := config.CheckHostPort(addr); err != nil {
			return nil, &Error{KeyUpstream, "Upstream resolver " + err.Error() + "."}
		}
		if addr != cur.Upstream {
			out[KeyUpstream] = addr
		}
	}
	if err := intField(out, KeyUpstreamTimeout, "Upstream timeout", "seconds", p.UpstreamTimeoutSeconds,
		config.MinUpstreamTimeoutSeconds, config.MaxUpstreamTimeoutSeconds, int(cur.UpstreamTimeout/time.Second)); err != nil {
		return nil, err
	}
	if err := intField(out, KeyRetention, "Log retention", "days", p.RetentionDays,
		config.MinRetentionDays, config.MaxRetentionDays, int(cur.Retention/(24*time.Hour))); err != nil {
		return nil, err
	}
	if err := intField(out, KeySyncInterval, "Feed sync interval", "hours", p.SyncIntervalHours,
		config.MinSyncIntervalHours, config.MaxSyncIntervalHours, int(cur.SyncInterval/time.Hour)); err != nil {
		return nil, err
	}
	if p.LogMode != nil {
		mode := strings.ToLower(strings.TrimSpace(*p.LogMode))
		if mode != LogAll && mode != LogBlocked && mode != LogNone {
			return nil, &Error{KeyLogMode, "Logging must be all, blocked, or none."}
		}
		if mode != cur.LogMode {
			out[KeyLogMode] = mode
		}
	}
	return out, nil
}

func intField(out map[string]string, key, label, unit string, v *int, min, max, cur int) error {
	if v == nil {
		return nil
	}
	if *v < min || *v > max {
		return &Error{key, fmt.Sprintf("%s must be between %d and %d %s.", label, min, max, unit)}
	}
	if *v != cur {
		out[key] = strconv.Itoa(*v)
	}
	return nil
}

func merge(v Values, saved map[string]store.Setting) Values {
	if item, ok := saved[KeyBlockedRCode]; ok && config.ValidBlockedRCode(item.Value) {
		v.BlockedRCode = item.Value
	}
	if item, ok := saved[KeyUpstream]; ok && config.CheckHostPort(item.Value) == nil {
		v.Upstream = item.Value
	}
	if n, ok := savedInt(saved, KeyUpstreamTimeout, config.MinUpstreamTimeoutSeconds, config.MaxUpstreamTimeoutSeconds); ok {
		v.UpstreamTimeout = time.Duration(n) * time.Second
	}
	if n, ok := savedInt(saved, KeyRetention, config.MinRetentionDays, config.MaxRetentionDays); ok {
		v.Retention = time.Duration(n) * 24 * time.Hour
	}
	if n, ok := savedInt(saved, KeySyncInterval, config.MinSyncIntervalHours, config.MaxSyncIntervalHours); ok {
		v.SyncInterval = time.Duration(n) * time.Hour
	}
	if item, ok := saved[KeyLogMode]; ok && (item.Value == LogAll || item.Value == LogBlocked || item.Value == LogNone) {
		v.LogMode = item.Value
	}
	if item, ok := saved[KeyFeedsSource]; ok && item.Value == FeedsFromConsole {
		v.FeedsSource = FeedsFromConsole
	}
	return v
}

func savedInt(saved map[string]store.Setting, key string, min, max int) (int, bool) {
	item, ok := saved[key]
	if !ok {
		return 0, false
	}
	n, err := strconv.Atoi(item.Value)
	if err != nil || n < min || n > max {
		return 0, false
	}
	return n, true
}
