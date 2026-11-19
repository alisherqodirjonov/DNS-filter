package feeds

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"dnsfilter/internal/config"
	"dnsfilter/internal/store"
)

const (
	// MaxBytes is the largest feed body the loader will accept.
	MaxBytes int64 = 10 << 20
	// DefaultTimeout bounds an HTTPS feed download.
	DefaultTimeout = 30 * time.Second
)

// Service loads feeds into SQLite and notifies the policy engine.
// The feeds table is the list that gets synced. Sources is the config.json list that
// Reconcile copies into it.
type Service struct {
	Store    *store.Store
	Sources  []config.FeedSource
	Client   *http.Client
	MaxBytes int64
	Timeout  time.Duration
	Logger   *slog.Logger
	OnChange func(context.Context) error
}

// SourceError is a feed definition the operator needs to correct.
type SourceError struct{ Message string }

func (e *SourceError) Error() string { return e.Message }

// Reconcile makes the feeds table match the configuration.
// Feeds removed from the configuration are deleted, along with their domains.
func (s *Service) Reconcile(ctx context.Context) error {
	names := make([]string, 0, len(s.Sources))
	for _, src := range s.Sources {
		if _, err := s.Store.UpsertFeed(ctx, src.Name, src.Origin(), src.Format); err != nil {
			return err
		}
		names = append(names, src.Name)
	}
	return s.Store.DeleteFeedsNotNamed(ctx, names)
}

// SyncAll reloads every feed in the table. One failure does not stop the others.
func (s *Service) SyncAll(ctx context.Context) {
	list, err := s.Store.ListFeeds(ctx)
	if err != nil {
		if s.Logger != nil && ctx.Err() == nil {
			s.Logger.Error("could not list feeds", "error", err.Error())
		}
		return
	}
	for _, feed := range list {
		if err := s.SyncSource(ctx, sourceOf(feed)); err != nil && s.Logger != nil {
			s.Logger.Error("feed sync failed", "feed", feed.Name, "error", err.Error())
		}
	}
}

// SyncByID reloads one feed.
func (s *Service) SyncByID(ctx context.Context, id int64) error {
	feed, err := s.Store.FeedByID(ctx, id)
	if err != nil {
		return err
	}
	return s.SyncSource(ctx, sourceOf(feed))
}

// CheckSource validates a feed typed into the console. Exactly one of path or url is set;
// a path must be absolute because there is no config file to resolve it against.
func CheckSource(name, path, rawURL, format string) (config.FeedSource, error) {
	name = strings.TrimSpace(name)
	path = strings.TrimSpace(path)
	rawURL = strings.TrimSpace(rawURL)
	format = strings.ToLower(strings.TrimSpace(format))
	if !config.ValidFeedName(name) {
		return config.FeedSource{}, &SourceError{"Name must start with a letter and use only letters, digits, hyphens, or underscores (64 at most)."}
	}
	if format != FormatDomains && format != FormatHosts {
		return config.FeedSource{}, &SourceError{"Format must be domains or hosts."}
	}
	if (path == "") == (rawURL == "") {
		return config.FeedSource{}, &SourceError{"Give either a file path or an https URL."}
	}
	if rawURL != "" {
		u, err := url.Parse(rawURL)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return config.FeedSource{}, &SourceError{"The URL must start with https://."}
		}
		return config.FeedSource{Name: name, URL: rawURL, Format: format}, nil
	}
	if !filepath.IsAbs(path) {
		return config.FeedSource{}, &SourceError{"The file path must be absolute, like /etc/dnsfilter/list.txt."}
	}
	return config.FeedSource{Name: name, Path: filepath.Clean(path), Format: format}, nil
}

// Add stores a new feed and loads it once. The feed is kept even when that first load
// fails; its status and last error show why. A taken name is store.ErrConflict.
func (s *Service) Add(ctx context.Context, src config.FeedSource) (store.Feed, error) {
	feed, err := s.Store.CreateFeed(ctx, src.Name, src.Origin(), src.Format)
	if err != nil {
		return store.Feed{}, err
	}
	if err := s.SyncSource(ctx, src); err != nil && s.Logger != nil {
		s.Logger.Warn("new feed did not load", "feed", src.Name, "error", err.Error())
	}
	return s.Store.FeedByID(ctx, feed.ID)
}

// Remove deletes a feed and its domains, then rebuilds the policy without them.
func (s *Service) Remove(ctx context.Context, id int64) (store.Feed, error) {
	feed, err := s.Store.FeedByID(ctx, id)
	if err != nil {
		return store.Feed{}, err
	}
	if err := s.Store.DeleteFeed(ctx, id); err != nil {
		return store.Feed{}, err
	}
	if s.OnChange != nil {
		if err := s.OnChange(ctx); err != nil {
			return feed, err
		}
	}
	return feed, nil
}

func sourceOf(feed store.Feed) config.FeedSource {
	src := config.FeedSource{Name: feed.Name, Format: feed.Format}
	if strings.HasPrefix(feed.Source, "https://") {
		src.URL = feed.Source
	} else {
		src.Path = feed.Source
	}
	return src
}

// SyncSource downloads or reads one feed and replaces its domains only after a usable parse.
func (s *Service) SyncSource(ctx context.Context, src config.FeedSource) error {
	feed, err := s.Store.UpsertFeed(ctx, src.Name, src.Origin(), src.Format)
	if err != nil {
		return err
	}
	body, err := s.load(ctx, src)
	if err != nil {
		return s.fail(ctx, feed.ID, err)
	}
	parsed, err := ParseBytes(body, src.Format)
	if err != nil {
		return s.fail(ctx, feed.ID, err)
	}
	if len(parsed.Domains) == 0 && parsed.Rejected > 0 {
		return s.fail(ctx, feed.ID, fmt.Errorf("feed %s contained %d malformed lines and no domains", src.Name, parsed.Rejected))
	}
	if err := s.Store.ReplaceFeedDomains(ctx, feed.ID, parsed.Domains, parsed.Rejected); err != nil {
		return s.fail(ctx, feed.ID, err)
	}
	if s.OnChange != nil {
		if err := s.OnChange(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) fail(ctx context.Context, id int64, cause error) error {
	msg := cause.Error()
	if len(msg) > 500 {
		msg = msg[:500]
	}
	if err := s.Store.MarkFeedError(ctx, id, msg); err != nil && s.Logger != nil {
		s.Logger.Error("could not record feed error", "error", err.Error())
	}
	return cause
}

func (s *Service) load(ctx context.Context, src config.FeedSource) ([]byte, error) {
	if src.URL != "" {
		return s.loadURL(ctx, src.URL)
	}
	if src.Path == "" {
		return nil, fmt.Errorf("feed %s has no path or url", src.Name)
	}
	file, err := os.Open(src.Path)
	if err != nil {
		return nil, fmt.Errorf("open feed %s: %w", src.Name, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat feed %s: %w", src.Name, err)
	}
	if info.Size() > s.maxBytes() {
		return nil, fmt.Errorf("feed %s exceeds %d bytes", src.Name, s.maxBytes())
	}
	return readLimited(file, s.maxBytes())
}

func (s *Service) loadURL(ctx context.Context, raw string) ([]byte, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return nil, fmt.Errorf("feed URL must use https")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/plain")
	resp, err := s.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("download feed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download feed: server returned %s", resp.Status)
	}
	return readLimited(resp.Body, s.maxBytes())
}

func (s *Service) httpClient() *http.Client {
	if s.Client != nil {
		return s.Client
	}
	return NewHTTPClient(s.timeout())
}

func (s *Service) maxBytes() int64 {
	if s.MaxBytes > 0 {
		return s.MaxBytes
	}
	return MaxBytes
}

func (s *Service) timeout() time.Duration {
	if s.Timeout > 0 {
		return s.Timeout
	}
	return DefaultTimeout
}

// NewHTTPClient returns the client used for configured HTTPS feeds.
// Redirects to plain HTTP are refused.
func NewHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:       timeout,
		CheckRedirect: rejectInsecureRedirect,
	}
}

func rejectInsecureRedirect(req *http.Request, via []*http.Request) error {
	if req.URL.Scheme != "https" {
		return fmt.Errorf("feed redirect must stay on https")
	}
	if len(via) >= 3 {
		return fmt.Errorf("feed redirect limit exceeded")
	}
	return nil
}

func readLimited(r io.Reader, max int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > max {
		return nil, fmt.Errorf("feed exceeds %d bytes", max)
	}
	return body, nil
}

// Schedule calls fn once every interval until ctx is cancelled. It does not call fn
// immediately. When changed fires, the interval is read again and the next run moves to
// the last run plus the new interval, so unrelated changes do not push it back.
func Schedule(ctx context.Context, every func() time.Duration, changed func() <-chan struct{}, fn func(context.Context)) {
	last := time.Now()
	for {
		interval := every()
		if interval <= 0 {
			interval = 24 * time.Hour
		}
		var wake <-chan struct{}
		if changed != nil {
			wake = changed()
		}
		timer := time.NewTimer(max(time.Until(last.Add(interval)), 0))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			fn(ctx)
			last = time.Now()
		case <-wake:
			timer.Stop()
		}
	}
}
