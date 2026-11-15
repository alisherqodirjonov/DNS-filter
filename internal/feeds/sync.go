package feeds

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
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

// Service loads configured feeds into SQLite and notifies the policy engine.
type Service struct {
	Store    *store.Store
	Sources  []config.FeedSource
	Client   *http.Client
	MaxBytes int64
	Timeout  time.Duration
	Logger   *slog.Logger
	OnChange func(context.Context) error
}

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

// SyncAll reloads every configured feed. One failure does not stop the others.
func (s *Service) SyncAll(ctx context.Context) {
	for _, src := range s.Sources {
		if err := s.SyncSource(ctx, src); err != nil && s.Logger != nil {
			s.Logger.Error("feed sync failed", "feed", src.Name, "error", err.Error())
		}
	}
}

// SyncByID reloads one configured feed. The id must belong to a source in the configuration.
func (s *Service) SyncByID(ctx context.Context, id int64) error {
	feed, err := s.Store.FeedByID(ctx, id)
	if err != nil {
		return err
	}
	for _, src := range s.Sources {
		if src.Name == feed.Name {
			return s.SyncSource(ctx, src)
		}
	}
	return fmt.Errorf("feed %q is not in the configuration", feed.Name)
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

// Schedule calls fn on each tick until ctx is cancelled. It does not call fn immediately.
func Schedule(ctx context.Context, every time.Duration, fn func(context.Context)) {
	if every <= 0 {
		every = 24 * time.Hour
	}
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fn(ctx)
		}
	}
}
