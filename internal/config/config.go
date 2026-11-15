// Package config reads and validates the DNS Filter JSON configuration.
package config

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Allowed blocked response codes. REFUSED is the demonstration default.
var blockedRCodes = map[string]struct{}{
	"REFUSED":  {},
	"SERVFAIL": {},
	"NXDOMAIN": {},
}

// Config is the validated runtime configuration.
// Paths are absolute. Durations are already converted from the JSON numbers.
type Config struct {
	File     string
	Dir      string
	DNS      DNS
	HTTP     HTTP
	Database Database
	Logging  Logging
	Feeds    Feeds
}

// DNS holds the data-plane listen and upstream settings.
type DNS struct {
	ListenUDP       string
	ListenTCP       string
	Upstream        string
	UpstreamTimeout time.Duration
	BlockedRCode    string
}

// HTTP holds the management listener. It defaults to loopback in the example config.
type HTTP struct {
	Listen string
}

// Database holds the SQLite file path.
type Database struct {
	Path string
}

// Logging holds query-log retention.
type Logging struct {
	Retention time.Duration
}

// Feeds holds the sync interval and the configured sources.
type Feeds struct {
	SyncInterval time.Duration
	Sources      []FeedSource
}

// FeedSource is one threat-intelligence list.
// Exactly one of Path or URL is set. Path is absolute.
type FeedSource struct {
	Name   string
	Path   string
	URL    string
	Format string
}

// Origin is the path or URL the operator configured, for display and logs.
func (f FeedSource) Origin() string {
	if f.URL != "" {
		return f.URL
	}
	return f.Path
}

type fileConfig struct {
	DNS struct {
		ListenUDP              string `json:"listen_udp"`
		ListenTCP              string `json:"listen_tcp"`
		Upstream               string `json:"upstream"`
		UpstreamTimeoutSeconds int    `json:"upstream_timeout_seconds"`
		BlockedRCode           string `json:"blocked_rcode"`
	} `json:"dns"`
	HTTP struct {
		Listen string `json:"listen"`
	} `json:"http"`
	Database struct {
		Path string `json:"path"`
	} `json:"database"`
	Logging struct {
		RetentionDays int `json:"retention_days"`
	} `json:"logging"`
	Feeds struct {
		SyncIntervalHours int `json:"sync_interval_hours"`
		Sources           []struct {
			Name   string `json:"name"`
			Path   string `json:"path,omitempty"`
			URL    string `json:"url,omitempty"`
			Format string `json:"format"`
		} `json:"sources"`
	} `json:"feeds"`
}

// Load reads path and returns a validated configuration.
// Relative feed and database paths are resolved against the configuration file's directory.
func Load(path string) (*Config, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("config: resolve path: %w", err)
	}
	raw, err := os.ReadFile(abs)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", abs, err)
	}

	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	var file fileConfig
	if err := dec.Decode(&file); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", abs, err)
	}
	var extra any
	if err := dec.Decode(&extra); err != nil && err.Error() != "EOF" {
		return nil, fmt.Errorf("config: parse %s: %w", abs, err)
	}

	cfg := &Config{
		File: abs,
		Dir:  filepath.Dir(abs),
		DNS: DNS{
			ListenUDP:       strings.TrimSpace(file.DNS.ListenUDP),
			ListenTCP:       strings.TrimSpace(file.DNS.ListenTCP),
			Upstream:        strings.TrimSpace(file.DNS.Upstream),
			UpstreamTimeout: time.Duration(file.DNS.UpstreamTimeoutSeconds) * time.Second,
			BlockedRCode:    strings.ToUpper(strings.TrimSpace(file.DNS.BlockedRCode)),
		},
		HTTP: HTTP{Listen: strings.TrimSpace(file.HTTP.Listen)},
		Logging: Logging{
			Retention: time.Duration(file.Logging.RetentionDays) * 24 * time.Hour,
		},
		Feeds: Feeds{
			SyncInterval: time.Duration(file.Feeds.SyncIntervalHours) * time.Hour,
		},
	}

	dbPath := strings.TrimSpace(file.Database.Path)
	if dbPath == "" {
		return nil, fmt.Errorf("config: database.path is required")
	}
	if !filepath.IsAbs(dbPath) {
		dbPath = filepath.Join(cfg.Dir, dbPath)
	}
	cfg.Database.Path = filepath.Clean(dbPath)

	if err := validateNetwork(cfg, file.DNS.UpstreamTimeoutSeconds, file.Logging.RetentionDays, file.Feeds.SyncIntervalHours); err != nil {
		return nil, err
	}

	seen := map[string]struct{}{}
	for i, src := range file.Feeds.Sources {
		name := strings.TrimSpace(src.Name)
		format := strings.ToLower(strings.TrimSpace(src.Format))
		pathVal := strings.TrimSpace(src.Path)
		urlVal := strings.TrimSpace(src.URL)
		if name == "" {
			return nil, fmt.Errorf("config: feeds.sources[%d].name is required", i)
		}
		if _, ok := seen[name]; ok {
			return nil, fmt.Errorf("config: duplicate feed name %q", name)
		}
		seen[name] = struct{}{}
		if !validFeedName(name) {
			return nil, fmt.Errorf("config: feed name %q must start with a letter and contain only letters, digits, hyphens, or underscores", name)
		}
		if format != "domains" && format != "hosts" {
			return nil, fmt.Errorf("config: feed %q format %q is not supported (use domains or hosts)", name, src.Format)
		}
		if (pathVal == "") == (urlVal == "") {
			return nil, fmt.Errorf("config: feed %q must set exactly one of path or url", name)
		}
		if urlVal != "" {
			u, err := url.Parse(urlVal)
			if err != nil || u.Host == "" || u.Scheme != "https" {
				return nil, fmt.Errorf("config: feed %q url must be an https URL", name)
			}
			cfg.Feeds.Sources = append(cfg.Feeds.Sources, FeedSource{
				Name: name, URL: urlVal, Format: format,
			})
			continue
		}
		if !filepath.IsAbs(pathVal) {
			pathVal = filepath.Join(cfg.Dir, pathVal)
		}
		cfg.Feeds.Sources = append(cfg.Feeds.Sources, FeedSource{
			Name: name, Path: filepath.Clean(pathVal), Format: format,
		})
	}
	return cfg, nil
}

func validateNetwork(cfg *Config, timeoutSec, retentionDays, syncHours int) error {
	if err := validateListen("dns.listen_udp", cfg.DNS.ListenUDP); err != nil {
		return err
	}
	if err := validateListen("dns.listen_tcp", cfg.DNS.ListenTCP); err != nil {
		return err
	}
	if err := validateListen("dns.upstream", cfg.DNS.Upstream); err != nil {
		return err
	}
	if err := validateListen("http.listen", cfg.HTTP.Listen); err != nil {
		return err
	}
	if timeoutSec < 1 || timeoutSec > 30 {
		return fmt.Errorf("config: dns.upstream_timeout_seconds must be between 1 and 30")
	}
	if _, ok := blockedRCodes[cfg.DNS.BlockedRCode]; !ok {
		return fmt.Errorf("config: dns.blocked_rcode must be REFUSED, SERVFAIL, or NXDOMAIN")
	}
	if retentionDays < 1 || retentionDays > 3650 {
		return fmt.Errorf("config: logging.retention_days must be between 1 and 3650")
	}
	if syncHours < 1 || syncHours > 720 {
		return fmt.Errorf("config: feeds.sync_interval_hours must be between 1 and 720")
	}
	return nil
}

func validateListen(field, addr string) error {
	if addr == "" {
		return fmt.Errorf("config: %s is required", field)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("config: %s %q must be host:port", field, addr)
	}
	if !validHost(host) {
		return fmt.Errorf("config: %s host %q is not a valid IP or hostname", field, host)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("config: %s port must be between 1 and 65535", field)
	}
	return nil
}

func validHost(host string) bool {
	if host == "" {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return true
	}
	if len(host) > 253 {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if len(label) < 1 || len(label) > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-'
			if !ok {
				return false
			}
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	return true
}

func validFeedName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	c0 := name[0]
	if !((c0 >= 'a' && c0 <= 'z') || (c0 >= 'A' && c0 <= 'Z')) {
		return false
	}
	for i := 1; i < len(name); i++ {
		c := name[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_'
		if !ok {
			return false
		}
	}
	return true
}

// LoopbackHTTP reports whether the management listener is bound to a loopback address.
func (c *Config) LoopbackHTTP() bool {
	host, _, err := net.SplitHostPort(c.HTTP.Listen)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
