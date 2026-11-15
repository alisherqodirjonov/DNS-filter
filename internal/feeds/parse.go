package feeds

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"

	"dnsfilter/internal/policy"
)

const (
	FormatDomains = "domains"
	FormatHosts   = "hosts"
)

// Parsed is one successful read of a feed file.
// Rejected counts lines that were not blank, not comments, and not usable domains.
type Parsed struct {
	Domains  []string
	Rejected int
}

// Parse reads a domains or hosts feed.
// A domains file has one name per line. A hosts file has "0.0.0.0 name" or "127.0.0.1 name".
// Blank lines and lines whose first non-space character is # are ignored.
func Parse(r io.Reader, format string) (Parsed, error) {
	if format != FormatDomains && format != FormatHosts {
		return Parsed{}, fmt.Errorf("feed format %q is not supported", format)
	}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	seen := map[string]struct{}{}
	var parsed Parsed
	for scanner.Scan() {
		domain, skip, malformed := classify(scanner.Text(), format)
		if skip {
			continue
		}
		if malformed {
			parsed.Rejected++
			continue
		}
		normalized, err := policy.Normalize(domain)
		if err != nil {
			parsed.Rejected++
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		parsed.Domains = append(parsed.Domains, normalized)
	}
	if err := scanner.Err(); err != nil {
		return Parsed{}, fmt.Errorf("read feed: %w", err)
	}
	return parsed, nil
}

func classify(line, format string) (domain string, skip, malformed bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return "", true, false
	}
	if format == FormatDomains {
		if strings.ContainsAny(trimmed, " \t") {
			return "", false, true
		}
		return trimmed, false, false
	}
	if idx := strings.IndexByte(trimmed, '#'); idx >= 0 {
		trimmed = strings.TrimSpace(trimmed[:idx])
	}
	if trimmed == "" {
		return "", true, false
	}
	fields := strings.Fields(trimmed)
	if len(fields) != 2 {
		return "", false, true
	}
	if fields[0] != "0.0.0.0" && fields[0] != "127.0.0.1" {
		return "", false, true
	}
	return fields[1], false, false
}

// ParseBytes is a small wrapper used by tests and the loader.
func ParseBytes(body []byte, format string) (Parsed, error) {
	return Parse(bytes.NewReader(body), format)
}
