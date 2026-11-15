// Package policy decides whether a DNS name is allowed, denied, or forwarded.
package policy

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"unicode"

	"golang.org/x/net/idna"
)

const (
	// ActionAllowed means the query is forwarded upstream.
	ActionAllowed = "ALLOWED"
	// ActionBlocked means the filter refuses the name locally.
	ActionBlocked = "BLOCKED"
	// ActionError means the query was not answered normally.
	ActionError = "ERROR"

	// KindAllow and KindDeny are manual rule types.
	KindAllow = "allow"
	KindDeny  = "deny"

	// MatchExact matches one name. MatchSuffix also matches its subdomains.
	MatchExact  = "exact"
	MatchSuffix = "suffix"

	// SourceManual is the matched_source value for a manual rule.
	SourceManual = "manual"
)

// ErrInvalidDomain means the name cannot be used in a comparison.
var ErrInvalidDomain = errors.New("invalid domain")

// Rule is one manual allow or deny entry. Domain may be a presentation name;
// NewSnapshot normalizes it.
type Rule struct {
	ID     int64
	Domain string
	Kind   string
	Match  string
}

// FeedRule is one name loaded from a threat feed. Feeds match as suffixes.
type FeedRule struct {
	Name   string
	Domain string
}

// Decision is the filter outcome for one normalized name.
//
// An allow rule that overrides a deny or a feed is ActionAllowed with
// MatchedSource set to "manual". The event schema uses ALLOWED, BLOCKED,
// and ERROR; the allow exception is visible from that source and domain.
type Decision struct {
	Action        string
	Forward       bool
	Invalid       bool
	MatchedSource string
	MatchedDomain string
}

// Snapshot is an immutable copy of the rules used for one generation of decisions.
type Snapshot struct {
	allowExact  map[string]Rule
	allowSuffix map[string]Rule
	denyExact   map[string]Rule
	denySuffix  map[string]Rule
	feedSuffix  map[string]FeedRule
}

// Engine publishes snapshots to concurrent DNS handlers without restarting them.
type Engine struct {
	current atomic.Pointer[Snapshot]
}

// NewEngine returns an engine that forwards every name until Replace is called.
func NewEngine() *Engine {
	e := &Engine{}
	snap, err := NewSnapshot(nil, nil)
	if err != nil {
		panic(err)
	}
	e.Replace(snap)
	return e
}

// Replace installs a new snapshot. Later decisions see it immediately.
func (e *Engine) Replace(s *Snapshot) {
	if s == nil {
		s, _ = NewSnapshot(nil, nil)
	}
	e.current.Store(s)
}

// Decide normalizes name and applies allow, manual deny, then feed deny.
func (e *Engine) Decide(name string) Decision {
	s := e.current.Load()
	if s == nil {
		s, _ = NewSnapshot(nil, nil)
	}
	return s.Decide(name)
}

// NewSnapshot builds a snapshot. Invalid rule or feed names are an error.
// When two feeds contain the same name, the first one is kept.
func NewSnapshot(rules []Rule, feeds []FeedRule) (*Snapshot, error) {
	s := &Snapshot{
		allowExact:  map[string]Rule{},
		allowSuffix: map[string]Rule{},
		denyExact:   map[string]Rule{},
		denySuffix:  map[string]Rule{},
		feedSuffix:  map[string]FeedRule{},
	}
	for _, rule := range rules {
		domain, err := Normalize(rule.Domain)
		if err != nil {
			return nil, fmt.Errorf("policy: rule %d: %w", rule.ID, err)
		}
		rule.Domain = domain
		switch {
		case rule.Kind == KindAllow && rule.Match == MatchExact:
			s.allowExact[domain] = rule
		case rule.Kind == KindAllow && rule.Match == MatchSuffix:
			s.allowSuffix[domain] = rule
		case rule.Kind == KindDeny && rule.Match == MatchExact:
			s.denyExact[domain] = rule
		case rule.Kind == KindDeny && rule.Match == MatchSuffix:
			s.denySuffix[domain] = rule
		default:
			return nil, fmt.Errorf("policy: rule %d has type %q and match %q", rule.ID, rule.Kind, rule.Match)
		}
	}
	for _, feed := range feeds {
		domain, err := Normalize(feed.Domain)
		if err != nil {
			return nil, fmt.Errorf("policy: feed %s: %w", feed.Name, err)
		}
		if _, exists := s.feedSuffix[domain]; exists {
			continue
		}
		feed.Domain = domain
		s.feedSuffix[domain] = feed
	}
	return s, nil
}

// Decide reports the highest-precedence match for an already comparable name.
// Malformed names set Invalid and are not compared against block rules.
func (s *Snapshot) Decide(name string) Decision {
	normalized, err := Normalize(name)
	if err != nil {
		return Decision{Action: ActionError, Invalid: true}
	}
	if rule, ok := s.allowExact[normalized]; ok {
		return allow(rule)
	}
	if rule, ok := lookup(normalized, s.allowSuffix); ok {
		return allow(rule)
	}
	if rule, ok := s.denyExact[normalized]; ok {
		return blockManual(rule)
	}
	if rule, ok := lookup(normalized, s.denySuffix); ok {
		return blockManual(rule)
	}
	if feed, ok := lookup(normalized, s.feedSuffix); ok {
		return Decision{
			Action:        ActionBlocked,
			MatchedSource: feed.Name,
			MatchedDomain: feed.Domain,
		}
	}
	return Decision{Action: ActionAllowed, Forward: true}
}

func allow(rule Rule) Decision {
	return Decision{
		Action:        ActionAllowed,
		Forward:       true,
		MatchedSource: SourceManual,
		MatchedDomain: rule.Domain,
	}
}

func blockManual(rule Rule) Decision {
	return Decision{
		Action:        ActionBlocked,
		MatchedSource: SourceManual,
		MatchedDomain: rule.Domain,
	}
}

func lookup[T any](name string, rules map[string]T) (T, bool) {
	for name != "" {
		if v, ok := rules[name]; ok {
			return v, true
		}
		dot := strings.IndexByte(name, '.')
		if dot < 0 || dot == len(name)-1 {
			break
		}
		name = name[dot+1:]
	}
	var zero T
	return zero, false
}

// Normalize strips one trailing dot, maps IDNA to ASCII, and lowercases.
// A name that cannot be compared returns ErrInvalidDomain.
func Normalize(name string) (string, error) {
	name = strings.TrimSpace(name)
	if strings.HasSuffix(name, ".") {
		name = strings.TrimSuffix(name, ".")
	}
	if name == "" || strings.Contains(name, "..") {
		return "", ErrInvalidDomain
	}
	ascii, err := idna.Lookup.ToASCII(name)
	if err != nil {
		if !isASCII(name) || !validDomain(strings.ToLower(name)) {
			return "", ErrInvalidDomain
		}
		ascii = strings.ToLower(name)
	}
	ascii = strings.ToLower(ascii)
	if net.ParseIP(ascii) != nil || !validDomain(ascii) {
		return "", ErrInvalidDomain
	}
	return ascii, nil
}

func isASCII(s string) bool {
	for _, r := range s {
		if r > unicode.MaxASCII {
			return false
		}
	}
	return true
}

func validDomain(name string) bool {
	if name == "" || len(name) > 253 || strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if !validLabel(label) {
			return false
		}
	}
	return true
}

func validLabel(label string) bool {
	if label == "" || len(label) > 63 {
		return false
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '_':
		case c == '-':
			if i == 0 || i == len(label)-1 {
				return false
			}
		default:
			return false
		}
	}
	return true
}
