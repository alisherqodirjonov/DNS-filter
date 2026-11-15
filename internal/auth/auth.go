// Package auth covers passwords, sessions, and the bootstrap accounts.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"dnsfilter/internal/store"
)

const (
	RoleAdmin   = "admin"
	RoleAnalyst = "analyst"

	// SessionTTL is how long a browser session stays valid.
	SessionTTL = 12 * time.Hour
	// CookieName is the HttpOnly session cookie.
	CookieName = "dnsfilter_session"
	// CSRFHeader is required on state-changing requests.
	CSRFHeader = "X-CSRF-Token"

	maxFailures = 5
	failWindow  = 10 * time.Minute
)

var (
	// ErrCredentials is returned for an unknown user or a wrong password.
	ErrCredentials = errors.New("invalid username or password")
	// ErrRateLimited is returned when a client has failed too many sign-ins.
	ErrRateLimited = errors.New("too many login attempts")
	// ErrUnauthenticated means the session is missing or expired.
	ErrUnauthenticated = errors.New("authentication required")
)

// Result is a successful sign-in. Token is the raw cookie value and is not stored.
type Result struct {
	Token    string
	CSRF     string
	Username string
	Role     string
	Expires  time.Time
}

// Service is the authentication boundary used by the HTTP API.
type Service struct {
	Store  *store.Store
	Logger *slog.Logger
	Now    func() time.Time

	limiter *limiter
	dummy   []byte
}

// New prepares the service. Password comparisons for unknown users use a dummy hash.
func New(st *store.Store, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	dummy, err := bcrypt.GenerateFromPassword([]byte("not-a-real-password"), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	return &Service{
		Store:   st,
		Logger:  logger,
		Now:     time.Now,
		limiter: newLimiter(),
		dummy:   dummy,
	}
}

// Bootstrap creates the first admin, and optionally an analyst, when the user table is empty.
// Later startups ignore the bootstrap values. Passwords are never written to the log.
func (s *Service) Bootstrap(ctx context.Context, adminUser, adminPass, analystUser, analystPass string) error {
	count, err := s.Store.UserCount(ctx)
	if err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	adminUser = strings.TrimSpace(adminUser)
	analystUser = strings.TrimSpace(analystUser)
	if adminUser == "" || adminPass == "" {
		return errors.New("the database has no users. Set DNSFILTER_BOOTSTRAP_ADMIN_USER and DNSFILTER_BOOTSTRAP_ADMIN_PASSWORD, then start again")
	}
	if err := validatePassword(adminPass); err != nil {
		return fmt.Errorf("bootstrap admin: %w", err)
	}
	if (analystUser == "") != (analystPass == "") {
		return errors.New("set both DNSFILTER_BOOTSTRAP_ANALYST_USER and DNSFILTER_BOOTSTRAP_ANALYST_PASSWORD, or leave both unset")
	}
	if analystUser != "" {
		if err := validatePassword(analystPass); err != nil {
			return fmt.Errorf("bootstrap analyst: %w", err)
		}
	}
	if err := s.createUser(ctx, adminUser, adminPass, RoleAdmin); err != nil {
		return err
	}
	s.Logger.Info("created bootstrap user", "username", adminUser, "role", RoleAdmin)
	if analystUser == "" {
		return nil
	}
	if err := s.createUser(ctx, analystUser, analystPass, RoleAnalyst); err != nil {
		return err
	}
	s.Logger.Info("created bootstrap user", "username", analystUser, "role", RoleAnalyst)
	return nil
}

// Login checks the password and opens a session.
func (s *Service) Login(ctx context.Context, username, password, clientIP string) (Result, error) {
	username = strings.TrimSpace(username)
	now := s.Now()
	if !s.limiter.allow(clientIP, now) {
		_ = s.audit(ctx, safeName(username), "login_failure", "session", "", "rate_limited")
		return Result{}, ErrRateLimited
	}
	user, err := s.Store.UserByUsername(ctx, username)
	hash := s.dummy
	if err == nil {
		hash = []byte(user.PasswordHash)
	} else if !errors.Is(err, store.ErrNotFound) {
		return Result{}, err
	}
	if bcrypt.CompareHashAndPassword(hash, []byte(password)) != nil || err != nil {
		s.limiter.fail(clientIP, now)
		_ = s.audit(ctx, safeName(username), "login_failure", "session", "", "failure")
		return Result{}, ErrCredentials
	}
	token, err := randomHex(32)
	if err != nil {
		return Result{}, err
	}
	csrf, err := randomHex(32)
	if err != nil {
		return Result{}, err
	}
	expires := now.Add(SessionTTL)
	if err := s.Store.CreateSession(ctx, HashToken(token), user.ID, csrf, expires); err != nil {
		return Result{}, err
	}
	_ = s.audit(ctx, user.Username, "login_success", "session", "", "success")
	return Result{Token: token, CSRF: csrf, Username: user.Username, Role: user.Role, Expires: expires}, nil
}

// Session returns the live session for a raw cookie token.
func (s *Service) Session(ctx context.Context, rawToken string) (store.Session, error) {
	if rawToken == "" {
		return store.Session{}, ErrUnauthenticated
	}
	sess, err := s.Store.SessionByTokenHash(ctx, HashToken(rawToken), s.Now())
	if errors.Is(err, store.ErrNotFound) {
		return store.Session{}, ErrUnauthenticated
	}
	return sess, err
}

// Logout deletes the session and writes an audit row when the token was valid.
func (s *Service) Logout(ctx context.Context, rawToken string) error {
	if rawToken == "" {
		return nil
	}
	sess, err := s.Session(ctx, rawToken)
	if err := s.Store.DeleteSession(ctx, HashToken(rawToken)); err != nil {
		return err
	}
	if err == nil {
		_ = s.audit(ctx, sess.Username, "logout", "session", "", "success")
	}
	return nil
}

// HashToken is the SHA-256 hex digest stored in SQLite.
func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func (s *Service) createUser(ctx context.Context, username, password, role string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = s.Store.CreateUser(ctx, username, string(hash), role)
	return err
}

func (s *Service) audit(ctx context.Context, username, action, objectType, objectID, result string) error {
	return s.Store.InsertAudit(ctx, store.AuditEvent{
		Username:   username,
		Action:     action,
		ObjectType: objectType,
		ObjectID:   objectID,
		Result:     result,
	})
}

func validatePassword(password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	return nil
}

func safeName(username string) string {
	username = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, username)
	if len(username) > 64 {
		username = username[:64]
	}
	if username == "" {
		return "unknown"
	}
	return username
}

func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// TokensEqual compares two secret strings without leaking the match through timing.
func TokensEqual(a, b string) bool {
	if len(a) != len(b) || a == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

type limiter struct {
	mu   sync.Mutex
	hits map[string][]time.Time
}

func newLimiter() *limiter {
	return &limiter{hits: map[string][]time.Time{}}
}

func (l *limiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.hits[key] = recent(l.hits[key], now)
	return len(l.hits[key]) < maxFailures
}

func (l *limiter) fail(key string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.hits[key] = append(recent(l.hits[key], now), now)
}

func recent(times []time.Time, now time.Time) []time.Time {
	cutoff := now.Add(-failWindow)
	out := times[:0]
	for _, ts := range times {
		if ts.After(cutoff) {
			out = append(out, ts)
		}
	}
	return out
}
