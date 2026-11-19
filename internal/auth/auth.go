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

	// DefaultAdminUser and DefaultAdminPassword are created on an empty database when no
	// bootstrap environment is set. The account must change its password before anything else.
	DefaultAdminUser     = "admin"
	DefaultAdminPassword = "admin"

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
	// ErrWrongPassword is returned when the current password given for a change is wrong.
	ErrWrongPassword = errors.New("current password is wrong")
	// ErrSelf is returned when an administrator tries to delete or reset their own account.
	ErrSelf = errors.New("use the account page for your own account")
	// ErrLastAdmin is returned when a change would leave no administrator.
	ErrLastAdmin = errors.New("at least one administrator must remain")
)

// InputError is a value the operator needs to correct. Message is written for them.
type InputError struct{ Message string }

func (e *InputError) Error() string { return e.Message }

// Result is a successful sign-in. Token is the raw cookie value and is not stored.
type Result struct {
	Token              string
	CSRF               string
	Username           string
	Role               string
	MustChangePassword bool
	Expires            time.Time
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

// Bootstrap creates the first accounts when the user table is empty. With no admin values it
// creates admin/admin, which must change its password at first sign-in. Later startups ignore
// the values. Passwords are never written to the log.
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
	if (adminUser == "") != (adminPass == "") {
		return errors.New("set both DNSFILTER_BOOTSTRAP_ADMIN_USER and DNSFILTER_BOOTSTRAP_ADMIN_PASSWORD, or leave both unset")
	}
	if (analystUser == "") != (analystPass == "") {
		return errors.New("set both DNSFILTER_BOOTSTRAP_ANALYST_USER and DNSFILTER_BOOTSTRAP_ANALYST_PASSWORD, or leave both unset")
	}
	if adminUser != "" {
		if err := checkPassword(adminPass); err != nil {
			return fmt.Errorf("bootstrap admin: %w", err)
		}
	}
	if analystUser != "" {
		if err := checkPassword(analystPass); err != nil {
			return fmt.Errorf("bootstrap analyst: %w", err)
		}
	}
	if adminUser == "" {
		if err := s.createUser(ctx, DefaultAdminUser, DefaultAdminPassword, RoleAdmin, true); err != nil {
			return err
		}
		s.Logger.Warn("created the default administrator; sign in as admin with password admin and choose a new password",
			"username", DefaultAdminUser)
	} else {
		if err := s.createUser(ctx, adminUser, adminPass, RoleAdmin, false); err != nil {
			return err
		}
		s.Logger.Info("created bootstrap user", "username", adminUser, "role", RoleAdmin)
	}
	if analystUser == "" {
		return nil
	}
	if err := s.createUser(ctx, analystUser, analystPass, RoleAnalyst, false); err != nil {
		return err
	}
	s.Logger.Info("created bootstrap user", "username", analystUser, "role", RoleAnalyst)
	return nil
}

// ChangePassword replaces the signed-in user's password after checking the current one.
// Every other session for the account is ended; the one making the change stays open.
func (s *Service) ChangePassword(ctx context.Context, sess store.Session, current, next string) error {
	key := "password:" + sess.Username
	now := s.Now()
	if !s.limiter.allow(key, now) {
		_ = s.audit(ctx, sess.Username, "password_change", "user", sess.Username, "rate_limited")
		return ErrRateLimited
	}
	user, err := s.Store.UserByID(ctx, sess.UserID)
	if err != nil {
		return err
	}
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(current)) != nil {
		s.limiter.fail(key, now)
		_ = s.audit(ctx, sess.Username, "password_change", "user", sess.Username, "failure")
		return ErrWrongPassword
	}
	if err := checkPassword(next); err != nil {
		return err
	}
	if next == current {
		return &InputError{"Choose a password that is different from the current one."}
	}
	if err := s.setPassword(ctx, user.ID, next, false, sess.TokenHash); err != nil {
		return err
	}
	return s.audit(ctx, sess.Username, "password_change", "user", sess.Username, "success")
}

// CreateAccount adds an account with a temporary password the user must change at first sign-in.
func (s *Service) CreateAccount(ctx context.Context, actor store.Session, username, password, role string) (store.User, error) {
	username = strings.TrimSpace(username)
	if !validUsername(username) {
		return store.User{}, &InputError{"Usernames are 1 to 64 letters, digits, dots, hyphens, or underscores."}
	}
	if role != RoleAdmin && role != RoleAnalyst {
		return store.User{}, &InputError{"Role must be admin or analyst."}
	}
	if err := checkPassword(password); err != nil {
		return store.User{}, err
	}
	if err := s.createUser(ctx, username, password, role, true); err != nil {
		return store.User{}, err
	}
	user, err := s.Store.UserByUsername(ctx, username)
	if err != nil {
		return store.User{}, err
	}
	_ = s.audit(ctx, actor.Username, "user_create", "user", username, "success")
	return user, nil
}

// ResetPassword gives another account a temporary password and signs it out everywhere.
func (s *Service) ResetPassword(ctx context.Context, actor store.Session, id int64, password string) (store.User, error) {
	if id == actor.UserID {
		return store.User{}, ErrSelf
	}
	if err := checkPassword(password); err != nil {
		return store.User{}, err
	}
	user, err := s.Store.UserByID(ctx, id)
	if err != nil {
		return store.User{}, err
	}
	if err := s.setPassword(ctx, id, password, true, ""); err != nil {
		return store.User{}, err
	}
	_ = s.audit(ctx, actor.Username, "password_reset", "user", user.Username, "success")
	return user, nil
}

// DeleteAccount removes another account. The last administrator cannot be removed.
func (s *Service) DeleteAccount(ctx context.Context, actor store.Session, id int64) (store.User, error) {
	if id == actor.UserID {
		return store.User{}, ErrSelf
	}
	user, err := s.Store.UserByID(ctx, id)
	if err != nil {
		return store.User{}, err
	}
	if user.Role == RoleAdmin {
		admins, err := s.Store.AdminCount(ctx)
		if err != nil {
			return store.User{}, err
		}
		if admins <= 1 {
			return store.User{}, ErrLastAdmin
		}
	}
	if err := s.Store.DeleteUser(ctx, id); err != nil {
		return store.User{}, err
	}
	_ = s.audit(ctx, actor.Username, "user_delete", "user", user.Username, "success")
	return user, nil
}

func (s *Service) setPassword(ctx context.Context, id int64, password string, mustChange bool, keepSession string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	if err := s.Store.SetPassword(ctx, id, string(hash), mustChange); err != nil {
		return err
	}
	return s.Store.DeleteUserSessions(ctx, id, keepSession)
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
	return Result{
		Token: token, CSRF: csrf, Username: user.Username, Role: user.Role,
		MustChangePassword: user.MustChangePassword, Expires: expires,
	}, nil
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

func (s *Service) createUser(ctx context.Context, username, password, role string, mustChange bool) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = s.Store.CreateUser(ctx, username, string(hash), role, mustChange)
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

// checkPassword applies the password rules. bcrypt reads at most 72 bytes.
func checkPassword(password string) error {
	if len(password) < 8 {
		return &InputError{"Passwords must be at least 8 characters."}
	}
	if len(password) > 72 {
		return &InputError{"Passwords can be at most 72 characters."}
	}
	return nil
}

func validUsername(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_'
		if !ok {
			return false
		}
	}
	return true
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
