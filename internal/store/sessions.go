package store

import (
	"context"
	"database/sql"
	"time"
)

// Session is a server-side login. TokenHash is the SHA-256 of the cookie value.
type Session struct {
	ID                 int64
	UserID             int64
	Username           string
	Role               string
	MustChangePassword bool
	CSRFToken          string
	TokenHash          string
	ExpiresAt          time.Time
}

// CreateSession stores a session. tokenHash must already be hashed.
func (s *Store) CreateSession(ctx context.Context, tokenHash string, userID int64, csrf string, expires time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO sessions(token_hash, user_id, csrf_token, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?)`,
		tokenHash, userID, csrf, formatTime(expires), formatTime(time.Now()))
	if err != nil {
		return err
	}
	return nil
}

// SessionByTokenHash returns a live session. Expired rows are reported as not found.
func (s *Store) SessionByTokenHash(ctx context.Context, tokenHash string, now time.Time) (Session, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT s.id, s.user_id, u.username, u.role, u.must_change_password, s.csrf_token, s.token_hash, s.expires_at
		FROM sessions s
		JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = ? AND s.expires_at > ?`, tokenHash, formatTime(now))
	var sess Session
	var exp string
	var mustChange int
	err := row.Scan(&sess.ID, &sess.UserID, &sess.Username, &sess.Role, &mustChange, &sess.CSRFToken, &sess.TokenHash, &exp)
	sess.MustChangePassword = mustChange == 1
	if err == sql.ErrNoRows {
		return Session{}, ErrNotFound
	}
	if err != nil {
		return Session{}, err
	}
	sess.ExpiresAt, err = parseTime(exp)
	if err != nil {
		return Session{}, err
	}
	return sess, nil
}

// DeleteSession removes a session by token hash. Missing rows are not an error.
func (s *Store) DeleteSession(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, tokenHash)
	return err
}

// DeleteUserSessions ends every session for a user except the one whose hash is keep.
// An empty keep ends them all.
func (s *Store) DeleteUserSessions(ctx context.Context, userID int64, keep string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ? AND token_hash <> ?`, userID, keep)
	return err
}

// DeleteExpiredSessions removes sessions whose expiry is at or before now.
func (s *Store) DeleteExpiredSessions(ctx context.Context, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, formatTime(now))
	return err
}
