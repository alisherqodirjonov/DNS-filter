package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// User is an operator account. The password hash is bcrypt, never the password.
type User struct {
	ID           int64
	Username     string
	PasswordHash string
	Role         string
	CreatedAt    time.Time
}

// CreateUser inserts an account. The caller supplies an already hashed password.
func (s *Store) CreateUser(ctx context.Context, username, passwordHash, role string) (User, error) {
	now := formatTime(time.Now())
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO users(username, password_hash, role, created_at)
		VALUES (?, ?, ?, ?)`, username, passwordHash, role, now)
	if err != nil {
		if isUnique(err) {
			return User{}, fmt.Errorf("%w: user %s", ErrConflict, username)
		}
		return User{}, fmt.Errorf("store: create user: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return User{}, err
	}
	return s.UserByID(ctx, id)
}

// UserCount returns the number of accounts.
func (s *Store) UserCount(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// UserByUsername looks up an account by its unique name.
func (s *Store) UserByUsername(ctx context.Context, username string) (User, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, username, password_hash, role, created_at
		FROM users WHERE username = ?`, username)
	return scanUser(row)
}

// UserByID looks up an account by primary key.
func (s *Store) UserByID(ctx context.Context, id int64) (User, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, username, password_hash, role, created_at
		FROM users WHERE id = ?`, id)
	return scanUser(row)
}

func scanUser(row *sql.Row) (User, error) {
	var u User
	var created string
	err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &created)
	if err == sql.ErrNoRows {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, err
	}
	u.CreatedAt, err = parseTime(created)
	if err != nil {
		return User{}, err
	}
	return u, nil
}
