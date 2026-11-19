package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// User is an operator account. The password hash is bcrypt, never the password.
// MustChangePassword is set for the default account and for temporary passwords.
type User struct {
	ID                 int64
	Username           string
	PasswordHash       string
	Role               string
	MustChangePassword bool
	CreatedAt          time.Time
}

// CreateUser inserts an account. The caller supplies an already hashed password.
func (s *Store) CreateUser(ctx context.Context, username, passwordHash, role string, mustChange bool) (User, error) {
	now := formatTime(time.Now())
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO users(username, password_hash, role, must_change_password, created_at)
		VALUES (?, ?, ?, ?, ?)`, username, passwordHash, role, boolInt(mustChange), now)
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

// AdminCount returns the number of administrator accounts.
func (s *Store) AdminCount(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role = 'admin'`).Scan(&n)
	return n, err
}

// UserByUsername looks up an account by its unique name.
func (s *Store) UserByUsername(ctx context.Context, username string) (User, error) {
	return scanUser(s.db.QueryRowContext(ctx, userSelect+` WHERE username = ?`, username).Scan)
}

// UserByID looks up an account by primary key.
func (s *Store) UserByID(ctx context.Context, id int64) (User, error) {
	return scanUser(s.db.QueryRowContext(ctx, userSelect+` WHERE id = ?`, id).Scan)
}

// ListUsers returns every account in name order.
func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, userSelect+` ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// SetPassword replaces an account's password hash and its must-change flag.
func (s *Store) SetPassword(ctx context.Context, id int64, passwordHash string, mustChange bool) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE users SET password_hash = ?, must_change_password = ? WHERE id = ?`,
		passwordHash, boolInt(mustChange), id)
	if err != nil {
		return err
	}
	return requireRow(res)
}

// DeleteUser removes an account. Its sessions go with it.
func (s *Store) DeleteUser(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return err
	}
	return requireRow(res)
}

const userSelect = `
	SELECT id, username, password_hash, role, must_change_password, created_at
	FROM users`

func scanUser(scan func(dest ...any) error) (User, error) {
	var u User
	var created string
	var mustChange int
	err := scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &mustChange, &created)
	if err == sql.ErrNoRows {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, err
	}
	u.MustChangePassword = mustChange == 1
	u.CreatedAt, err = parseTime(created)
	if err != nil {
		return User{}, err
	}
	return u, nil
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func requireRow(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
