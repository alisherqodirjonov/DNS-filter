package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// Rule is a manual allow or deny entry.
type Rule struct {
	ID          int64
	Domain      string
	RuleType    string
	MatchType   string
	Description string
	CreatedBy   string
	CreatedAt   time.Time
}

// CreateRule inserts a manual rule. A duplicate domain, type, and match returns ErrConflict.
func (s *Store) CreateRule(ctx context.Context, domain, ruleType, matchType, description, createdBy string) (Rule, error) {
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO rules(domain, rule_type, match_type, description, created_by, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		domain, ruleType, matchType, description, createdBy, formatTime(time.Now()))
	if err != nil {
		if isUnique(err) {
			return Rule{}, fmt.Errorf("%w: rule %s %s %s", ErrConflict, ruleType, matchType, domain)
		}
		return Rule{}, fmt.Errorf("store: create rule: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return Rule{}, err
	}
	return s.RuleByID(ctx, id)
}

// RuleByID loads one rule.
func (s *Store) RuleByID(ctx context.Context, id int64) (Rule, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, domain, rule_type, match_type, description, created_by, created_at
		FROM rules WHERE id = ?`, id)
	return scanRule(row)
}

// ListRules returns manual rules in insertion order.
func (s *Store) ListRules(ctx context.Context) ([]Rule, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, domain, rule_type, match_type, description, created_by, created_at
		FROM rules ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Rule
	for rows.Next() {
		rule, err := scanRuleRows(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rule)
	}
	return out, rows.Err()
}

// DeleteRule removes a manual rule. A missing id returns ErrNotFound.
func (s *Store) DeleteRule(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM rules WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func scanRule(row *sql.Row) (Rule, error) {
	var rule Rule
	var created string
	err := row.Scan(&rule.ID, &rule.Domain, &rule.RuleType, &rule.MatchType, &rule.Description, &rule.CreatedBy, &created)
	if err == sql.ErrNoRows {
		return Rule{}, ErrNotFound
	}
	if err != nil {
		return Rule{}, err
	}
	rule.CreatedAt, err = parseTime(created)
	return rule, err
}

func scanRuleRows(rows *sql.Rows) (Rule, error) {
	var rule Rule
	var created string
	err := rows.Scan(&rule.ID, &rule.Domain, &rule.RuleType, &rule.MatchType, &rule.Description, &rule.CreatedBy, &created)
	if err != nil {
		return Rule{}, err
	}
	rule.CreatedAt, err = parseTime(created)
	return rule, err
}
