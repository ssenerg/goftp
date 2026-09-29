package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/casbin/casbin/v3"
	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

// PgStore is the Postgres Store.
type PgStore struct{ db *pgxpool.Pool }

func NewPgStore(db *pgxpool.Pool) *PgStore { return &PgStore{db: db} }

const userColumns = "id, username, password_hash, must_change_password, created_at"

func scanUser(row pgx.Row) (*User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.MustChangePassword, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &u, err
}

func (s *PgStore) CreateUser(ctx context.Context, username, passwordHash string) (int64, error) {
	var id int64
	err := s.db.QueryRow(ctx,
		"INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id",
		username, passwordHash).Scan(&id)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return 0, ErrExists
	}
	return id, err
}

func (s *PgStore) UserByName(ctx context.Context, username string) (*User, error) {
	return scanUser(s.db.QueryRow(ctx, "SELECT "+userColumns+" FROM users WHERE username = $1", username))
}

func (s *PgStore) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.Query(ctx, "SELECT "+userColumns+" FROM users ORDER BY username")
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (User, error) {
		u, err := scanUser(row)
		if err != nil {
			return User{}, err
		}
		return *u, nil
	})
}

func (s *PgStore) SetPassword(ctx context.Context, userID int64, passwordHash string, mustChange bool) error {
	return pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			"UPDATE users SET password_hash = $2, must_change_password = $3, password_changed_at = now() WHERE id = $1",
			userID, passwordHash, mustChange)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		_, err = tx.Exec(ctx, "DELETE FROM sessions WHERE user_id = $1", userID)
		return err
	})
}

func (s *PgStore) DeleteUser(ctx context.Context, userID int64) error {
	tag, err := s.db.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	if err == nil && tag.RowsAffected() == 0 {
		err = ErrNotFound
	}
	return err
}

// maxUserSessions bounds the sessions a single user can pile up.
const maxUserSessions = 100

func (s *PgStore) CreateSession(ctx context.Context, tokenHash []byte, userID int64, expires time.Time) error {
	return pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ($1, $2, $3)",
			tokenHash, userID, expires); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM sessions WHERE token_hash IN (
			SELECT token_hash FROM sessions WHERE user_id = $1 ORDER BY created_at DESC OFFSET $2)`,
			userID, maxUserSessions)
		return err
	})
}

func (s *PgStore) SessionUser(ctx context.Context, tokenHash []byte) (*User, error) {
	return scanUser(s.db.QueryRow(ctx, `SELECT u.id, u.username, u.password_hash, u.must_change_password, u.created_at
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = $1 AND s.expires_at > now()`, tokenHash))
}

func (s *PgStore) DeleteSession(ctx context.Context, tokenHash []byte) error {
	_, err := s.db.Exec(ctx, "DELETE FROM sessions WHERE token_hash = $1", tokenHash)
	return err
}

func (s *PgStore) DeleteExpiredSessions(ctx context.Context) error {
	_, err := s.db.Exec(ctx, "DELETE FROM sessions WHERE expires_at <= now()")
	return err
}

// policyChannel is notified on every policy change so that running servers
// reload their enforcer.
const policyChannel = "goftp_policy"

// PgAdapter stores Casbin rules in the casbin_rule table.
type PgAdapter struct{ db *pgxpool.Pool }

var _ persist.Adapter = (*PgAdapter)(nil)

func NewPgAdapter(db *pgxpool.Pool) *PgAdapter { return &PgAdapter{db: db} }

const ruleFields = 6

func (a *PgAdapter) ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 30*time.Second)
}

func (a *PgAdapter) LoadPolicy(m model.Model) error {
	ctx, cancel := a.ctx()
	defer cancel()
	rows, err := a.db.Query(ctx, "SELECT ptype, v0, v1, v2, v3, v4, v5 FROM casbin_rule ORDER BY id")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var rule [ruleFields + 1]string
		if err := rows.Scan(&rule[0], &rule[1], &rule[2], &rule[3], &rule[4], &rule[5], &rule[6]); err != nil {
			return err
		}
		n := len(rule)
		for n > 1 && rule[n-1] == "" {
			n--
		}
		if err := persist.LoadPolicyArray(rule[:n], m); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (a *PgAdapter) SavePolicy(m model.Model) error {
	ctx, cancel := a.ctx()
	defer cancel()
	return pgx.BeginFunc(ctx, a.db, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "DELETE FROM casbin_rule"); err != nil {
			return err
		}
		for _, sec := range []string{"p", "g"} {
			for ptype, ast := range m[sec] {
				for _, rule := range ast.Policy {
					if err := insertRule(ctx, tx, ptype, rule); err != nil {
						return err
					}
				}
			}
		}
		return notify(ctx, tx)
	})
}

func (a *PgAdapter) AddPolicy(_, ptype string, rule []string) error {
	ctx, cancel := a.ctx()
	defer cancel()
	return pgx.BeginFunc(ctx, a.db, func(tx pgx.Tx) error {
		if err := insertRule(ctx, tx, ptype, rule); err != nil {
			return err
		}
		return notify(ctx, tx)
	})
}

func (a *PgAdapter) RemovePolicy(_, ptype string, rule []string) error {
	values, err := padRule(rule)
	if err != nil {
		return err
	}
	ctx, cancel := a.ctx()
	defer cancel()
	return pgx.BeginFunc(ctx, a.db, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM casbin_rule WHERE ptype = $1
			AND v0 = $2 AND v1 = $3 AND v2 = $4 AND v3 = $5 AND v4 = $6 AND v5 = $7`,
			append([]any{ptype}, values...)...); err != nil {
			return err
		}
		return notify(ctx, tx)
	})
}

func (a *PgAdapter) RemoveFilteredPolicy(_, ptype string, fieldIndex int, fieldValues ...string) error {
	if fieldIndex < 0 || fieldIndex+len(fieldValues) > ruleFields {
		return fmt.Errorf("casbin: invalid filter at field %d", fieldIndex)
	}
	query := "DELETE FROM casbin_rule WHERE ptype = $1"
	args := []any{ptype}
	for i, v := range fieldValues {
		if v != "" {
			args = append(args, v)
			query += fmt.Sprintf(" AND v%d = $%d", fieldIndex+i, len(args))
		}
	}
	ctx, cancel := a.ctx()
	defer cancel()
	return pgx.BeginFunc(ctx, a.db, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, query, args...); err != nil {
			return err
		}
		return notify(ctx, tx)
	})
}

func padRule(rule []string) ([]any, error) {
	if len(rule) > ruleFields {
		return nil, fmt.Errorf("casbin: rule has more than %d fields", ruleFields)
	}
	values := make([]any, ruleFields)
	for i := range values {
		values[i] = ""
		if i < len(rule) {
			values[i] = rule[i]
		}
	}
	return values, nil
}

func insertRule(ctx context.Context, tx pgx.Tx, ptype string, rule []string) error {
	values, err := padRule(rule)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
		VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING`, append([]any{ptype}, values...)...)
	return err
}

func notify(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, "SELECT pg_notify($1, '')", policyChannel)
	return err
}

// WatchPolicies reloads the enforcer whenever the policy changes, and every
// few minutes in case a notification was missed. It returns when ctx ends.
func WatchPolicies(ctx context.Context, db *pgxpool.Pool, e *casbin.SyncedEnforcer, log *zap.Logger) {
	const resync = 5 * time.Minute
	reload := func() {
		if err := e.LoadPolicy(); err != nil {
			log.Error("reload policy", zap.Error(err))
		}
	}
	for ctx.Err() == nil {
		err := listen(ctx, db, resync, reload)
		if ctx.Err() == nil {
			log.Warn("policy listener stopped, retrying", zap.Error(err))
			select {
			case <-ctx.Done():
			case <-time.After(5 * time.Second):
			}
		}
	}
}

func listen(ctx context.Context, db *pgxpool.Pool, resync time.Duration, reload func()) error {
	pooled, err := db.Acquire(ctx)
	if err != nil {
		return err
	}
	// A connection left in LISTEN mode must not go back to the pool.
	conn := pooled.Hijack()
	defer conn.Close(context.Background())
	if _, err := conn.Exec(ctx, "LISTEN "+pgx.Identifier{policyChannel}.Sanitize()); err != nil {
		return err
	}
	// Changes made before LISTEN took effect were not notified.
	reload()
	for {
		wait, cancel := context.WithTimeout(ctx, resync)
		_, err := conn.WaitForNotification(wait)
		cancel()
		switch {
		case err == nil, errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil:
			reload()
		case ctx.Err() != nil:
			return nil
		default:
			return err
		}
	}
}

// NewPgEnforcer loads the policy from Postgres.
func NewPgEnforcer(db *pgxpool.Pool) (*casbin.SyncedEnforcer, error) {
	e, err := NewEnforcer(NewPgAdapter(db))
	if err != nil && strings.Contains(err.Error(), "casbin_rule") {
		return nil, fmt.Errorf("load policy (run migrations first): %w", err)
	}
	return e, err
}
