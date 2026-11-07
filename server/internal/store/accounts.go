package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

var (
	// ErrUsernameTaken is returned for a sign-up under a name in use.
	ErrUsernameTaken = errors.New("username taken")
	// ErrCapacity is returned for a sign-up past the account cap.
	ErrCapacity = errors.New("account limit reached")
)

// Session lifetimes, NIST SP 800-63B-4 at AAL2: a session ends after an hour
// without a request, and a day after sign-in whatever its use.
const (
	SessionIdle     = time.Hour
	SessionLifetime = 24 * time.Hour
	// touchEvery spaces the writes that record a session's use.
	touchEvery = time.Minute
)

// User is an account. AuthHash is the Argon2id hash of the auth secret in
// the PHC string format; Salt and SealedKey are the browser's (D026).
type User struct {
	ID        int64
	Username  string
	Salt      []byte
	AuthHash  string
	SealedKey []byte
	CreatedAt time.Time
}

// CreateUser inserts the account while fewer than max exist and returns its
// id, ErrUsernameTaken or ErrCapacity.
func (s *Store) CreateUser(ctx context.Context, u User, max int) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO users (username, salt, auth_hash, sealed_key, created_at)
		SELECT ?, ?, ?, ?, ? WHERE (SELECT COUNT(*) FROM users) < ?
		ON CONFLICT (username) DO NOTHING`,
		u.Username, u.Salt, u.AuthHash, u.SealedKey, u.CreatedAt.Unix(), max)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	if n == 0 {
		taken, err := s.exists(ctx, `SELECT 1 FROM users WHERE username = ?`, u.Username)
		if err != nil {
			return 0, err
		}
		if taken {
			return 0, ErrUsernameTaken
		}
		return 0, ErrCapacity
	}
	return res.LastInsertId()
}

// UserByName returns the account or ErrNotFound.
func (s *Store) UserByName(ctx context.Context, username string) (User, error) {
	var u User
	var created int64
	err := s.db.QueryRowContext(ctx, `
		SELECT id, username, salt, auth_hash, sealed_key, created_at FROM users WHERE username = ?`,
		username).Scan(&u.ID, &u.Username, &u.Salt, &u.AuthHash, &u.SealedKey, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, err
	}
	u.CreatedAt = time.Unix(created, 0).UTC()
	return u, nil
}

// SetPassword replaces what the account's password protects: the browser's
// salt, the hash of the auth secret and the sealed account key.
func (s *Store) SetPassword(ctx context.Context, userID int64, salt []byte, authHash string, sealedKey []byte) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET salt = ?, auth_hash = ?, sealed_key = ? WHERE id = ?`, salt, authHash, sealedKey, userID)
	return err
}

// DeleteUser removes the account and, through the cascade, its sessions.
func (s *Store) DeleteUser(ctx context.Context, userID int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, userID)
	return err
}

// CreateSession stores a session and ends all but the newest keep sessions
// of the account, so repeated sign-ins cannot pile them up.
func (s *Store) CreateSession(ctx context.Context, tokenHash []byte, userID int64, now time.Time, keep int) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after Commit
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO sessions (token_hash, user_id, created_at, seen_at) VALUES (?, ?, ?, ?)`,
		tokenHash, userID, now.Unix(), now.Unix()); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM sessions WHERE user_id = ?1 AND rowid NOT IN (
			SELECT rowid FROM sessions WHERE user_id = ?1 ORDER BY created_at DESC, rowid DESC LIMIT ?2)`,
		userID, keep); err != nil {
		return err
	}
	return tx.Commit()
}

// SessionUser returns the account of a session that is still valid at now
// and records the session's use. It reports false for an unknown, idle or
// expired session.
func (s *Store) SessionUser(ctx context.Context, tokenHash []byte, now time.Time) (User, bool, error) {
	var u User
	var created, seen int64
	err := s.db.QueryRowContext(ctx, `
		SELECT u.id, u.username, u.salt, u.auth_hash, u.sealed_key, u.created_at, s.seen_at
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = ? AND s.seen_at > ? AND s.created_at > ?`,
		tokenHash, now.Add(-SessionIdle).Unix(), now.Add(-SessionLifetime).Unix()).Scan(
		&u.ID, &u.Username, &u.Salt, &u.AuthHash, &u.SealedKey, &created, &seen)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, false, nil
	}
	if err != nil {
		return User{}, false, err
	}
	u.CreatedAt = time.Unix(created, 0).UTC()
	if now.Unix()-seen >= int64(touchEvery/time.Second) {
		if _, err := s.db.ExecContext(ctx,
			`UPDATE sessions SET seen_at = ? WHERE token_hash = ?`, now.Unix(), tokenHash); err != nil {
			return User{}, false, err
		}
	}
	return u, true, nil
}

// DeleteSession ends one session.
func (s *Store) DeleteSession(ctx context.Context, tokenHash []byte) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, tokenHash)
	return err
}

// DeleteSessions ends every session of the account.
func (s *Store) DeleteSessions(ctx context.Context, userID int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, userID)
	return err
}

// ExpireSessions drops the sessions that can no longer be used at now.
func (s *Store) ExpireSessions(ctx context.Context, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE seen_at <= ? OR created_at <= ?`,
		now.Add(-SessionIdle).Unix(), now.Add(-SessionLifetime).Unix())
	return err
}
