// Package store persists file records in SQLite. The server never holds a
// decryption key: a record carries encrypted metadata, the HMAC key that
// verifies download challenges, and hashes of the tokens it issues.
package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite" // database/sql driver
)

//go:embed migrations/*.sql
var migrations embed.FS

// ErrNotFound is returned for an id that has no record.
var ErrNotFound = errors.New("not found")

// UploadGrace is how long a record may wait for its content before it is purged.
const UploadGrace = time.Hour

// Store is a SQLite-backed file record store.
type Store struct {
	db *sql.DB
}

// Open opens or creates the database at path and applies pending migrations.
func Open(ctx context.Context, path string) (*Store, error) {
	dsn := "file:" + path +
		"?_pragma=busy_timeout(5000)" +
		"&_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(NORMAL)" +
		"&_pragma=foreign_keys(ON)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// SQLite has one writer at a time; a small pool keeps readers concurrent
	// without piling up connections that would only wait on busy_timeout.
	db.SetMaxOpenConns(4)
	if err := migrate(ctx, db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func migrate(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx,
		`CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL)`)
	if err != nil {
		return err
	}
	entries, err := fs.ReadDir(migrations, "migrations")
	if err != nil {
		return err
	}
	for _, entry := range entries { // fs.ReadDir sorts by name, so 0001 runs before 0002
		name := entry.Name()
		version, err := strconv.Atoi(strings.SplitN(name, "_", 2)[0])
		if err != nil {
			return fmt.Errorf("migration %q: bad version prefix", name)
		}
		var applied int
		err = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, version).Scan(&applied)
		if err != nil {
			return err
		}
		if applied > 0 {
			continue
		}
		script, err := migrations.ReadFile("migrations/" + name)
		if err != nil {
			return err
		}
		if err := apply(ctx, db, version, string(script)); err != nil {
			return fmt.Errorf("migration %q: %w", name, err)
		}
	}
	return nil
}

func apply(ctx context.Context, db *sql.DB, version int, script string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after Commit
	if _, err := tx.ExecContext(ctx, script); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`,
		version, time.Now().Unix())
	if err != nil {
		return err
	}
	return tx.Commit()
}

// File is one shared file. Times are stored as Unix seconds.
type File struct {
	ID             string
	SizeBytes      int64
	MetaCiphertext []byte
	AuthKey        []byte
	OwnerTokenHash []byte
	DownloadsLeft  int64
	ExpiresAt      time.Time
	CreatedAt      time.Time
	Uploaded       bool
}

// Live reports whether the file can be downloaded at now.
func (f File) Live(now time.Time) bool {
	return f.Uploaded && f.DownloadsLeft > 0 && now.Before(f.ExpiresAt)
}

func (s *Store) CreateFile(ctx context.Context, f File) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO files (id, size_bytes, meta_ciphertext, auth_key, owner_token_hash,
			downloads_left, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		f.ID, f.SizeBytes, f.MetaCiphertext, f.AuthKey, f.OwnerTokenHash,
		f.DownloadsLeft, f.ExpiresAt.Unix(), f.CreatedAt.Unix())
	return err
}

func (s *Store) GetFile(ctx context.Context, id string) (File, error) {
	var f File
	var expires, created int64
	var uploaded sql.NullInt64
	err := s.db.QueryRowContext(ctx, `
		SELECT id, size_bytes, meta_ciphertext, auth_key, owner_token_hash,
			downloads_left, expires_at, created_at, uploaded_at
		FROM files WHERE id = ?`, id).Scan(
		&f.ID, &f.SizeBytes, &f.MetaCiphertext, &f.AuthKey, &f.OwnerTokenHash,
		&f.DownloadsLeft, &expires, &created, &uploaded)
	if errors.Is(err, sql.ErrNoRows) {
		return File{}, ErrNotFound
	}
	if err != nil {
		return File{}, err
	}
	f.ExpiresAt = time.Unix(expires, 0).UTC()
	f.CreatedAt = time.Unix(created, 0).UTC()
	f.Uploaded = uploaded.Valid
	return f, nil
}

// MarkUploaded records that the content is stored. It reports false when the
// file is unknown or already marked, so a second upload cannot replace the first.
func (s *Store) MarkUploaded(ctx context.Context, id string, at time.Time) (bool, error) {
	return s.changed(s.db.ExecContext(ctx,
		`UPDATE files SET uploaded_at = ? WHERE id = ? AND uploaded_at IS NULL`, at.Unix(), id))
}

// DeleteFile removes the record and, through cascades, its challenges and tokens.
func (s *Store) DeleteFile(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM files WHERE id = ?`, id)
	return err
}

// CreateChallenge stores a one-time nonce for the file, keeping at most the
// newest challengesPerFile so a flood of metadata requests cannot grow the table.
func (s *Store) CreateChallenge(ctx context.Context, fileID string, nonce []byte, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		DELETE FROM challenges WHERE file_id = ?1 AND nonce NOT IN (
			SELECT nonce FROM challenges WHERE file_id = ?1 ORDER BY expires_at DESC LIMIT ?2)`,
		fileID, challengesPerFile-1)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO challenges (nonce, file_id, expires_at) VALUES (?, ?, ?)`,
		nonce, fileID, expiresAt.Unix())
	return err
}

const challengesPerFile = 16

// ConsumeChallenge deletes the nonce and reports whether it was valid for the file at now.
func (s *Store) ConsumeChallenge(ctx context.Context, fileID string, nonce []byte, now time.Time) (bool, error) {
	return s.changed(s.db.ExecContext(ctx,
		`DELETE FROM challenges WHERE nonce = ? AND file_id = ? AND expires_at > ?`,
		nonce, fileID, now.Unix()))
}

// ConsumeDownload decrements the download count of a live file in one
// statement, so concurrent callers can never take more downloads than allowed.
// It returns the remaining count and whether a download was granted.
func (s *Store) ConsumeDownload(ctx context.Context, fileID string, now time.Time) (int64, bool, error) {
	var left int64
	err := s.db.QueryRowContext(ctx, `
		UPDATE files SET downloads_left = downloads_left - 1
		WHERE id = ? AND downloads_left > 0 AND uploaded_at IS NOT NULL AND expires_at > ?
		RETURNING downloads_left`, fileID, now.Unix()).Scan(&left)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return left, true, nil
}

func (s *Store) CreateDownloadToken(ctx context.Context, fileID string, tokenHash []byte, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO download_tokens (token_hash, file_id, expires_at) VALUES (?, ?, ?)`,
		tokenHash, fileID, expiresAt.Unix())
	return err
}

// ConsumeDownloadToken deletes the token and reports whether it was valid for the file at now.
func (s *Store) ConsumeDownloadToken(ctx context.Context, fileID string, tokenHash []byte, now time.Time) (bool, error) {
	return s.changed(s.db.ExecContext(ctx,
		`DELETE FROM download_tokens WHERE token_hash = ? AND file_id = ? AND expires_at > ?`,
		tokenHash, fileID, now.Unix()))
}

// Purgeable lists files whose content can be deleted: expired ones, ones
// whose downloads are used up and have no download token still pending, and
// ones whose content never arrived within the upload grace period.
func (s *Store) Purgeable(ctx context.Context, now time.Time) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id FROM files f
		WHERE expires_at <= ?1
		   OR (downloads_left = 0 AND NOT EXISTS (
		          SELECT 1 FROM download_tokens t WHERE t.file_id = f.id AND t.expires_at > ?1))
		   OR (uploaded_at IS NULL AND created_at <= ?2)`,
		now.Unix(), now.Add(-UploadGrace).Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// ExpireTokens drops challenges and download tokens that are past their expiry.
func (s *Store) ExpireTokens(ctx context.Context, now time.Time) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM challenges WHERE expires_at <= ?`, now.Unix()); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM download_tokens WHERE expires_at <= ?`, now.Unix())
	return err
}

func (s *Store) changed(res sql.Result, err error) (bool, error) {
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}
