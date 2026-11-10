// Package store persists files, accounts, sessions, second-factor state and
// the audit log in SQLite, and tracks in memory which files have an upload or
// a deletion in flight (Claim, Release). The server never holds a decryption
// key: a file record carries encrypted metadata, the HMAC key that verifies
// download challenges, and hashes of the tokens it issues.
package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"sync"
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

	mu sync.Mutex
	// claimed holds the files being uploaded or deleted; see Claim.
	claimed map[string]bool
}

// Claim reserves a file for an upload or a deletion and reports false while
// another holds it. An upload keeps its claim until its body has ended, so no
// request and no cleanup run deletes a record whose bytes are still arriving
// and would no longer count against the quota. vaultd runs as one process,
// so the claims live in memory.
func (s *Store) Claim(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.claimed[id] {
		return false
	}
	s.claimed[id] = true
	return true
}

// Release gives up a claim taken with Claim.
func (s *Store) Release(id string) {
	s.mu.Lock()
	delete(s.claimed, id)
	s.mu.Unlock()
}

// Open opens or creates the database at path and applies pending migrations.
func Open(ctx context.Context, path string) (*Store, error) {
	// Create the file owner-only; SQLite gives the WAL and shared-memory
	// files the same mode.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600) // #nosec G304 -- path comes from configuration
	if err != nil {
		return nil, err
	}
	_ = f.Close()
	// Transactions take the write lock when they begin. A deferred one that
	// reads before it writes fails at once, past busy_timeout, when another
	// connection wrote in between.
	dsn := "file:" + path +
		"?_pragma=busy_timeout(5000)" +
		"&_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(NORMAL)" +
		"&_pragma=foreign_keys(ON)" +
		"&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// SQLite has one writer at a time; a small pool keeps readers concurrent
	// without piling up connections that would only wait on busy_timeout.
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(4)
	dir, err := fs.Sub(migrations, "migrations")
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := migrate(ctx, db, dir); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &Store{db: db, claimed: map[string]bool{}}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

// migrate applies the scripts in dir that have not run yet, in name order.
func migrate(ctx context.Context, db *sql.DB, dir fs.FS) error {
	_, err := db.ExecContext(ctx,
		`CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL)`)
	if err != nil {
		return err
	}
	entries, err := fs.ReadDir(dir, ".")
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
		script, err := fs.ReadFile(dir, name)
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

// RecordOverhead is charged to the quota for every record on top of its
// size and metadata. It covers the database row, the filesystem's block for
// the blob and the record's audit entries, and it caps the number of
// records at quota / RecordOverhead. Migration 0003 uses the same figure.
const RecordOverhead = 64 << 10

// Charge is what a record costs against the storage quota.
func Charge(sizeBytes int64, metaLen int) int64 {
	return sizeBytes + int64(metaLen) + RecordOverhead
}

// CreateFile inserts the record if the quota has room for its charge and
// reports whether it did. The check and the insert are one statement, which
// SQLite runs under its write lock, so concurrent creates cannot overshoot.
func (s *Store) CreateFile(ctx context.Context, f File, quota int64) (bool, error) {
	charge := Charge(f.SizeBytes, len(f.MetaCiphertext))
	return s.changed(s.db.ExecContext(ctx, `
		INSERT INTO files (id, size_bytes, meta_ciphertext, auth_key, owner_token_hash,
			downloads_left, expires_at, created_at, charge)
		SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?
		WHERE (SELECT charged FROM usage WHERE id = 1) + ? <= ?`,
		f.ID, f.SizeBytes, f.MetaCiphertext, f.AuthKey, f.OwnerTokenHash,
		f.DownloadsLeft, f.ExpiresAt.Unix(), f.CreatedAt.Unix(), charge, charge, quota))
}

// Usage is the storage currently charged against the quota.
func (s *Store) Usage(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `SELECT charged FROM usage WHERE id = 1`).Scan(&n)
	return n, err
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

// FileExists reports whether id has a record, live or not.
func (s *Store) FileExists(ctx context.Context, id string) (bool, error) {
	return s.exists(ctx, `SELECT 1 FROM files WHERE id = ?`, id)
}

// MarkUploaded records that the content is stored. It reports false when the
// record is gone or already marked.
func (s *Store) MarkUploaded(ctx context.Context, id string, at time.Time) (bool, error) {
	return s.changed(s.db.ExecContext(ctx,
		`UPDATE files SET uploaded_at = ? WHERE id = ? AND uploaded_at IS NULL`, at.Unix(), id))
}

// DeleteFile removes the record and, through the cascade, its download tokens.
func (s *Store) DeleteFile(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM files WHERE id = ?`, id)
	return err
}

// DeleteIfPending removes the record only while its content has not arrived,
// so a purge can never race an upload that just completed.
func (s *Store) DeleteIfPending(ctx context.Context, id string) (bool, error) {
	return s.changed(s.db.ExecContext(ctx,
		`DELETE FROM files WHERE id = ? AND uploaded_at IS NULL`, id))
}

// DeleteIfBurned removes the record once every permitted download has been
// taken and no download token is still pending.
func (s *Store) DeleteIfBurned(ctx context.Context, id string, now time.Time) (bool, error) {
	return s.changed(s.db.ExecContext(ctx, `
		DELETE FROM files WHERE id = ?1 AND downloads_left = 0 AND NOT EXISTS (
			SELECT 1 FROM download_tokens t WHERE t.file_id = ?1 AND t.expires_at > ?2)`,
		id, now.Unix()))
}

// GrantDownload takes one download from a live file and stores the token
// that redeems it, in one transaction. A file whose count reaches zero
// therefore always has its token pending, so DeleteIfBurned and Purgeable
// leave it until that download is done; and concurrent callers can never
// take more downloads than allowed. It returns the remaining count and
// whether a download was granted.
func (s *Store) GrantDownload(ctx context.Context, fileID string, tokenHash []byte, now, tokenExpires time.Time) (int64, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, false, err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after Commit
	var left int64
	err = tx.QueryRowContext(ctx, `
		UPDATE files SET downloads_left = downloads_left - 1
		WHERE id = ? AND downloads_left > 0 AND uploaded_at IS NOT NULL AND expires_at > ?
		RETURNING downloads_left`, fileID, now.Unix()).Scan(&left)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO download_tokens (token_hash, file_id, expires_at) VALUES (?, ?, ?)`,
		tokenHash, fileID, tokenExpires.Unix()); err != nil {
		return 0, false, err
	}
	if err := tx.Commit(); err != nil {
		return 0, false, err
	}
	return left, true, nil
}

// DownloadTokenValid reports whether the token is valid for the file at now,
// without using it up.
func (s *Store) DownloadTokenValid(ctx context.Context, fileID string, tokenHash []byte, now time.Time) (bool, error) {
	return s.exists(ctx,
		`SELECT 1 FROM download_tokens WHERE token_hash = ? AND file_id = ? AND expires_at > ?`,
		tokenHash, fileID, now.Unix())
}

// ConsumeDownloadToken deletes the token and reports whether it was valid for the file at now.
func (s *Store) ConsumeDownloadToken(ctx context.Context, fileID string, tokenHash []byte, now time.Time) (bool, error) {
	return s.changed(s.db.ExecContext(ctx,
		`DELETE FROM download_tokens WHERE token_hash = ? AND file_id = ? AND expires_at > ?`,
		tokenHash, fileID, now.Unix()))
}

// Purge names a file the cleanup job may remove. Pending means its content
// never arrived, which changes how it is removed.
type Purge struct {
	ID      string
	Pending bool
}

// Purgeable lists expired and used-up files that have no download token still
// pending, and files whose content never arrived within the upload grace period.
func (s *Store) Purgeable(ctx context.Context, now time.Time) ([]Purge, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, uploaded_at IS NULL FROM files f
		WHERE (uploaded_at IS NOT NULL
		       AND (expires_at <= ?1 OR downloads_left = 0)
		       AND NOT EXISTS (SELECT 1 FROM download_tokens t WHERE t.file_id = f.id AND t.expires_at > ?1))
		   OR (uploaded_at IS NULL AND created_at <= ?2)`,
		now.Unix(), now.Add(-UploadGrace).Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var purges []Purge
	for rows.Next() {
		var p Purge
		if err := rows.Scan(&p.ID, &p.Pending); err != nil {
			return nil, err
		}
		purges = append(purges, p)
	}
	return purges, rows.Err()
}

// ExpireTokens drops download tokens that are past their expiry.
func (s *Store) ExpireTokens(ctx context.Context, now time.Time) error {
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

// exists reports whether query, a SELECT 1, returns a row.
func (s *Store) exists(ctx context.Context, query string, args ...any) (bool, error) {
	var one int
	err := s.db.QueryRowContext(ctx, query, args...).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// AuditEntry is one security-relevant event. Client identifiers arrive
// already hashed; the store never sees an address.
type AuditEntry struct {
	Event  string
	FileID string
	// UserID names the account; 0 means none.
	UserID int64
	IPHash []byte
	UAHash []byte
	At     time.Time
}

func (s *Store) RecordAudit(ctx context.Context, e AuditEntry) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO audit_log (event, file_id, user_id, ip_hash, ua_hash, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		e.Event, sql.NullString{String: e.FileID, Valid: e.FileID != ""}, sql.NullInt64{Int64: e.UserID, Valid: e.UserID != 0},
		e.IPHash, e.UAHash, e.At.Unix())
	return err
}

// RecentAudit returns the newest entries, newest first.
func (s *Store) RecentAudit(ctx context.Context, limit int) ([]AuditEntry, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT event, COALESCE(file_id, ''), COALESCE(user_id, 0), ip_hash, ua_hash, created_at
		FROM audit_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var entries []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var at int64
		if err := rows.Scan(&e.Event, &e.FileID, &e.UserID, &e.IPHash, &e.UAHash, &at); err != nil {
			return nil, err
		}
		e.At = time.Unix(at, 0).UTC()
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// PurgeAudit drops entries recorded before the given time.
func (s *Store) PurgeAudit(ctx context.Context, before time.Time) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM audit_log WHERE created_at < ?`, before.Unix())
	return err
}

// TrimAudit keeps at most the newest max entries and reports how many it
// dropped. Ids only grow and only the oldest rows are ever deleted, so the
// newest max entries are the ids above MAX(id) - max.
func (s *Store) TrimAudit(ctx context.Context, max int) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM audit_log WHERE id <= (SELECT MAX(id) FROM audit_log) - ?`, max)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
