package store

import (
	"context"
	"time"
)

// KeepFile adds the file to the account with the entry the browser sealed
// for it. It reports false for a file that is gone, expired or kept by
// another account; keeping it again replaces the entry.
func (s *Store) KeepFile(ctx context.Context, fileID string, userID int64, entry []byte, now time.Time) (bool, error) {
	return s.changed(s.db.ExecContext(ctx, `
		UPDATE files SET user_id = ?1, entry = ?2
		WHERE id = ?3 AND expires_at > ?4 AND (user_id IS NULL OR user_id = ?1)`,
		userID, entry, fileID, now.Unix()))
}

// KeptFile is a file of an account as its owner sees it.
type KeptFile struct {
	File
	Entry []byte
}

// KeptFiles lists the account's files that can still be downloaded or are
// still waiting for their content, newest first, at most limit of them.
func (s *Store) KeptFiles(ctx context.Context, userID int64, now time.Time, limit int) ([]KeptFile, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, size_bytes, meta_ciphertext, downloads_left, expires_at, created_at, uploaded_at IS NOT NULL, entry
		FROM files
		WHERE user_id = ? AND expires_at > ? AND downloads_left > 0 AND entry IS NOT NULL
		ORDER BY created_at DESC, id LIMIT ?`, userID, now.Unix(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var kept []KeptFile
	for rows.Next() {
		var f KeptFile
		var expires, created int64
		if err := rows.Scan(&f.ID, &f.SizeBytes, &f.MetaCiphertext, &f.DownloadsLeft, &expires, &created, &f.Uploaded, &f.Entry); err != nil {
			return nil, err
		}
		f.ExpiresAt = time.Unix(expires, 0).UTC()
		f.CreatedAt = time.Unix(created, 0).UTC()
		kept = append(kept, f)
	}
	return kept, rows.Err()
}
