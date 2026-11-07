package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// SetPendingTOTP keeps a sealed secret that is being set up. It replaces any
// earlier one.
func (s *Store) SetPendingTOTP(ctx context.Context, userID int64, sealed []byte) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET totp_pending = ? WHERE id = ?`, sealed, userID)
	return err
}

// PendingTOTP returns the sealed secret being set up, or ErrNotFound.
func (s *Store) PendingTOTP(ctx context.Context, userID int64) ([]byte, error) {
	var sealed []byte
	err := s.db.QueryRowContext(ctx, `SELECT totp_pending FROM users WHERE id = ?`, userID).Scan(&sealed)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && sealed == nil) {
		return nil, ErrNotFound
	}
	return sealed, err
}

// EnableTOTP turns two-factor sign-in on with the pending secret, sealed
// again as sealed, records step as used and replaces the recovery codes.
// It reports false when no secret was pending.
func (s *Store) EnableTOTP(ctx context.Context, userID int64, sealed []byte, step int64, codeHashes [][]byte) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after Commit
	enabled, err := s.changed(tx.ExecContext(ctx, `
		UPDATE users SET totp_secret = ?, totp_pending = NULL, totp_step = ?
		WHERE id = ? AND totp_pending IS NOT NULL`, sealed, step, userID))
	if err != nil || !enabled {
		return false, err
	}
	if err := replaceCodes(ctx, tx, userID, codeHashes); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

// DisableTOTP turns two-factor sign-in off and drops the recovery codes.
func (s *Store) DisableTOTP(ctx context.Context, userID int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after Commit
	if _, err := tx.ExecContext(ctx,
		`UPDATE users SET totp_secret = NULL, totp_pending = NULL WHERE id = ?`, userID); err != nil {
		return err
	}
	if err := replaceCodes(ctx, tx, userID, nil); err != nil {
		return err
	}
	return tx.Commit()
}

func replaceCodes(ctx context.Context, tx *sql.Tx, userID int64, codeHashes [][]byte) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM recovery_codes WHERE user_id = ?`, userID); err != nil {
		return err
	}
	for _, h := range codeHashes {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)`, userID, h); err != nil {
			return err
		}
	}
	return nil
}

// UseTOTPStep records step as used and reports false when it, or a later
// one, already was: the same code never works twice, even in parallel.
func (s *Store) UseTOTPStep(ctx context.Context, userID, step int64) (bool, error) {
	return s.changed(s.db.ExecContext(ctx,
		`UPDATE users SET totp_step = ?1 WHERE id = ?2 AND totp_step < ?1 AND totp_secret IS NOT NULL`, step, userID))
}

// UseRecoveryCode spends a recovery code and reports whether it was one.
func (s *Store) UseRecoveryCode(ctx context.Context, userID int64, codeHash []byte) (bool, error) {
	return s.changed(s.db.ExecContext(ctx,
		`DELETE FROM recovery_codes WHERE user_id = ? AND code_hash = ?`, userID, codeHash))
}

// RecoveryCodesLeft counts the account's unused recovery codes.
func (s *Store) RecoveryCodesLeft(ctx context.Context, userID int64) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM recovery_codes WHERE user_id = ?`, userID).Scan(&n)
	return n, err
}

// SecondStepFailed counts a failed second step after a right password.
func (s *Store) SecondStepFailed(ctx context.Context, userID int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET totp_failures = totp_failures + 1 WHERE id = ?`, userID)
	return err
}

// CreateTicket stores a sign-in waiting for its second step.
func (s *Store) CreateTicket(ctx context.Context, tokenHash []byte, userID int64, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO login_tickets (token_hash, user_id, expires_at) VALUES (?, ?, ?)`, tokenHash, userID, expiresAt.Unix())
	return err
}

// TicketAttempt takes one of the ticket's max attempts, before a code is
// checked, and returns its account. It reports false for a ticket that is
// gone, expired or out of attempts. Taking the attempt and checking the
// count are one statement, so attempts that arrive together get no more.
func (s *Store) TicketAttempt(ctx context.Context, tokenHash []byte, now time.Time, max int) (int64, bool, error) {
	var id int64
	err := s.db.QueryRowContext(ctx, `
		UPDATE login_tickets SET attempts = attempts + 1
		WHERE token_hash = ? AND expires_at > ? AND attempts < ?
		RETURNING user_id`, tokenHash, now.Unix(), max).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	return id, err == nil, err
}

// ErrFactorUsed is returned for a second-step code already used up.
var ErrFactorUsed = errors.New("code already used")

// CompleteSecondStep spends the ticket and the code together, so neither
// goes without the other: the TOTP step, or with recoveryHash set, that
// recovery code. It returns the failed second steps since the last sign-in
// and starts that count again. A ticket already gone gives ErrNotFound, a
// code already used ErrFactorUsed, and either way nothing is spent.
func (s *Store) CompleteSecondStep(ctx context.Context, tokenHash []byte, userID int64, now time.Time, step int64, recoveryHash []byte) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after Commit
	ticket, err := s.changed(tx.ExecContext(ctx,
		`DELETE FROM login_tickets WHERE token_hash = ? AND user_id = ? AND expires_at > ?`, tokenHash, userID, now.Unix()))
	if err != nil {
		return 0, err
	}
	if !ticket {
		return 0, ErrNotFound
	}
	var spent bool
	if recoveryHash != nil {
		spent, err = s.changed(tx.ExecContext(ctx,
			`DELETE FROM recovery_codes WHERE user_id = ? AND code_hash = ?`, userID, recoveryHash))
	} else {
		spent, err = s.changed(tx.ExecContext(ctx,
			`UPDATE users SET totp_step = ?1 WHERE id = ?2 AND totp_step < ?1 AND totp_secret IS NOT NULL`, step, userID))
	}
	if err != nil {
		return 0, err
	}
	if !spent {
		return 0, ErrFactorUsed
	}
	var failures int
	if err := tx.QueryRowContext(ctx, `SELECT totp_failures FROM users WHERE id = ?`, userID).Scan(&failures); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE users SET totp_failures = 0 WHERE id = ?`, userID); err != nil {
		return 0, err
	}
	return failures, tx.Commit()
}

// ExpireTickets drops tickets past their expiry.
func (s *Store) ExpireTickets(ctx context.Context, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM login_tickets WHERE expires_at <= ?`, now.Unix())
	return err
}
