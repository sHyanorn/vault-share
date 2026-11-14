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
// The account's sign-ins restart with r. It reports false when no secret
// was pending.
func (s *Store) EnableTOTP(ctx context.Context, userID int64, sealed []byte, step int64, codeHashes [][]byte, r Renewal) (bool, error) {
	var enabled bool
	err := inTx(ctx, s.db, func(tx *sql.Tx) error {
		var err error
		enabled, err = s.changed(tx.ExecContext(ctx, `
			UPDATE users SET totp_secret = ?, totp_pending = NULL, totp_step = ?
			WHERE id = ? AND totp_pending IS NOT NULL`, sealed, step, userID))
		if err != nil || !enabled {
			return err
		}
		if err := replaceCodes(ctx, tx, userID, codeHashes); err != nil {
			return err
		}
		return restartSignIns(ctx, tx, userID, r)
	})
	return enabled && err == nil, err
}

// DisableTOTP spends f, turns two-factor sign-in off and drops the recovery
// codes. The account's sign-ins restart with r.
func (s *Store) DisableTOTP(ctx context.Context, userID int64, r Renewal, f *Factor) error {
	return inTx(ctx, s.db, func(tx *sql.Tx) error {
		if err := s.spend(ctx, tx, userID, f); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE users SET totp_secret = NULL, totp_pending = NULL WHERE id = ?`, userID); err != nil {
			return err
		}
		if err := replaceCodes(ctx, tx, userID, nil); err != nil {
			return err
		}
		return restartSignIns(ctx, tx, userID, r)
	})
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

// The statements that spend a second-step code; each changes a row only for
// a code not yet used.
const (
	// useTOTPStep takes the step and the account id.
	useTOTPStep = `UPDATE users SET totp_step = ?1 WHERE id = ?2 AND totp_step < ?1 AND totp_secret IS NOT NULL`
	// useRecoveryCode takes the account id and the code's hash.
	useRecoveryCode = `DELETE FROM recovery_codes WHERE user_id = ? AND code_hash = ?`
)

// Factor is a second-step code that matched: a TOTP time step, or a
// recovery code by its hash.
type Factor struct {
	Step         int64
	RecoveryHash []byte
}

// spend uses f up in tx, or returns ErrFactorUsed when a step at least as
// late was used, or the recovery code is gone; the same code never works
// twice, even in parallel. It runs in the transaction of what the code
// confirms, so neither happens without the other (F41, F59). A nil f, for a
// change that asked for no code, spends nothing.
func (s *Store) spend(ctx context.Context, tx *sql.Tx, userID int64, f *Factor) error {
	if f == nil {
		return nil
	}
	var spent bool
	var err error
	if f.RecoveryHash != nil {
		spent, err = s.changed(tx.ExecContext(ctx, useRecoveryCode, userID, f.RecoveryHash))
	} else {
		spent, err = s.changed(tx.ExecContext(ctx, useTOTPStep, f.Step, userID))
	}
	if err == nil && !spent {
		err = ErrFactorUsed
	}
	return err
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

// SecondStep is a sign-in's second step: the ticket, the code that matched,
// and the session it opens.
type SecondStep struct {
	TicketHash []byte
	UserID     int64
	// Step is the TOTP time step, unless RecoveryHash names a recovery code.
	Step         int64
	RecoveryHash []byte
	SessionHash  []byte
	// KeepSessions is how many of the account's newest sessions stay.
	KeepSessions int
}

// CompleteSecondStep spends the ticket and the code and opens the session
// in one transaction, so none of them happens without the others (F38,
// F41). It returns the failed second steps since the last sign-in and
// starts that count again. A ticket already gone gives ErrNotFound, a code
// already used ErrFactorUsed, and then nothing changes.
func (s *Store) CompleteSecondStep(ctx context.Context, st SecondStep, now time.Time) (int, error) {
	var failures int
	err := inTx(ctx, s.db, func(tx *sql.Tx) error {
		ticket, err := s.changed(tx.ExecContext(ctx,
			`DELETE FROM login_tickets WHERE token_hash = ? AND user_id = ? AND expires_at > ?`, st.TicketHash, st.UserID, now.Unix()))
		if err != nil {
			return err
		}
		if !ticket {
			return ErrNotFound
		}
		if err := s.spend(ctx, tx, st.UserID, &Factor{Step: st.Step, RecoveryHash: st.RecoveryHash}); err != nil {
			return err
		}
		if err := tx.QueryRowContext(ctx, `SELECT totp_failures FROM users WHERE id = ?`, st.UserID).Scan(&failures); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE users SET totp_failures = 0 WHERE id = ?`, st.UserID); err != nil {
			return err
		}
		return insertSession(ctx, tx, st.SessionHash, st.UserID, now, st.KeepSessions)
	})
	if err != nil {
		return 0, err
	}
	return failures, nil
}

// ExpireTickets drops tickets past their expiry.
func (s *Store) ExpireTickets(ctx context.Context, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM login_tickets WHERE expires_at <= ?`, now.Unix())
	return err
}
