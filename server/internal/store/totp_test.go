package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestTOTPStepIsUsedOnce(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	id, _ := s.CreateUser(ctx, user("alice"), 10)
	useStep := func(step int64) (bool, error) {
		err := inTx(ctx, s.db, func(tx *sql.Tx) error { return s.spend(ctx, tx, id, &Factor{Step: step}) })
		if errors.Is(err, ErrFactorUsed) {
			return false, nil
		}
		return err == nil, err
	}
	if used, _ := useStep(100); used {
		t.Fatal("a step was used while two-factor sign-in is off")
	}
	s.SetPendingTOTP(ctx, id, []byte("sealed"))
	if ok, err := s.EnableTOTP(ctx, id, []byte("sealed"), 100, [][]byte{[]byte("a"), []byte("b")}, renewal); !ok || err != nil {
		t.Fatalf("enable: %v %v", ok, err)
	}
	// Two requests with the same code at once: one wins.
	var won atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if used, err := useStep(101); err != nil {
				t.Error(err)
			} else if used {
				won.Add(1)
			}
		})
	}
	wg.Wait()
	if won.Load() != 1 {
		t.Errorf("step 101 used %d times", won.Load())
	}
	for step, want := range map[int64]bool{100: false, 101: false, 102: true} {
		if used, _ := useStep(step); used != want {
			t.Errorf("step %d used %v, want %v", step, used, want)
		}
	}
	if n, _ := s.RecoveryCodesLeft(ctx, id); n != 2 {
		t.Errorf("%d recovery codes", n)
	}
	if ok, _ := s.EnableTOTP(ctx, id, []byte("again"), 0, nil, renewal); ok {
		t.Error("enabled without a pending secret")
	}
	if err := s.DisableTOTP(ctx, id, renewal, nil); err != nil {
		t.Fatal(err)
	}
	u, _ := s.UserByName(ctx, "alice")
	if n, _ := s.RecoveryCodesLeft(ctx, id); u.TOTPSecret != nil || n != 0 {
		t.Errorf("after disabling: secret %x, %d codes", u.TOTPSecret, n)
	}
}

func TestTicketAttemptsAreBounded(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	id, _ := s.CreateUser(ctx, user("alice"), 10)
	s.CreateTicket(ctx, []byte("ticket"), id, t0.Add(5*time.Minute))
	var taken atomic.Int32
	var wg sync.WaitGroup
	for range 40 {
		wg.Go(func() {
			if got, ok, err := s.TicketAttempt(ctx, []byte("ticket"), t0, 5); err != nil {
				t.Error(err)
			} else if ok && got == id {
				taken.Add(1)
			}
		})
	}
	wg.Wait()
	if taken.Load() != 5 {
		t.Errorf("40 attempts at once on one ticket: %d taken, want 5", taken.Load())
	}
	s.CreateTicket(ctx, []byte("later"), id, t0.Add(5*time.Minute))
	if _, ok, _ := s.TicketAttempt(ctx, []byte("later"), t0.Add(5*time.Minute), 5); ok {
		t.Error("an expired ticket took an attempt")
	}
	if err := s.ExpireTickets(ctx, t0.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM login_tickets`).Scan(&n)
	if n != 0 {
		t.Errorf("%d tickets survived their expiry", n)
	}
}

func TestCompleteSecondStepSpendsBothOrNeither(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	id, _ := s.CreateUser(ctx, user("alice"), 10)
	s.SetPendingTOTP(ctx, id, []byte("sealed"))
	s.EnableTOTP(ctx, id, []byte("sealed"), 100, [][]byte{[]byte("code-a"), []byte("code-b")}, renewal)
	s.SecondStepFailed(ctx, id)
	s.SecondStepFailed(ctx, id)
	left := func() int {
		n, _ := s.RecoveryCodesLeft(ctx, id)
		return n
	}

	complete := func(ticket string, step int64, recovery string) (int, error) {
		st := SecondStep{TicketHash: []byte(ticket), UserID: id, Step: step,
			SessionHash: []byte("session-" + ticket + recovery), KeepSessions: 10}
		if recovery != "" {
			st.RecoveryHash = []byte(recovery)
		}
		return s.CompleteSecondStep(ctx, st, t0)
	}
	opened := func(ticket, recovery string) bool {
		_, ok, _ := s.SessionUser(ctx, []byte("session-"+ticket+recovery), t0)
		return ok
	}

	// A code already used keeps the ticket and opens nothing.
	s.CreateTicket(ctx, []byte("t1"), id, t0.Add(time.Minute))
	if _, err := complete("t1", 100, ""); !errors.Is(err, ErrFactorUsed) || opened("t1", "") {
		t.Errorf("a used step: %v", err)
	}
	if _, err := complete("t1", 0, "not-a-code"); !errors.Is(err, ErrFactorUsed) {
		t.Errorf("an unknown recovery code: %v", err)
	}
	failures, err := complete("t1", 0, "code-a")
	if err != nil || failures != 2 || left() != 1 || !opened("t1", "code-a") {
		t.Errorf("a recovery code: %d failures, %v, %d codes left", failures, err, left())
	}
	// A ticket already gone keeps the code.
	if _, err := complete("t1", 0, "code-b"); !errors.Is(err, ErrNotFound) || left() != 1 || opened("t1", "code-b") {
		t.Errorf("a used ticket: %v, %d codes left", err, left())
	}
	s.CreateTicket(ctx, []byte("t2"), id, t0.Add(time.Minute))
	if failures, err := complete("t2", 101, ""); err != nil || failures != 0 || !opened("t2", "") {
		t.Errorf("a fresh step: %d failures, %v", failures, err)
	}
	if _, err := complete("t2", 102, ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("a second sign-in on one ticket: %v", err)
	}

	// A session that cannot be opened spends nothing (F41).
	s.CreateTicket(ctx, []byte("t3"), id, t0.Add(time.Minute))
	if _, err := s.db.Exec(`CREATE TRIGGER no_sessions BEFORE INSERT ON sessions BEGIN SELECT RAISE(ABORT, 'full'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := complete("t3", 0, "code-b"); err == nil {
		t.Fatal("a session that failed to open did not fail the step")
	}
	s.db.Exec(`DROP TRIGGER no_sessions`)
	if _, ok, _ := s.TicketAttempt(ctx, []byte("t3"), t0, 5); !ok || left() != 1 {
		t.Errorf("after a session that failed to open: ticket usable %v, %d codes left", ok, left())
	}
}

// A code that confirms a change is spent in the change's transaction: a used
// code changes nothing, and a change that fails keeps the code (F59).
func TestChangesSpendTheirCodeWithTheChange(t *testing.T) {
	ctx := context.Background()
	for name, change := range map[string]func(s *Store, id int64, f *Factor) error{
		"password": func(s *Store, id int64, f *Factor) error {
			return s.SetPassword(ctx, id, []byte("new-salt"), "$argon2id$new", []byte("new-sealed"), renewal, f)
		},
		"disable": func(s *Store, id int64, f *Factor) error { return s.DisableTOTP(ctx, id, renewal, f) },
		"delete":  func(s *Store, id int64, f *Factor) error { return s.DeleteUser(ctx, id, t0, f) },
	} {
		t.Run(name, func(t *testing.T) {
			s := openTest(t)
			id, _ := s.CreateUser(ctx, user("alice"), 10)
			s.SetPendingTOTP(ctx, id, []byte("sealed"))
			s.EnableTOTP(ctx, id, []byte("sealed"), 100, [][]byte{[]byte("code")}, Renewal{SessionHash: []byte("first"), Now: t0})
			unchanged := func() bool {
				u, err := s.UserByID(ctx, id)
				n, _ := s.RecoveryCodesLeft(ctx, id)
				return err == nil && u.AuthHash == user("alice").AuthHash && u.TOTPSecret != nil && n == 1
			}
			for _, used := range []*Factor{{Step: 100}, {RecoveryHash: []byte("not-a-code")}} {
				if err := change(s, id, used); !errors.Is(err, ErrFactorUsed) || !unchanged() {
					t.Errorf("a used code %+v: %v", used, err)
				}
			}
			// The change fails after the code is spent: both roll back.
			if _, err := s.db.Exec(`
				CREATE TRIGGER no_update BEFORE UPDATE ON users BEGIN SELECT RAISE(ABORT, 'refused'); END;
				CREATE TRIGGER no_delete BEFORE DELETE ON users BEGIN SELECT RAISE(ABORT, 'refused'); END`); err != nil {
				t.Fatal(err)
			}
			if err := change(s, id, &Factor{RecoveryHash: []byte("code")}); err == nil || !unchanged() {
				t.Errorf("a change that failed: %v, or it spent the code", err)
			}
			s.db.Exec(`DROP TRIGGER no_update; DROP TRIGGER no_delete`)
			if err := change(s, id, &Factor{RecoveryHash: []byte("code")}); err != nil || unchanged() {
				t.Errorf("the change with an unused code: %v", err)
			}
		})
	}
}

// A change to how an account signs in ends the account's sessions and its
// sign-ins waiting for a second step, and nobody else's, and opens the
// renewal session in the same transaction: when that session cannot open,
// nothing changes (F43, F46).
func TestChangesRestartSignIns(t *testing.T) {
	ctx := context.Background()
	for name, change := range map[string]func(s *Store, id int64) error{
		"password": func(s *Store, id int64) error {
			return s.SetPassword(ctx, id, []byte("new-salt"), "$argon2id$new", []byte("new-sealed"), renewal, nil)
		},
		"enable": func(s *Store, id int64) error {
			if ok, err := s.EnableTOTP(ctx, id, []byte("sealed"), 1, nil, renewal); !ok {
				return errors.Join(errors.New("nothing pending"), err)
			}
			return nil
		},
		"disable": func(s *Store, id int64) error { return s.DisableTOTP(ctx, id, renewal, nil) },
	} {
		t.Run(name, func(t *testing.T) {
			s := openTest(t)
			alice, _ := s.CreateUser(ctx, user("alice"), 10)
			bob, _ := s.CreateUser(ctx, user("bob"), 10)
			s.SetPendingTOTP(ctx, alice, []byte("sealed"))
			// The existing sessions look newer than the renewal, as after the
			// clock was set back, so keeping only the newest would keep them.
			for _, id := range []int64{alice, bob} {
				key := []byte(fmt.Sprint("signed-in-", id))
				s.CreateSession(ctx, key, id, t0.Add(time.Hour), 10)
				s.CreateTicket(ctx, key, id, t0.Add(time.Minute))
			}
			state := func() string {
				var users, sessions, tickets string
				s.db.QueryRow(`SELECT group_concat(id || auth_hash || hex(ifnull(totp_secret, '')) || hex(ifnull(totp_pending, '')), ',') FROM users`).Scan(&users)
				s.db.QueryRow(`SELECT group_concat(user_id || hex(token_hash), ',') FROM (SELECT * FROM sessions ORDER BY token_hash)`).Scan(&sessions)
				s.db.QueryRow(`SELECT group_concat(user_id || hex(token_hash), ',') FROM (SELECT * FROM login_tickets ORDER BY token_hash)`).Scan(&tickets)
				return users + " | " + sessions + " | " + tickets
			}
			before := state()
			if _, err := s.db.Exec(`CREATE TRIGGER no_sessions BEFORE INSERT ON sessions BEGIN SELECT RAISE(ABORT, 'full'); END`); err != nil {
				t.Fatal(err)
			}
			if err := change(s, alice); err == nil {
				t.Fatal("the change went through without its session")
			}
			if after := state(); after != before {
				t.Errorf("a change whose session failed to open left\n%s\nwhere there was\n%s", after, before)
			}
			s.db.Exec(`DROP TRIGGER no_sessions`)
			if err := change(s, alice); err != nil {
				t.Fatal(err)
			}
			var sessions string
			s.db.QueryRow(`SELECT group_concat(CAST(token_hash AS TEXT), ',') FROM (SELECT * FROM sessions WHERE user_id = ? ORDER BY token_hash)`, alice).Scan(&sessions)
			if sessions != "renewed" {
				t.Errorf("the account's sessions after the change: %q", sessions)
			}
			if _, ok, _ := s.TicketAttempt(ctx, []byte(fmt.Sprint("signed-in-", alice)), t0, 5); ok {
				t.Error("the account's ticket outlived the change")
			}
			var others int
			s.db.QueryRow(`SELECT (SELECT COUNT(*) FROM sessions WHERE user_id = ?1) + (SELECT COUNT(*) FROM login_tickets WHERE user_id = ?1)`, bob).Scan(&others)
			if others != 2 {
				t.Errorf("another account kept %d of its session and ticket", others)
			}
		})
	}
}
