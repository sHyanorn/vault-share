package store

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestTOTPStepIsUsedOnce(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	id, _ := s.CreateUser(ctx, user("alice"), 10)
	if used, _ := s.UseTOTPStep(ctx, id, 100); used {
		t.Fatal("a step was used while two-factor sign-in is off")
	}
	s.SetPendingTOTP(ctx, id, []byte("sealed"))
	if ok, err := s.EnableTOTP(ctx, id, []byte("sealed"), 100, [][]byte{[]byte("a"), []byte("b")}); !ok || err != nil {
		t.Fatalf("enable: %v %v", ok, err)
	}
	// Two requests with the same code at once: one wins.
	var won atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if used, err := s.UseTOTPStep(ctx, id, 101); err != nil {
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
		if used, _ := s.UseTOTPStep(ctx, id, step); used != want {
			t.Errorf("step %d used %v, want %v", step, used, want)
		}
	}
	if n, _ := s.RecoveryCodesLeft(ctx, id); n != 2 {
		t.Errorf("%d recovery codes", n)
	}
	if ok, _ := s.EnableTOTP(ctx, id, []byte("again"), 0, nil); ok {
		t.Error("enabled without a pending secret")
	}
	if err := s.DisableTOTP(ctx, id); err != nil {
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
	s.EnableTOTP(ctx, id, []byte("sealed"), 100, [][]byte{[]byte("code-a"), []byte("code-b")})
	s.SecondStepFailed(ctx, id)
	s.SecondStepFailed(ctx, id)
	left := func() int {
		n, _ := s.RecoveryCodesLeft(ctx, id)
		return n
	}

	// A code already used keeps the ticket.
	s.CreateTicket(ctx, []byte("t1"), id, t0.Add(time.Minute))
	if _, err := s.CompleteSecondStep(ctx, []byte("t1"), id, t0, 100, nil); !errors.Is(err, ErrFactorUsed) {
		t.Errorf("a used step: %v", err)
	}
	if _, err := s.CompleteSecondStep(ctx, []byte("t1"), id, t0, 0, []byte("not-a-code")); !errors.Is(err, ErrFactorUsed) {
		t.Errorf("an unknown recovery code: %v", err)
	}
	failures, err := s.CompleteSecondStep(ctx, []byte("t1"), id, t0, 0, []byte("code-a"))
	if err != nil || failures != 2 || left() != 1 {
		t.Errorf("a recovery code: %d failures, %v, %d codes left", failures, err, left())
	}
	// A ticket already gone keeps the code.
	if _, err := s.CompleteSecondStep(ctx, []byte("t1"), id, t0, 0, []byte("code-b")); !errors.Is(err, ErrNotFound) || left() != 1 {
		t.Errorf("a used ticket: %v, %d codes left", err, left())
	}
	s.CreateTicket(ctx, []byte("t2"), id, t0.Add(time.Minute))
	if failures, err := s.CompleteSecondStep(ctx, []byte("t2"), id, t0, 101, nil); err != nil || failures != 0 {
		t.Errorf("a fresh step: %d failures, %v", failures, err)
	}
	if _, err := s.CompleteSecondStep(ctx, []byte("t2"), id, t0, 102, nil); !errors.Is(err, ErrNotFound) {
		t.Errorf("a second sign-in on one ticket: %v", err)
	}
}
