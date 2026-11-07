package store

import (
	"context"
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

func TestTickets(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	id, _ := s.CreateUser(ctx, user("alice"), 10)
	s.CreateTicket(ctx, []byte("ticket"), id, t0.Add(5*time.Minute))
	if got, ok, _ := s.TicketUser(ctx, []byte("ticket"), t0); !ok || got != id {
		t.Fatalf("ticket: %d %v", got, ok)
	}
	if _, ok, _ := s.TicketUser(ctx, []byte("ticket"), t0.Add(5*time.Minute)); ok {
		t.Error("an expired ticket is valid")
	}
	if err := s.ExpireTickets(ctx, t0.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if used, _ := s.UseTicket(ctx, []byte("ticket"), t0); used {
		t.Error("an expired ticket survived cleanup")
	}
}
