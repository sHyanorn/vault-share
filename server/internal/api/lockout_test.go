package api

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/sHyanorn/vault-share/server/internal/totp"
)

// Every admitted attempt ends once, however its caller leaves (F39, F44).

func TestLockoutAttemptsEndOnce(t *testing.T) {
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	l := newLockouts(lockoutFailures, func() time.Time { return now })

	// Attempts that pass, or end unchecked, count nothing and leave nothing.
	for range 100 {
		try, why := l.admit("k")
		if try == nil {
			t.Fatalf("refused after attempts that passed: %v", why)
		}
		try.end()
		try.end() // a second end changes nothing
	}
	for range 100 {
		try, _ := l.admit("k")
		try.pass(false)
	}
	if n := len(l.table.entries); n != 0 {
		t.Errorf("%d entries left by attempts that passed", n)
	}

	// Four failures and one attempt in flight: the next is refused for a
	// moment, not locked out.
	for range lockoutFailures - 1 {
		try, _ := l.admit("k")
		try.fail()
	}
	held, _ := l.admit("k")
	if try, why := l.admit("k"); try != nil || why != refusedBusy {
		t.Errorf("with the last attempt in flight: %v %v, want busy", try, why)
	}
	held.pass(false)
	last, _ := l.admit("k")
	if last == nil || !last.fail() {
		t.Fatal("the fifth failure did not lock")
	}
	if try, why := l.admit("k"); try != nil || why != refusedLocked {
		t.Errorf("after the fifth failure: %v %v, want locked", try, why)
	}

	// A pass that forgets drops the failures counted so far.
	for range lockoutFailures - 1 {
		try, _ := l.admit("f")
		try.fail()
	}
	try, _ := l.admit("f")
	try.pass(true)
	for range lockoutFailures - 1 {
		if try, _ := l.admit("f"); try == nil || try.fail() {
			t.Fatal("failures survived a forgetting pass")
		}
	}
}

func TestLockoutEvictionKeepsAttemptsInFlight(t *testing.T) {
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	l := newLockouts(lockoutFailures, func() time.Time { return now })
	// A full table in which every key has an attempt in flight: no entry
	// may make room for a new key.
	held := make([]*attempt, 0, maxEntries)
	for i := range maxEntries {
		try, _ := l.admit(strconv.Itoa(i))
		held = append(held, try)
	}
	if try, _ := l.admit("new"); try == nil {
		t.Fatal("a new key was refused")
	}
	if n := len(l.table.entries); n != maxEntries+1 {
		t.Fatalf("%d entries: an entry with an attempt in flight was evicted", n)
	}
	// Once the attempts end, their entries make room again.
	for _, try := range held {
		try.fail()
	}
	l.admit("newer")
	if n := len(l.table.entries); n != maxEntries {
		t.Errorf("%d entries after the attempts ended, cap %d", n, maxEntries)
	}
}

func TestAttemptsThatPassLeaveNoTrace(t *testing.T) {
	e := newAccountEnv(t)
	alice := newCreds("alice")
	b := e.browser()
	b.signup(alice)
	for i := range 3 * accountFailures {
		if status, _ := b.login("alice", alice.auth); status != http.StatusOK {
			t.Fatalf("sign-in %d: %d", i, status)
		}
	}
	secret, _ := b.enableTOTP(alice)
	for i := range 3 * lockoutFailures {
		e.advance(totp.Period)
		if status, _, body := e.browser().secondStep(alice, e.code(secret, 0)); status != http.StatusOK {
			t.Fatalf("second step %d: %d %s", i, status, body)
		}
	}
	sh := e.shared(100, 3*lockoutFailures, 3600)
	for i := range 3 * lockoutFailures {
		if _, status := e.token(sh); status != http.StatusOK {
			t.Fatalf("download %d: %d", i, status)
		}
	}
}

// A sign-in refused only because others are in flight is told to retry in
// a moment, not to wait out a lockout (F42).
func TestAttemptsInFlightAnswerBusy(t *testing.T) {
	e := newAccountEnv(t)
	alice := newCreds("alice")
	e.browser().signup(alice)
	a := &accounts{store: e.store, hasher: newHasher(testAuthParams), keys: deriveServerKeys(randomBytes(32)),
		clientLocks: newLockouts(lockoutFailures, e.clock), accountLocks: newLockouts(accountFailures, e.clock),
		deviceLocks: newLockouts(lockoutFailures, e.clock), totpLocks: newLockouts(lockoutFailures, e.clock),
		now: e.clock, log: slog.New(slog.DiscardHandler)}
	r, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "/", nil)
	clientKey := bucketFrom(r.Context()) + "|alice"
	for range lockoutFailures - 1 {
		try, _ := a.clientLocks.admit(clientKey)
		try.fail()
	}
	held, _ := a.clientLocks.admit(clientKey)
	if _, result := a.authenticate(r, "alice", alice.auth); result != authBusy {
		t.Errorf("with an attempt in flight: %v, want busy", result)
	}
	held.end()
	if _, result := a.authenticate(r, "alice", alice.auth); result != authOK {
		t.Errorf("once it ended: %v", result)
	}
}

// A sign-in that passes forgets the failures of its client and of its known
// browser, but not those counted for unknown browsers, so a guesser's
// failures survive the owner's sign-ins (D027).
func TestSignInsForgetOnlyTheirOwnFailures(t *testing.T) {
	e := newAccountEnv(t)
	alice := newCreds("alice")
	e.browser().signup(alice)
	wrong := randomBytes(32)
	fails := func(b *browser, n int, forget bool) {
		t.Helper()
		for i := range n {
			if forget {
				b.cookies = map[string]string{} // stays an unknown browser
			}
			if status, _ := b.login("alice", wrong); status != http.StatusUnauthorized {
				t.Fatalf("failure %d: %d", i, status)
			}
		}
	}

	// The client: failures, a success, failures again stay below its limit.
	b := e.browser()
	fails(b, lockoutFailures-1, true)
	b.login("alice", alice.auth)
	fails(b, lockoutFailures-1, true)

	// The known browser likewise, from wherever it signs in.
	known := e.browser()
	known.login("alice", alice.auth)
	for range lockoutFailures - 1 {
		known.addr = "203.0.113." + strconv.Itoa(int(browsers.Add(1)%250+1))
		known.login("alice", wrong)
	}
	known.login("alice", alice.auth)
	for range lockoutFailures - 1 {
		known.addr = "203.0.113." + strconv.Itoa(int(browsers.Add(1)%250+1))
		if status, _ := known.login("alice", wrong); status != http.StatusUnauthorized {
			t.Fatalf("the known browser after its success: %d", status)
		}
	}

	// Unknown browsers: 2*(lockoutFailures-1) failures counted so far; their
	// count reaches the limit however many sign-ins pass in between.
	for i := 2 * (lockoutFailures - 1); i < accountFailures-1; i++ {
		fails(e.browser(), 1, true)
	}
	e.browser().login("alice", alice.auth)
	fails(e.browser(), 1, true)
	if status, _ := e.browser().login("alice", alice.auth); status != http.StatusTooManyRequests {
		t.Errorf("unknown browsers after %d failures: %d", accountFailures, status)
	}
}
