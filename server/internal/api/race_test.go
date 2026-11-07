package api

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"testing"

	"github.com/sHyanorn/vault-share/server/internal/audit"
)

// Requests that arrive together must not get more attempts than the
// lockouts allow (F38, F39): each attempt is admitted before it is checked.

// parallel runs n requests at once and counts their error codes.
func parallel(n int, request func(i int) []byte) map[string]int {
	var mu sync.Mutex
	codes := map[string]int{}
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			code := errorCode(request(i))
			mu.Lock()
			codes[code]++
			mu.Unlock()
		})
	}
	wg.Wait()
	return codes
}

func TestConcurrentSignInsRespectTheLockouts(t *testing.T) {
	// A real cost, so many sign-ins are in flight at once as in production,
	// yet well within the test server's write timeout under the race detector.
	saved := authParams
	authParams = argonParams{memory: 2 << 10, time: 1, threads: 1}
	defer func() { authParams = saved }()
	e := newAccountEnv(t)
	alice := newCreds("alice")
	e.browser().signup(alice)
	wrong := encoding.EncodeToString(randomBytes(32))

	// From many clients: the username locks for unknown browsers after
	// accountFailures checks, however they arrive.
	codes := parallel(50, func(i int) []byte {
		b := &browser{e: e, addr: "203.0.113." + strconv.Itoa(i+1), cookies: map[string]string{}}
		_, body := b.send(http.MethodPost, "/api/v1/session", loginRequest{Username: "alice", Auth: wrong}, nil)
		return body
	})
	if codes["login_failed"] != accountFailures || codes["locked"] != 50-accountFailures {
		t.Errorf("50 sign-ins at once from 50 clients: %v, want %d checked", codes, accountFailures)
	}

	// From one client: that client locks after lockoutFailures checks.
	codes = parallel(20, func(int) []byte {
		b := &browser{e: e, addr: "198.51.100.200", cookies: map[string]string{}}
		_, body := b.send(http.MethodPost, "/api/v1/session", loginRequest{Username: "bob", Auth: wrong}, nil)
		return body
	})
	if codes["login_failed"] != lockoutFailures {
		t.Errorf("20 sign-ins at once from one client: %v, want %d checked", codes, lockoutFailures)
	}
}

func TestConcurrentSecondStepsRespectTheLimits(t *testing.T) {
	e := newAccountEnv(t)
	alice := newCreds("alice")
	owner := e.browser()
	owner.signup(alice)
	owner.enableTOTP(alice)
	ticket := func() string {
		var first secondStepResponse
		e.browser().send(http.MethodPost, "/api/v1/session", loginRequest{Username: "alice", Auth: encoding.EncodeToString(alice.auth)}, &first)
		return first.Ticket
	}
	step := func(ticket, code string) []byte {
		_, body := e.browser().send(http.MethodPost, "/api/v1/session/totp", secondStepRequest{Ticket: ticket, Code: code}, nil)
		return body
	}

	// One ticket checks at most maxTicketAttempts codes, and the account at
	// most lockoutFailures in its window, however many arrive at once.
	one := ticket()
	codes := parallel(40, func(int) []byte { return step(one, "000000") })
	if codes["wrong_code"] > maxTicketAttempts {
		t.Errorf("40 codes at once on one ticket: %v, want at most %d checked", codes, maxTicketAttempts)
	}
	e.advance(lockoutPeriod + 1)
	tickets := make([]string, 8)
	for i := range tickets {
		tickets[i] = ticket()
	}
	codes = parallel(40, func(i int) []byte { return step(tickets[i%len(tickets)], "000000") })
	if codes["wrong_code"] > lockoutFailures {
		t.Errorf("40 codes at once over 8 tickets: %v, want at most %d checked", codes, lockoutFailures)
	}
}

func TestConcurrentDownloadsRespectTheLockout(t *testing.T) {
	e := newEnvWith(t, func(o *Options) { o.TrustedProxies = loopbackProxies })
	sh := e.shared(100, 50, 3600)
	wrong := randomBytes(32)
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() { e.downloadFrom(sh, "203.0.113.9", wrong) })
	}
	wg.Wait()
	entries, err := e.store.RecentAudit(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	denied := 0
	for _, entry := range entries {
		if entry.Event == audit.DownloadDenied {
			denied++
		}
	}
	if denied != lockoutFailures {
		t.Errorf("20 bad signatures at once: %d checked, want %d", denied, lockoutFailures)
	}
}

// A code is spent together with its ticket: of several valid recovery
// codes sent at once on one ticket, one signs in and only that one is used.
func TestSecondStepSpendsTheCodeWithTheTicket(t *testing.T) {
	e := newAccountEnv(t)
	alice := newCreds("alice")
	owner := e.browser()
	owner.signup(alice)
	_, codes := owner.enableTOTP(alice)
	var first secondStepResponse
	e.browser().send(http.MethodPost, "/api/v1/session", loginRequest{Username: "alice", Auth: encoding.EncodeToString(alice.auth)}, &first)
	results := parallel(5, func(i int) []byte {
		_, body := e.browser().send(http.MethodPost, "/api/v1/session/totp", secondStepRequest{Ticket: first.Ticket, Code: codes[i]}, nil)
		return body
	})
	u, _ := e.store.UserByName(context.Background(), "alice")
	left, _ := e.store.RecoveryCodesLeft(context.Background(), u.ID)
	if results[""] != 1 || left != recoveryCodeCount-1 {
		t.Errorf("5 recovery codes at once on one ticket: %v, %d codes left, want one sign-in and %d left",
			results, left, recoveryCodeCount-1)
	}
}
