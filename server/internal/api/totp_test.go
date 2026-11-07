package api

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/sHyanorn/vault-share/server/internal/audit"
	"github.com/sHyanorn/vault-share/server/internal/totp"
)

// code is what the authenticator app shows at the env's time, offset by
// whole steps.
func (e *env) code(secret []byte, steps int64) string {
	return totp.Code(secret, totp.Step(e.clock())+steps, totp.Digits)
}

// enableTOTP sets up two-factor sign-in on b's account and returns the
// secret and the recovery codes. The clock then moves one step on, so the
// code used to enable is in the past.
func (b *browser) enableTOTP(c creds) ([]byte, []string) {
	b.e.t.Helper()
	var setup totpSetupResponse
	if status, body := b.send(http.MethodPost, "/api/v1/account/totp/setup", nil, &setup); status != http.StatusOK {
		b.e.t.Fatalf("setup: %d %s", status, body)
	}
	secret, err := totp.Encoding.DecodeString(setup.Secret)
	if err != nil {
		b.e.t.Fatal(err)
	}
	var resp sessionResponse
	if status, body := b.send(http.MethodPost, "/api/v1/account/totp",
		totpRequest{Auth: encoding.EncodeToString(c.auth), Code: b.e.code(secret, 0)}, &resp); status != http.StatusOK {
		b.e.t.Fatalf("enable: %d %s", status, body)
	}
	b.e.advance(totp.Period)
	return secret, resp.RecoveryCodes
}

// secondStep signs in with a password and then code, and returns the
// status of the second step and its answer.
func (b *browser) secondStep(c creds, code string) (int, sessionResponse, []byte) {
	b.e.t.Helper()
	var first secondStepResponse
	if status, body := b.send(http.MethodPost, "/api/v1/session",
		loginRequest{Username: c.username, Auth: encoding.EncodeToString(c.auth)}, &first); status != http.StatusOK || !first.SecondStep {
		b.e.t.Fatalf("first step: %d %s", status, body)
	}
	var resp sessionResponse
	status, body := b.send(http.MethodPost, "/api/v1/session/totp", secondStepRequest{Ticket: first.Ticket, Code: code}, &resp)
	return status, resp, body
}

func TestTOTPSetup(t *testing.T) {
	e := newAccountEnv(t)
	alice := newCreds("alice")
	b := e.browser()
	b.signup(alice)
	elsewhere := e.browser()
	elsewhere.login("alice", alice.auth)

	var setup totpSetupResponse
	b.send(http.MethodPost, "/api/v1/account/totp/setup", nil, &setup)
	secret, err := totp.Encoding.DecodeString(setup.Secret)
	if err != nil || len(secret) != totp.SecretBytes || !strings.HasPrefix(setup.URI, "otpauth://totp/vault-share:alice?") {
		t.Fatalf("setup %+v: %v", setup, err)
	}
	enable := func(auth []byte, code string) (int, []byte) {
		return b.send(http.MethodPost, "/api/v1/account/totp", totpRequest{Auth: encoding.EncodeToString(auth), Code: code}, nil)
	}
	if status, body := enable(randomBytes(32), e.code(secret, 0)); status != http.StatusForbidden || errorCode(body) != "wrong_password" {
		t.Errorf("wrong password: %d %s", status, body)
	}
	if status, body := enable(alice.auth, e.code(secret, 2)); status != http.StatusForbidden || errorCode(body) != "wrong_code" {
		t.Errorf("wrong code: %d %s", status, body)
	}
	before := b.cookies[sessionCookie]
	var resp sessionResponse
	status, body := b.send(http.MethodPost, "/api/v1/account/totp",
		totpRequest{Auth: encoding.EncodeToString(alice.auth), Code: e.code(secret, 0)}, &resp)
	if status != http.StatusOK || !resp.TOTP || len(resp.RecoveryCodes) != recoveryCodeCount {
		t.Fatalf("enable: %d %s", status, body)
	}
	seen := map[string]bool{}
	for _, code := range resp.RecoveryCodes {
		if !regexp.MustCompile(`^[a-z2-7]{4}(-[a-z2-7]{4}){3}$`).MatchString(code) || seen[code] {
			t.Errorf("recovery code %q", code)
		}
		seen[code] = true
	}
	if b.cookies[sessionCookie] == before {
		t.Error("the session was not renewed")
	}
	if status, s := b.current(); status != http.StatusOK || !s.TOTP {
		t.Errorf("session after enabling: %d %+v", status, s)
	}
	if status, _ := elsewhere.current(); status != http.StatusUnauthorized {
		t.Errorf("another session survived: %d", status)
	}
	if status, body := b.send(http.MethodPost, "/api/v1/account/totp/setup", nil, nil); status != http.StatusConflict || errorCode(body) != "totp_on" {
		t.Errorf("setup while on: %d %s", status, body)
	}

	// The secret is kept sealed and bound to its account.
	u, err := e.store.UserByName(context.Background(), "alice")
	if err != nil || bytes.Contains(u.TOTPSecret, secret) || len(u.TOTPSecret) != 12+totp.SecretBytes+16 {
		t.Errorf("stored secret %x: %v", u.TOTPSecret, err)
	}

	bob := newCreds("bob")
	other := e.browser()
	other.signup(bob)
	if status, body := other.send(http.MethodPost, "/api/v1/account/totp",
		totpRequest{Auth: encoding.EncodeToString(bob.auth), Code: "123456"}, nil); status != http.StatusConflict || errorCode(body) != "no_setup" {
		t.Errorf("enable without setup: %d %s", status, body)
	}
}

func TestSealedTOTPSecretsAreBound(t *testing.T) {
	a := &accounts{keys: deriveServerKeys(randomBytes(32))}
	secret := randomBytes(totp.SecretBytes)
	sealed := a.sealTOTP(7, secret)
	if got, err := a.openTOTP(7, sealed); err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("open: %v", err)
	}
	if _, err := a.openTOTP(8, sealed); err == nil {
		t.Error("a secret opened for another account")
	}
	other := &accounts{keys: deriveServerKeys(randomBytes(32))}
	if _, err := other.openTOTP(7, sealed); err == nil {
		t.Error("a secret opened under another key")
	}
}

func TestSignInWithTOTP(t *testing.T) {
	e := newAccountEnv(t)
	alice := newCreds("alice")
	owner := e.browser()
	owner.signup(alice)
	secret, _ := owner.enableTOTP(alice)

	b := e.browser()
	var first secondStepResponse
	b.send(http.MethodPost, "/api/v1/session", loginRequest{Username: "alice", Auth: encoding.EncodeToString(alice.auth)}, &first)
	if !first.SecondStep || len(first.Ticket) != 43 || len(b.cookies) != 0 {
		t.Fatalf("first step: %+v, cookies %v", first, b.cookies)
	}
	code := e.code(secret, 0)
	var resp sessionResponse
	if status, body := b.send(http.MethodPost, "/api/v1/session/totp", secondStepRequest{Ticket: first.Ticket, Code: code[:3] + " " + code[3:]}, &resp); status != http.StatusOK {
		t.Fatalf("second step: %d %s", status, body)
	}
	if resp.Username != "alice" || resp.SealedKey != encoding.EncodeToString(alice.sealed) || !resp.TOTP || b.cookies[sessionCookie] == "" {
		t.Errorf("session %+v", resp)
	}
	// The same code never works twice, not even in the same step.
	if status, _, body := e.browser().secondStep(alice, code); status != http.StatusUnauthorized || errorCode(body) != "wrong_code" {
		t.Errorf("replayed code: %d %s", status, body)
	}
	e.advance(totp.Period)
	for offset, want := range map[int64]int{-1: http.StatusUnauthorized, 2: http.StatusUnauthorized, 1: http.StatusOK} {
		// -1 is the step already used above; +2 is too far ahead.
		if status, _, body := e.browser().secondStep(alice, e.code(secret, offset)); status != want {
			t.Errorf("code %d steps away: %d %s", offset, status, body)
		}
	}
}

func TestSecondStepTickets(t *testing.T) {
	e := newAccountEnv(t)
	alice := newCreds("alice")
	owner := e.browser()
	owner.signup(alice)
	secret, _ := owner.enableTOTP(alice)
	ticket := func(b *browser) string {
		var first secondStepResponse
		b.send(http.MethodPost, "/api/v1/session", loginRequest{Username: "alice", Auth: encoding.EncodeToString(alice.auth)}, &first)
		return first.Ticket
	}
	step := func(b *browser, ticket, code string) (int, string) {
		status, body := b.send(http.MethodPost, "/api/v1/session/totp", secondStepRequest{Ticket: ticket, Code: code}, nil)
		return status, errorCode(body)
	}

	// A ticket takes maxTicketAttempts wrong codes, then it is gone, before
	// the lockout of the account is even asked.
	b := e.browser()
	tk := ticket(b)
	for i := 0; i < maxTicketAttempts; i++ {
		step(b, tk, "000000")
	}
	if status, code := step(b, tk, e.code(secret, 0)); status != http.StatusUnauthorized || code != "ticket_expired" {
		t.Errorf("a ticket after %d failures: %d %s", maxTicketAttempts, status, code)
	}
	e.advance(lockoutPeriod + time.Second)

	// A ticket lasts five minutes and serves one sign-in.
	tk = ticket(b)
	e.advance(ticketTTL)
	if status, code := step(b, tk, e.code(secret, 0)); status != http.StatusUnauthorized || code != "ticket_expired" {
		t.Errorf("an old ticket: %d %s", status, code)
	}
	tk = ticket(b)
	if status, _ := step(b, tk, e.code(secret, 0)); status != http.StatusOK {
		t.Fatalf("a fresh ticket: %d", status)
	}
	e.advance(totp.Period)
	if status, code := step(e.browser(), tk, e.code(secret, 0)); status != http.StatusUnauthorized || code != "ticket_expired" {
		t.Errorf("a used ticket: %d %s", status, code)
	}
	if status, _ := step(b, "short", "123456"); status != http.StatusBadRequest {
		t.Errorf("malformed ticket: %d", status)
	}
	if status, _ := step(b, ticket(b), strings.Repeat("1", 33)); status != http.StatusBadRequest {
		t.Errorf("oversized code: %d", status)
	}
}

func TestRecoveryCodes(t *testing.T) {
	e := newAccountEnv(t)
	alice := newCreds("alice")
	owner := e.browser()
	owner.signup(alice)
	_, codes := owner.enableTOTP(alice)
	typed := strings.ToUpper(strings.ReplaceAll(codes[3], "-", ""))
	status, resp, body := e.browser().secondStep(alice, typed)
	if status != http.StatusOK || resp.RecoveryCodesLeft == nil || *resp.RecoveryCodesLeft != recoveryCodeCount-1 {
		t.Fatalf("recovery code: %d %s", status, body)
	}
	if status, _, _ := e.browser().secondStep(alice, codes[3]); status != http.StatusUnauthorized {
		t.Errorf("a spent recovery code: %d", status)
	}
	if status, resp, _ := e.browser().secondStep(alice, codes[4]); status != http.StatusOK || *resp.RecoveryCodesLeft != recoveryCodeCount-2 {
		t.Errorf("another recovery code: %d %+v", status, resp)
	}
}

func TestSecondStepLockout(t *testing.T) {
	e := newAccountEnv(t)
	alice := newCreds("alice")
	owner := e.browser()
	owner.signup(alice)
	secret, _ := owner.enableTOTP(alice)
	// Failures from many browsers and tickets count against the account.
	for i := 0; i < lockoutFailures; i++ {
		if status, _, _ := e.browser().secondStep(alice, "000000"); status != http.StatusUnauthorized {
			t.Fatalf("failure %d: %d", i, status)
		}
	}
	if status, _, body := e.browser().secondStep(alice, e.code(secret, 0)); status != http.StatusTooManyRequests || errorCode(body) != "locked" {
		t.Errorf("locked account with the right code: %d %s", status, body)
	}
	e.advance(lockoutPeriod + time.Second)
	status, resp, _ := e.browser().secondStep(alice, e.code(secret, 0))
	if status != http.StatusOK || resp.SecondStepFailures != lockoutFailures {
		t.Errorf("after the lockout: %d, %d failures reported", status, resp.SecondStepFailures)
	}
	e.advance(totp.Period)
	if _, resp, _ := e.browser().secondStep(alice, e.code(secret, 0)); resp.SecondStepFailures != 0 {
		t.Errorf("failures reported twice: %d", resp.SecondStepFailures)
	}
}

func TestDisableTOTP(t *testing.T) {
	e := newAccountEnv(t)
	alice := newCreds("alice")
	b := e.browser()
	b.signup(alice)
	secret, codes := b.enableTOTP(alice)
	disable := func(code string) (int, []byte) {
		return b.send(http.MethodDelete, "/api/v1/account/totp", totpRequest{Auth: encoding.EncodeToString(alice.auth), Code: code}, nil)
	}
	if status, body := disable(""); status != http.StatusForbidden || errorCode(body) != "wrong_code" {
		t.Errorf("without a code: %d %s", status, body)
	}
	if status, body := disable(e.code(secret, 0)); status != http.StatusOK {
		t.Fatalf("disable: %d %s", status, body)
	}
	if status, s := b.current(); status != http.StatusOK || s.TOTP {
		t.Errorf("session after disabling: %d %+v", status, s)
	}
	if status, resp := e.browser().login("alice", alice.auth); status != http.StatusOK || resp.Username != "alice" {
		t.Errorf("password-only sign-in: %d", status)
	}
	if status, body := disable(codes[0]); status != http.StatusConflict || errorCode(body) != "totp_off" {
		t.Errorf("disable while off: %d %s", status, body)
	}
	// Turning it on again starts from a new secret and new codes.
	_, again := b.enableTOTP(alice)
	if status, _, _ := e.browser().secondStep(alice, codes[0]); status != http.StatusUnauthorized {
		t.Errorf("an old recovery code after re-enabling: %d", status)
	}
	if status, _, _ := e.browser().secondStep(alice, again[0]); status != http.StatusOK {
		t.Errorf("a new recovery code: %d", status)
	}
}

func TestChangesNeedTheCodeWhileTOTPIsOn(t *testing.T) {
	e := newAccountEnv(t)
	alice := newCreds("alice")
	b := e.browser()
	b.signup(alice)
	secret, codes := b.enableTOTP(alice)
	next := newCreds("alice")
	change := func(code string) (int, []byte) {
		return b.send(http.MethodPost, "/api/v1/account/password", passwordRequest{
			Auth: encoding.EncodeToString(alice.auth), Salt: encoding.EncodeToString(next.salt),
			NewAuth: encoding.EncodeToString(next.auth), SealedKey: encoding.EncodeToString(next.sealed), Code: code,
		}, nil)
	}
	if status, body := change(""); status != http.StatusForbidden || errorCode(body) != "wrong_code" {
		t.Errorf("password change without a code: %d %s", status, body)
	}
	if status, body := change(e.code(secret, 0)); status != http.StatusOK {
		t.Fatalf("password change: %d %s", status, body)
	}
	remove := func(code string) int {
		status, _ := b.send(http.MethodDelete, "/api/v1/account", confirmRequest{Auth: encoding.EncodeToString(next.auth), Code: code}, nil)
		return status
	}
	if status := remove(""); status != http.StatusForbidden {
		t.Errorf("deletion without a code: %d", status)
	}
	if status := remove(codes[0]); status != http.StatusNoContent {
		t.Errorf("deletion with a recovery code: %d", status)
	}
}

func TestTOTPAuditAndLogs(t *testing.T) {
	var logs bytes.Buffer
	e := newEnvWith(t, func(o *Options) {
		o.TrustedProxies = loopbackProxies
		o.Logger = slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	})
	alice := newCreds("alice")
	b := e.browser()
	b.signup(alice)
	var setup totpSetupResponse
	b.send(http.MethodPost, "/api/v1/account/totp/setup", nil, &setup)
	secret, _ := totp.Encoding.DecodeString(setup.Secret)
	var enabled sessionResponse
	b.send(http.MethodPost, "/api/v1/account/totp", totpRequest{Auth: encoding.EncodeToString(alice.auth), Code: e.code(secret, 0)}, &enabled)
	e.advance(totp.Period)
	var first secondStepResponse
	b.send(http.MethodPost, "/api/v1/session", loginRequest{Username: "alice", Auth: encoding.EncodeToString(alice.auth)}, &first)
	b.send(http.MethodPost, "/api/v1/session/totp", secondStepRequest{Ticket: first.Ticket, Code: "000000"}, nil)
	b.send(http.MethodPost, "/api/v1/session/totp", secondStepRequest{Ticket: first.Ticket, Code: enabled.RecoveryCodes[0]}, nil)
	b.send(http.MethodDelete, "/api/v1/account/totp", totpRequest{Auth: encoding.EncodeToString(alice.auth), Code: e.code(secret, 0)}, nil)

	entries, err := e.store.RecentAudit(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, entry := range entries {
		counts[entry.Event]++
	}
	for _, event := range []string{audit.TOTPEnabled, audit.TOTPFailed, audit.RecoveryCodeUsed, audit.TOTPDisabled} {
		if counts[event] != 1 {
			t.Errorf("%s recorded %d times: %v", event, counts[event], counts)
		}
	}
	out := logs.String()
	for name, secret := range map[string]string{
		"TOTP secret":   setup.Secret,
		"otpauth URI":   "otpauth",
		"ticket":        first.Ticket,
		"recovery code": enabled.RecoveryCodes[0],
		"code":          e.code(secret, 0),
	} {
		if strings.Contains(out, secret) {
			t.Errorf("%s appears in the logs", name)
		}
	}
}
