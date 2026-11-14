package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sHyanorn/vault-share/server/internal/audit"
)

// The production parameters take tens of milliseconds a hash and far longer
// under the race detector; TestAuthHashParameters covers them.
var testAuthParams = argonParams{memory: 64, time: 1, threads: 1}

// creds stands in for what the browser derives from a password (D026).
type creds struct {
	username           string
	salt, auth, sealed []byte
}

func newCreds(username string) creds {
	return creds{username: username, salt: randomBytes(16), auth: randomBytes(32), sealed: randomBytes(60)}
}

// browser keeps cookies like a browser would and speaks from its own
// address, so each browser is a client of its own.
type browser struct {
	e       *env
	addr    string
	cookies map[string]string
	// headers go on every request, as a browser's Fetch Metadata would.
	headers map[string]string
	last    http.Header
}

var browsers atomic.Int32

func (e *env) browser() *browser {
	n := browsers.Add(1)
	return &browser{e: e, addr: "198.51.100." + strconv.Itoa(int(n%250+1)), cookies: map[string]string{}}
}

func (b *browser) send(method, path string, body, out any) (int, []byte) {
	b.e.t.Helper()
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			b.e.t.Fatal(err)
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, b.e.srv.URL+path, reader)
	if err != nil {
		b.e.t.Fatal(err)
	}
	req.Header.Set("X-Forwarded-For", b.addr)
	for name, value := range b.headers {
		req.Header.Set(name, value)
	}
	for name, value := range b.cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	resp, err := b.e.srv.Client().Do(req)
	if err != nil {
		b.e.t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	for _, c := range resp.Cookies() {
		if c.MaxAge < 0 {
			delete(b.cookies, c.Name)
		} else {
			b.cookies[c.Name] = c.Value
		}
	}
	b.last = resp.Header
	if out != nil && resp.StatusCode < 300 {
		if err := json.Unmarshal(data, out); err != nil {
			b.e.t.Fatalf("decode %s %s: %v (%q)", method, path, err, data)
		}
	}
	return resp.StatusCode, data
}

// direct sends a request from b straight to the handler under ctx, as a
// client that may hang up while it is handled.
func (b *browser) direct(ctx context.Context, method, path string, body any) *httptest.ResponseRecorder {
	b.e.t.Helper()
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			b.e.t.Fatal(err)
		}
		reader = bytes.NewReader(data)
	}
	req := httptest.NewRequestWithContext(ctx, method, b.e.srv.URL+path, reader)
	for name, value := range b.cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	rec := httptest.NewRecorder()
	b.e.srv.Config.Handler.ServeHTTP(rec, req)
	return rec
}

// newHangUpEnv builds an account env and a source of request contexts that
// are cancelled when the next audit event is recorded, as if the client hung
// up right then.
func newHangUpEnv(t *testing.T) (*env, func() context.Context) {
	var hangUp atomic.Pointer[context.CancelFunc]
	e := newEnvWith(t, func(o *Options) {
		o.TrustedProxies = loopbackProxies
		auditor, err := audit.New(t.TempDir(), o.Store, o.Logger, func() time.Time {
			if cancel := hangUp.Swap(nil); cancel != nil {
				(*cancel)()
			}
			return o.Now()
		})
		if err != nil {
			t.Fatal(err)
		}
		o.Audit = auditor
	})
	return e, func() context.Context {
		ctx, cancel := context.WithCancel(context.Background())
		hangUp.Store(&cancel)
		return ctx
	}
}

func (b *browser) signup(c creds) (int, sessionResponse) {
	var resp sessionResponse
	status, _ := b.send(http.MethodPost, "/api/v1/account", signupRequest{
		Username: c.username, Salt: encoding.EncodeToString(c.salt),
		Auth: encoding.EncodeToString(c.auth), SealedKey: encoding.EncodeToString(c.sealed),
	}, &resp)
	return status, resp
}

func (b *browser) login(username string, auth []byte) (int, sessionResponse) {
	var resp sessionResponse
	status, _ := b.send(http.MethodPost, "/api/v1/session",
		loginRequest{Username: username, Auth: encoding.EncodeToString(auth)}, &resp)
	return status, resp
}

func (b *browser) current() (int, sessionResponse) {
	var resp sessionResponse
	status, _ := b.send(http.MethodGet, "/api/v1/session", nil, &resp)
	return status, resp
}

func (b *browser) salt(username string) (int, []byte) {
	var resp saltResponse
	status, _ := b.send(http.MethodPost, "/api/v1/account/salt", usernameRequest{Username: username}, &resp)
	salt, _ := encoding.DecodeString(resp.Salt)
	return status, salt
}

func newAccountEnv(t *testing.T) *env {
	return newEnvWith(t, func(o *Options) { o.TrustedProxies = loopbackProxies })
}

func errorCode(body []byte) string {
	var e errorBody
	_ = json.Unmarshal(body, &e)
	return e.Error.Code
}

func TestSignupStartsASession(t *testing.T) {
	e := newAccountEnv(t)
	b := e.browser()
	alice := newCreds("alice")
	var resp sessionResponse
	status, _ := b.send(http.MethodPost, "/api/v1/account", signupRequest{
		Username: alice.username, Salt: encoding.EncodeToString(alice.salt),
		Auth: encoding.EncodeToString(alice.auth), SealedKey: encoding.EncodeToString(alice.sealed),
	}, &resp)
	if status != http.StatusCreated || resp.Username != "alice" || resp.SealedKey != encoding.EncodeToString(alice.sealed) {
		t.Fatalf("sign-up: %d %+v", status, resp)
	}
	if b.last.Get("Cache-Control") != "no-store" {
		t.Error("a response with keys may be cached")
	}
	cookies := map[string]*http.Cookie{}
	for _, line := range b.last.Values("Set-Cookie") {
		c, err := http.ParseSetCookie(line)
		if err != nil {
			t.Fatal(err)
		}
		cookies[c.Name] = c
		if c.Path != "/" || c.Domain != "" || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
			t.Errorf("cookie attributes: %q", line)
		}
	}
	if c := cookies[sessionCookie]; c == nil || c.MaxAge != int(24*time.Hour/time.Second) || len(c.Value) != 43 {
		t.Errorf("session cookie: %+v", c)
	}
	if c := cookies[deviceCookie]; c == nil || c.MaxAge != int(deviceCookieAge/time.Second) {
		t.Errorf("device cookie: %+v", c)
	}
	if key, err := encoding.DecodeString(resp.DeviceKey); err != nil || len(key) != 32 {
		t.Errorf("device key %q", resp.DeviceKey)
	}
	status, now := b.current()
	if status != http.StatusOK || now.Username != "alice" || now.DeviceKey != resp.DeviceKey || now.SealedKey != "" {
		t.Errorf("session: %d %+v", status, now)
	}
}

func TestSignupValidation(t *testing.T) {
	e := newAccountEnv(t)
	good := newCreds("alice")
	valid := func() signupRequest {
		return signupRequest{Username: good.username, Salt: encoding.EncodeToString(good.salt),
			Auth: encoding.EncodeToString(good.auth), SealedKey: encoding.EncodeToString(good.sealed)}
	}
	cases := map[string]func(*signupRequest){
		"too short":       func(r *signupRequest) { r.Username = "al" },
		"too long":        func(r *signupRequest) { r.Username = strings.Repeat("a", 33) },
		"upper case":      func(r *signupRequest) { r.Username = "Alice" },
		"leading dash":    func(r *signupRequest) { r.Username = "-alice" },
		"space":           func(r *signupRequest) { r.Username = "al ice" },
		"not ascii":       func(r *signupRequest) { r.Username = "alïce" },
		"short salt":      func(r *signupRequest) { r.Salt = encoding.EncodeToString(randomBytes(15)) },
		"short auth":      func(r *signupRequest) { r.Auth = encoding.EncodeToString(randomBytes(31)) },
		"long sealed key": func(r *signupRequest) { r.SealedKey = encoding.EncodeToString(randomBytes(61)) },
		"padded auth":     func(r *signupRequest) { r.Auth += "=" },
	}
	for name, mutate := range cases {
		req := valid()
		mutate(&req)
		if status, body := e.browser().send(http.MethodPost, "/api/v1/account", req, nil); status != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, status, body)
		}
	}
	if status, _ := e.browser().send(http.MethodPost, "/api/v1/account", map[string]string{"username": "alice", "admin": "yes"}, nil); status != http.StatusBadRequest {
		t.Errorf("unknown field: %d", status)
	}
	if status, _ := e.browser().signup(good); status != http.StatusCreated {
		t.Fatalf("sign-up: %d", status)
	}
	if status, body := e.browser().send(http.MethodPost, "/api/v1/account", valid(), nil); status != http.StatusConflict || errorCode(body) != "username_taken" {
		t.Errorf("taken: %d %s", status, body)
	}

	closed := newEnvWith(t, func(o *Options) { o.SignupClosed = true })
	if status, body := closed.browser().send(http.MethodPost, "/api/v1/account", valid(), nil); status != http.StatusForbidden || errorCode(body) != "signup_closed" {
		t.Errorf("closed: %d %s", status, body)
	}
	full := newEnvWith(t, func(o *Options) { o.MaxAccounts = 1 })
	full.browser().signup(newCreds("first"))
	if status, body := full.browser().send(http.MethodPost, "/api/v1/account", valid(), nil); status != http.StatusServiceUnavailable || errorCode(body) != "capacity" {
		t.Errorf("full: %d %s", status, body)
	}
}

func TestSaltLookupRevealsNoAccount(t *testing.T) {
	key := randomBytes(32)
	e := newEnvWith(t, func(o *Options) { o.AccountKey = key })
	alice := newCreds("alice")
	e.browser().signup(alice)
	b := e.browser()
	if status, salt := b.salt("alice"); status != http.StatusOK || !bytes.Equal(salt, alice.salt) {
		t.Errorf("alice: %d %x", status, salt)
	}
	_, ghost := b.salt("ghost")
	_, again := b.salt("ghost")
	_, other := b.salt("phantom")
	if len(ghost) != 16 || !bytes.Equal(ghost, again) || bytes.Equal(ghost, other) {
		t.Errorf("fake salts %x %x %x", ghost, again, other)
	}
	// The fake salt survives a restart, as a real one would.
	restarted := newEnvWith(t, func(o *Options) { o.AccountKey = key })
	if _, salt := restarted.browser().salt("ghost"); !bytes.Equal(salt, ghost) {
		t.Error("fake salt changed with a restart")
	}
	if status, body := b.send(http.MethodPost, "/api/v1/account/salt", usernameRequest{Username: "Ghost"}, nil); status != http.StatusBadRequest || errorCode(body) != "invalid_username" {
		t.Errorf("malformed username: %d %s", status, body)
	}
}

func TestLogin(t *testing.T) {
	e := newAccountEnv(t)
	alice := newCreds("alice")
	e.browser().signup(alice)

	b := e.browser()
	status, resp := b.login("alice", alice.auth)
	if status != http.StatusOK || resp.SealedKey != encoding.EncodeToString(alice.sealed) || resp.DeviceKey == "" {
		t.Fatalf("login: %d %+v", status, resp)
	}
	if status, _ := b.current(); status != http.StatusOK {
		t.Errorf("session after login: %d", status)
	}
	first := b.cookies[sessionCookie]

	// Signing in again replaces the session the browser holds.
	if status, _ := b.login("alice", alice.auth); status != http.StatusOK || b.cookies[sessionCookie] == first {
		t.Fatalf("second login: %d", status)
	}
	stale := &browser{e: e, addr: b.addr, cookies: map[string]string{sessionCookie: first}}
	if status, _ := stale.current(); status != http.StatusUnauthorized {
		t.Errorf("the replaced session still works: %d", status)
	}

	// A wrong secret and an unknown username get the same answer.
	_, wrong := e.browser().send(http.MethodPost, "/api/v1/session",
		loginRequest{Username: "alice", Auth: encoding.EncodeToString(randomBytes(32))}, nil)
	_, unknown := e.browser().send(http.MethodPost, "/api/v1/session",
		loginRequest{Username: "nobody", Auth: encoding.EncodeToString(randomBytes(32))}, nil)
	if !bytes.Equal(wrong, unknown) || errorCode(wrong) != "login_failed" {
		t.Errorf("wrong secret %s, unknown user %s", wrong, unknown)
	}
	if status, _ := e.browser().send(http.MethodPost, "/api/v1/session", loginRequest{Username: "alice", Auth: "short"}, nil); status != http.StatusBadRequest {
		t.Errorf("malformed auth: %d", status)
	}
}

func TestSessionTimeouts(t *testing.T) {
	e := newAccountEnv(t)
	b := e.browser()
	b.signup(newCreds("alice"))

	// An hour without use ends a session; the store's tests cover the rest.
	e.advance(59 * time.Minute)
	if status, _ := b.current(); status != http.StatusOK {
		t.Fatalf("after 59 minutes: %d", status)
	}
	e.advance(time.Hour)
	if status, _ := b.current(); status != http.StatusUnauthorized {
		t.Errorf("an hour after the last use: %d", status)
	}
	if _, ok := b.cookies[sessionCookie]; ok {
		t.Error("the ended session's cookie was kept")
	}
}

func TestSessionsEndADayAfterSignIn(t *testing.T) {
	e := newAccountEnv(t)
	b := e.browser()
	b.signup(newCreds("alice"))
	for elapsed := 30 * time.Minute; elapsed < 24*time.Hour; elapsed += 30 * time.Minute {
		e.advance(30 * time.Minute)
		if status, _ := b.current(); status != http.StatusOK {
			t.Fatalf("after %v: %d", elapsed, status)
		}
	}
	e.advance(30 * time.Minute)
	if status, _ := b.current(); status != http.StatusUnauthorized {
		t.Errorf("a day after sign-in: %d", status)
	}
}

func TestLogout(t *testing.T) {
	e := newAccountEnv(t)
	b := e.browser()
	b.signup(newCreds("alice"))
	token := b.cookies[sessionCookie]
	if status, _ := b.send(http.MethodDelete, "/api/v1/session", nil, nil); status != http.StatusNoContent {
		t.Fatalf("logout: %d", status)
	}
	if _, ok := b.cookies[sessionCookie]; ok {
		t.Error("cookie kept after logout")
	}
	replay := &browser{e: e, addr: b.addr, cookies: map[string]string{sessionCookie: token}}
	if status, _ := replay.current(); status != http.StatusUnauthorized {
		t.Errorf("session usable after logout: %d", status)
	}
	if status, _ := e.browser().send(http.MethodDelete, "/api/v1/session", nil, nil); status != http.StatusNoContent {
		t.Errorf("logout without a session: %d", status)
	}
}

func TestSessionsPerAccountAreCapped(t *testing.T) {
	e := newAccountEnv(t)
	alice := newCreds("alice")
	first := e.browser()
	first.signup(alice)
	for i := 0; i < maxSessionsPerUser; i++ {
		e.advance(time.Second)
		if status, _ := e.browser().login("alice", alice.auth); status != http.StatusOK {
			t.Fatalf("login %d: %d", i, status)
		}
	}
	if status, _ := first.current(); status != http.StatusUnauthorized {
		t.Errorf("the oldest session survived %d newer ones: %d", maxSessionsPerUser, status)
	}
}

func TestAccountRequestsNeedASession(t *testing.T) {
	e := newAccountEnv(t)
	garbage := e.browser()
	garbage.cookies[sessionCookie] = encoding.EncodeToString(randomBytes(32))
	for _, b := range []*browser{e.browser(), garbage} {
		for _, req := range []struct{ method, path string }{
			{http.MethodGet, "/api/v1/session"},
			{http.MethodPost, "/api/v1/account/password"},
			{http.MethodDelete, "/api/v1/account"},
		} {
			if status, body := b.send(req.method, req.path, map[string]string{}, nil); status != http.StatusUnauthorized || errorCode(body) != "unauthenticated" {
				t.Errorf("%s %s: %d %s", req.method, req.path, status, body)
			}
		}
	}
}

func TestLoginLockouts(t *testing.T) {
	e := newAccountEnv(t)
	alice := newCreds("alice")
	owner := e.browser()
	owner.signup(alice) // the owner's browser now carries a device cookie
	wrong := randomBytes(32)

	// One client that keeps failing is refused that username.
	guesser := e.browser()
	for i := 0; i < lockoutFailures; i++ {
		if status, _ := guesser.login("alice", wrong); status != http.StatusUnauthorized {
			t.Fatalf("failure %d: %d", i, status)
		}
	}
	if status, _ := guesser.login("alice", alice.auth); status != http.StatusTooManyRequests || guesser.last.Get("Retry-After") != "900" {
		t.Errorf("locked client with the right secret: %d", status)
	}
	if status, _ := e.browser().login("alice", alice.auth); status != http.StatusOK {
		t.Errorf("another client: %d", status)
	}

	// Failures spread over many clients lock the account for unknown
	// browsers, but not for the owner's.
	for i := lockoutFailures; i < accountFailures; i++ {
		if status, _ := e.browser().login("alice", wrong); status != http.StatusUnauthorized {
			t.Fatalf("spread failure %d: %d", i, status)
		}
	}
	if status, _ := e.browser().login("alice", alice.auth); status != http.StatusTooManyRequests {
		t.Errorf("unknown browser on a locked account: %d", status)
	}
	if status, _ := owner.login("alice", alice.auth); status != http.StatusOK {
		t.Errorf("the owner's browser: %d", status)
	}
	// A device cookie counts only for the account it was issued for.
	bob := newCreds("bob")
	other := e.browser()
	other.signup(bob)
	if status, _ := other.login("alice", alice.auth); status != http.StatusTooManyRequests {
		t.Errorf("a browser known to another account: %d", status)
	}
	// A known browser that fails is counted on its own.
	for i := 0; i < lockoutFailures; i++ {
		owner.addr = "203.0.113." + strconv.Itoa(i+1) // the owner's laptop on the move
		owner.login("alice", wrong)
	}
	if status, _ := owner.login("alice", alice.auth); status != http.StatusTooManyRequests {
		t.Errorf("a known browser that failed %d times: %d", lockoutFailures, status)
	}

	// Usernames without an account lock the same way.
	for i := 0; i < lockoutFailures; i++ {
		guesser.login("ghost", wrong)
	}
	if status, _ := guesser.login("ghost", wrong); status != http.StatusTooManyRequests {
		t.Errorf("unknown username: %d", status)
	}

	e.advance(lockoutPeriod + time.Second)
	if status, _ := e.browser().login("alice", alice.auth); status != http.StatusOK {
		t.Errorf("after the lockout: %d", status)
	}

	entries, err := e.store.RecentAudit(context.Background(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	var unknownFailures int
	for _, entry := range entries {
		counts[entry.Event]++
		if entry.Event == audit.LoginFailed && entry.UserID == 0 {
			unknownFailures++
		}
	}
	if counts[audit.LoginFailed] != accountFailures+lockoutFailures+lockoutFailures || unknownFailures != lockoutFailures || counts[audit.ClientLocked] < 3 {
		t.Errorf("audit counts %v, failures for unknown users %d", counts, unknownFailures)
	}
}

// guesses sends n wrong auth secrets for username from b and returns how
// many of them were checked.
func (b *browser) guesses(username string, n int) int {
	b.e.t.Helper()
	checked := 0
	for range n {
		status, body := b.send(http.MethodPost, "/api/v1/session",
			loginRequest{Username: username, Auth: encoding.EncodeToString(randomBytes(32))}, nil)
		if status == http.StatusUnauthorized && errorCode(body) == "login_failed" {
			checked++
		}
	}
	return checked
}

// A device cookie counts only while the account signs in as it did when the
// cookie was issued, and an account knows at most deviceSlots browsers (F57).
func TestDeviceCookiesEndWithTheSignInTheyMark(t *testing.T) {
	e := newAccountEnv(t)
	// known signs n browsers in to c's account, each from its own address.
	known := func(c creds, n int) []*browser {
		t.Helper()
		browsers := make([]*browser, n)
		for i := range browsers {
			browsers[i] = e.browser()
			if status, _ := browsers[i].login(c.username, c.auth); status != http.StatusOK {
				t.Fatalf("sign-in %d to %s: %d", i, c.username, status)
			}
		}
		return browsers
	}
	// Eight browsers that once signed in get no more checked guesses than
	// the account allows browsers it does not know.
	guessed := func(browsers []*browser, username string) int {
		n := 0
		for _, b := range browsers {
			n += b.guesses(username, lockoutFailures)
		}
		return n
	}

	alice := newCreds("alice")
	owner := e.browser()
	owner.signup(alice)
	thieves := known(alice, 8)
	next := newCreds("alice")
	if status, body := owner.send(http.MethodPost, "/api/v1/account/password", passwordRequest{
		Auth: encoding.EncodeToString(alice.auth), Salt: encoding.EncodeToString(next.salt),
		NewAuth: encoding.EncodeToString(next.auth), SealedKey: encoding.EncodeToString(next.sealed),
	}, nil); status != http.StatusOK {
		t.Fatalf("password change: %d %s", status, body)
	}
	if n := guessed(thieves, "alice"); n != accountFailures {
		t.Errorf("after a password change: %d guesses checked, want %d", n, accountFailures)
	}

	bob := newCreds("bob")
	owner = e.browser()
	owner.signup(bob)
	thieves = known(bob, 8)
	owner.enableTOTP(bob)
	if n := guessed(thieves, "bob"); n != accountFailures {
		t.Errorf("after two-factor sign-in was turned on: %d guesses checked, want %d", n, accountFailures)
	}

	carol := newCreds("carol")
	owner = e.browser()
	owner.signup(carol)
	thieves = known(carol, 8)
	if status, _ := owner.send(http.MethodDelete, "/api/v1/account", confirmRequest{Auth: encoding.EncodeToString(carol.auth)}, nil); status != http.StatusNoContent {
		t.Fatalf("delete: %d", status)
	}
	if status, _ := e.browser().signup(newCreds("carol")); status != http.StatusCreated {
		t.Fatalf("a new account under the name: %d", status)
	}
	if n := guessed(thieves, "carol"); n != accountFailures {
		t.Errorf("for a new account under a deleted one's name: %d guesses checked, want %d", n, accountFailures)
	}

	dave := newCreds("dave")
	e.browser().signup(dave)
	cookies := map[string]bool{}
	for _, b := range known(dave, 40) {
		cookies[b.cookies[deviceCookie]] = true
	}
	if len(cookies) > deviceSlots {
		t.Errorf("40 sign-ins left %d distinct device cookies, want at most %d", len(cookies), deviceSlots)
	}
}

// The account is read before the lockouts are asked, yet a username without
// an account takes the same path as a browser the account does not know, so
// the answers tell nothing about which names exist.
func TestLockoutsAnswerUnknownUsernamesAlike(t *testing.T) {
	e := newAccountEnv(t)
	e.browser().signup(newCreds("alice"))
	other := e.browser()
	other.signup(newCreds("bob"))
	trace := func(username string) []string {
		var answers []string
		try := func(b *browser, n int) {
			for range n {
				status, body := b.send(http.MethodPost, "/api/v1/session",
					loginRequest{Username: username, Auth: encoding.EncodeToString(randomBytes(32))}, nil)
				answers = append(answers, fmt.Sprintf("%d %s %s", status, errorCode(body), b.last.Get("Retry-After")))
			}
		}
		// A browser known to another account, one with a cookie that does
		// not verify, then browsers without one.
		foreign := e.browser()
		foreign.cookies[deviceCookie] = other.cookies[deviceCookie]
		try(foreign, lockoutFailures+1)
		garbled := e.browser()
		garbled.cookies[deviceCookie] = encoding.EncodeToString(randomBytes(len(other.cookies[deviceCookie]) * 3 / 4))
		try(garbled, lockoutFailures+1)
		for range accountFailures {
			try(e.browser(), 1)
		}
		return answers
	}
	if known, unknown := trace("alice"), trace("ghost"); strings.Join(known, ", ") != strings.Join(unknown, ", ") {
		t.Errorf("an account:      %v\nno such account: %v", known, unknown)
	}
}

func TestPasswordChange(t *testing.T) {
	e := newAccountEnv(t)
	alice := newCreds("alice")
	b := e.browser()
	b.signup(alice)
	elsewhere := e.browser()
	elsewhere.login("alice", alice.auth)

	next := newCreds("alice")
	change := func(current []byte) (int, []byte) {
		return b.send(http.MethodPost, "/api/v1/account/password", passwordRequest{
			Auth: encoding.EncodeToString(current), Salt: encoding.EncodeToString(next.salt),
			NewAuth: encoding.EncodeToString(next.auth), SealedKey: encoding.EncodeToString(next.sealed),
		}, nil)
	}
	if status, body := change(randomBytes(32)); status != http.StatusForbidden || errorCode(body) != "wrong_password" {
		t.Fatalf("wrong current password: %d %s", status, body)
	}
	before := b.cookies[sessionCookie]
	var resp sessionResponse
	status, body := change(alice.auth)
	if status != http.StatusOK {
		t.Fatalf("change: %d %s", status, body)
	}
	_ = json.Unmarshal(body, &resp)
	if resp.SealedKey != encoding.EncodeToString(next.sealed) || b.cookies[sessionCookie] == before {
		t.Errorf("response %+v", resp)
	}
	if status, _ := b.current(); status != http.StatusOK {
		t.Errorf("this browser after the change: %d", status)
	}
	if status, _ := elsewhere.current(); status != http.StatusUnauthorized {
		t.Errorf("another session after the change: %d", status)
	}
	if status, _ := e.browser().login("alice", alice.auth); status != http.StatusUnauthorized {
		t.Errorf("the old password: %d", status)
	}
	if status, _ := e.browser().login("alice", next.auth); status != http.StatusOK {
		t.Errorf("the new password: %d", status)
	}
	if _, salt := e.browser().salt("alice"); !bytes.Equal(salt, next.salt) {
		t.Error("salt not replaced")
	}
}

func TestDeleteAccount(t *testing.T) {
	e := newAccountEnv(t)
	alice := newCreds("alice")
	b := e.browser()
	b.signup(alice)
	if status, _ := b.send(http.MethodDelete, "/api/v1/account", confirmRequest{Auth: encoding.EncodeToString(randomBytes(32))}, nil); status != http.StatusForbidden {
		t.Fatalf("wrong password: %d", status)
	}
	if status, _ := b.send(http.MethodDelete, "/api/v1/account", confirmRequest{Auth: encoding.EncodeToString(alice.auth)}, nil); status != http.StatusNoContent {
		t.Fatalf("delete: %d", status)
	}
	if len(b.cookies) != 0 {
		t.Errorf("cookies kept: %v", b.cookies)
	}
	if status, _ := e.browser().login("alice", alice.auth); status != http.StatusUnauthorized {
		t.Errorf("login after deletion: %d", status)
	}
	if status, _ := e.browser().signup(newCreds("alice")); status != http.StatusCreated {
		t.Errorf("the name is not free again: %d", status)
	}
}

func TestAccountAuditTrail(t *testing.T) {
	e := newAccountEnv(t)
	alice := newCreds("alice")
	b := e.browser()
	b.signup(alice)
	b.send(http.MethodDelete, "/api/v1/session", nil, nil)
	b.login("alice", alice.auth)
	next := newCreds("alice")
	b.send(http.MethodPost, "/api/v1/account/password", passwordRequest{
		Auth: encoding.EncodeToString(alice.auth), Salt: encoding.EncodeToString(next.salt),
		NewAuth: encoding.EncodeToString(next.auth), SealedKey: encoding.EncodeToString(next.sealed),
	}, nil)
	b.send(http.MethodDelete, "/api/v1/account", confirmRequest{Auth: encoding.EncodeToString(next.auth)}, nil)

	entries, err := e.store.RecentAudit(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	var events []string
	for i := len(entries) - 1; i >= 0; i-- {
		if entries[i].UserID == 0 || entries[i].IPHash == nil {
			t.Errorf("entry without account or client: %+v", entries[i])
		}
		events = append(events, entries[i].Event)
	}
	want := []string{audit.AccountCreated, audit.SessionEnded, audit.LoginSucceeded, audit.PasswordChanged, audit.AccountDeleted}
	if strings.Join(events, " ") != strings.Join(want, " ") {
		t.Errorf("events %v, want %v", events, want)
	}
}

func TestAccountLogsNeverContainSecrets(t *testing.T) {
	var logs bytes.Buffer
	e := newEnvWith(t, func(o *Options) {
		o.TrustedProxies = loopbackProxies
		o.Logger = slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	})
	alice := newCreds("alice")
	b := e.browser()
	_, signed := b.signup(alice)
	b.login("alice", randomBytes(32))
	_, session := b.login("alice", alice.auth)
	b.salt("alice")
	next := newCreds("alice")
	b.send(http.MethodPost, "/api/v1/account/password", passwordRequest{
		Auth: encoding.EncodeToString(alice.auth), Salt: encoding.EncodeToString(next.salt),
		NewAuth: encoding.EncodeToString(next.auth), SealedKey: encoding.EncodeToString(next.sealed),
	}, nil)
	sessionValue, deviceValue := b.cookies[sessionCookie], b.cookies[deviceCookie]
	b.send(http.MethodDelete, "/api/v1/session", nil, nil)

	out := logs.String()
	if !strings.Contains(out, `"path":"/api/v1/session"`) {
		t.Fatalf("request log missing: %s", out)
	}
	secrets := map[string]string{
		"auth secret":    encoding.EncodeToString(alice.auth),
		"new auth":       encoding.EncodeToString(next.auth),
		"sealed key":     encoding.EncodeToString(alice.sealed),
		"salt":           encoding.EncodeToString(alice.salt),
		"device key":     signed.DeviceKey,
		"later key":      session.DeviceKey,
		"session cookie": sessionValue,
		"device cookie":  deviceValue,
		"username":       "alice",
	}
	for name, secret := range secrets {
		if strings.Contains(out, secret) {
			t.Errorf("%s appears in the logs", name)
		}
	}
}

func TestAuthHashes(t *testing.T) {
	h := newHasher(testAuthParams)
	ctx := context.Background()
	secret := randomBytes(32)
	encoded, err := h.hash(ctx, secret)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := h.verify(ctx, encoded, secret); !ok || err != nil {
		t.Errorf("right secret: %v %v", ok, err)
	}
	if ok, _ := h.verify(ctx, encoded, randomBytes(32)); ok {
		t.Error("wrong secret accepted")
	}
	if ok, err := h.verify(ctx, "", secret); ok || err != nil {
		t.Errorf("unknown user: %v %v", ok, err)
	}
	again, _ := h.hash(ctx, secret)
	if again == encoded {
		t.Error("the salt is not random")
	}
	for _, bad := range []string{
		"", "$argon2i$v=19$m=64,t=1,p=1$c2FsdHNhbHQ$" + strings.Repeat("A", 43),
		strings.Replace(encoded, "v=19", "v=16", 1),
		strings.Replace(encoded, "m=64", "m=1048576", 1),
		strings.Replace(encoded, "t=1", "t=0", 1),
		strings.Replace(encoded, "p=1", "p=9", 1),
		strings.Replace(encoded, "m=64", "m=064", 1),
		encoded + "$",
		encoded + "=",
	} {
		if _, _, _, err := decodeHash(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestAuthHashParameters(t *testing.T) {
	// OWASP Password Storage Cheat Sheet: Argon2id with at least 19 MiB, two
	// passes and one lane.
	if defaultAuthParams != (argonParams{memory: 19 << 10, time: 2, threads: 1}) {
		t.Errorf("parameters %+v", defaultAuthParams)
	}
	h := newHasher(defaultAuthParams)
	secret := randomBytes(32)
	encoded, err := h.hash(context.Background(), secret)
	if err != nil || !strings.HasPrefix(encoded, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("hash %q: %v", encoded, err)
	}
	if ok, _ := h.verify(context.Background(), encoded, secret); !ok {
		t.Error("production hash does not verify")
	}
}

func TestHashingIsBounded(t *testing.T) {
	h := newHasher(testAuthParams)
	for i := 0; i < hashSlots; i++ {
		h.slots <- struct{}{}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := h.hash(ctx, randomBytes(32)); err != errBusy {
		t.Errorf("hash with every slot taken: %v", err)
	}
	if _, err := h.verify(ctx, "", randomBytes(32)); err != errBusy {
		t.Errorf("verify with every slot taken: %v", err)
	}
	<-h.slots
	if _, err := h.hash(context.Background(), randomBytes(32)); err != nil {
		t.Errorf("hash with a slot free: %v", err)
	}
}

// A sign-out ends the session even when the client hangs up at once (F46).
func TestSignOutFinishesAfterHangUp(t *testing.T) {
	e := newAccountEnv(t)
	b := e.browser()
	b.signup(newCreds("alice"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	b.direct(ctx, http.MethodDelete, "/api/v1/session", nil)
	if status, _ := b.current(); status != http.StatusUnauthorized {
		t.Errorf("a session after its sign-out: %d", status)
	}
}
