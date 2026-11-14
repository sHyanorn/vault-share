package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/sHyanorn/vault-share/server/internal/audit"
	"github.com/sHyanorn/vault-share/server/internal/store"
)

// Accounts (D026, D027). The browser derives everything from the password:
// the server receives a salt, an auth secret it hashes again, and the
// account key sealed under the password, and it hands out sessions.

const (
	saltBytes      = 16
	authBytes      = 32
	sealedKeyBytes = 12 + 32 + 16
	// maxSessionsPerUser ends the oldest sessions of an account that signs
	// in again and again.
	maxSessionsPerUser = 10
	// Password lockouts: a client is refused a username after
	// lockoutFailures failures, unknown browsers are refused it after
	// accountFailures failures from anywhere, and a known browser after
	// lockoutFailures of its own. The second step allows lockoutFailures
	// in each (D035).
	accountFailures = 20
)

var usernamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,31}$`)

type accounts struct {
	store  *store.Store
	audit  *audit.Recorder
	hasher *hasher
	keys   serverKeys
	// Failures of each step of signing in, and of the changes confirmed
	// from each session (D027, D035).
	password, secondStep signInLocks
	sessionLocks         *lockouts
	// issuer names the service in authenticator apps.
	issuer      string
	signup      bool
	maxAccounts int
	now         func() time.Time
	log         *slog.Logger
}

type signupRequest struct {
	Username  string `json:"username"`
	Salt      string `json:"salt"`
	Auth      string `json:"auth"`
	SealedKey string `json:"sealed_key"`
}

type sessionResponse struct {
	Username  string `json:"username"`
	DeviceKey string `json:"device_key"`
	SealedKey string `json:"sealed_key,omitempty"`
	// TOTP tells whether two-factor sign-in is on.
	TOTP bool `json:"totp"`
	// RecoveryCodes are shown once, when two-factor sign-in is turned on.
	RecoveryCodes []string `json:"recovery_codes,omitempty"`
	// RecoveryCodesLeft follows a sign-in with a recovery code.
	RecoveryCodesLeft *int `json:"recovery_codes_left,omitempty"`
	// SecondStepFailures counts second steps that failed after a right
	// password since the last sign-in, so the owner learns their password
	// is known (OWASP Multifactor Authentication Cheat Sheet).
	SecondStepFailures int `json:"second_step_failures,omitempty"`
}

func (a *accounts) signupHandler(w http.ResponseWriter, r *http.Request) {
	if !a.signup {
		writeError(w, http.StatusForbidden, "signup_closed", "sign-up is closed")
		return
	}
	var req signupRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	salt, okSalt := decodeFixed(req.Salt, saltBytes)
	auth, okAuth := decodeFixed(req.Auth, authBytes)
	sealed, okSealed := decodeFixed(req.SealedKey, sealedKeyBytes)
	switch {
	case !usernamePattern.MatchString(req.Username):
		invalidUsername(w)
		return
	case !okSalt || !okAuth || !okSealed:
		writeError(w, http.StatusBadRequest, "invalid_request", "salt, auth and sealed_key must be base64url of 16, 32 and 60 bytes")
		return
	}
	ctx := r.Context()
	encoded, err := a.hasher.hash(ctx, auth)
	if err != nil {
		busy(w)
		return
	}
	u := store.User{Username: req.Username, Salt: salt, AuthHash: encoded, SealedKey: sealed, CreatedAt: a.now()}
	u.ID, err = a.store.CreateUser(ctx, u, a.maxAccounts)
	switch {
	case errors.Is(err, store.ErrUsernameTaken):
		writeError(w, http.StatusConflict, "username_taken", "that username is taken")
		return
	case errors.Is(err, store.ErrCapacity):
		writeError(w, http.StatusServiceUnavailable, "capacity", "no new accounts can be opened now")
		return
	case err != nil:
		internalError(w, a.log, "create account", err)
		return
	}
	a.audit.RecordAccount(ctx, audit.AccountCreated, u.ID, clientFrom(ctx))
	a.startSession(w, r, u, http.StatusCreated)
}

type usernameRequest struct {
	Username string `json:"username"`
}

type saltResponse struct {
	Salt string `json:"salt"`
}

// saltHandler returns the salt the browser derives the password with. A
// username without an account gets a stable salt of its own.
func (a *accounts) saltHandler(w http.ResponseWriter, r *http.Request) {
	var req usernameRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !usernamePattern.MatchString(req.Username) {
		invalidUsername(w)
		return
	}
	salt := a.fakeSalt(req.Username)
	u, err := a.store.UserByName(r.Context(), req.Username)
	switch {
	case err == nil:
		salt = u.Salt
	case !errors.Is(err, store.ErrNotFound):
		internalError(w, a.log, "load account", err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, saltResponse{Salt: encoding.EncodeToString(salt)})
}

type loginRequest struct {
	Username string `json:"username"`
	Auth     string `json:"auth"`
}

func (a *accounts) loginHandler(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	auth, ok := decodeFixed(req.Auth, authBytes)
	if !usernamePattern.MatchString(req.Username) || !ok {
		writeError(w, http.StatusBadRequest, "invalid_request", "username and auth must be well-formed")
		return
	}
	u, result := a.authenticate(r, req.Username, auth, nil)
	switch result {
	case authOK:
	case authFailed:
		writeError(w, http.StatusUnauthorized, "login_failed", "wrong username or password")
		return
	default:
		refuse(w, result)
		return
	}
	ctx := r.Context()
	if u.TOTPSecret != nil {
		ticket := randomBytes(tokenBytes)
		if err := a.store.CreateTicket(ctx, hashToken(ticket), u.ID, a.now().Add(ticketTTL)); err != nil {
			internalError(w, a.log, "create ticket", err)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, secondStepResponse{SecondStep: true, Ticket: encoding.EncodeToString(ticket)})
		return
	}
	a.audit.RecordAccount(ctx, audit.LoginSucceeded, u.ID, clientFrom(ctx))
	a.startSession(w, r, u, http.StatusOK)
}

type authResult int

const (
	authOK authResult = iota
	authFailed
	authLocked
	authBusy
	authError
)

// signInLocks count the failures of one step of signing in: per client and
// username, per device cookie for browsers the account knows, and per
// username for all others together (D027, D035).
type signInLocks struct {
	client, account, device *lockouts
}

// newSignInLocks allows lockoutFailures per client and per known browser,
// and perAccount to all other browsers together.
func newSignInLocks(perAccount int, now func() time.Time) signInLocks {
	return signInLocks{
		client:  newLockouts(lockoutFailures, now),
		account: newLockouts(perAccount, now),
		device:  newLockouts(lockoutFailures, now),
	}
}

// stepLocks names the locks a sign-in step for u counts under, reached
// through r: its client's, and its browser's if u knows the browser, or
// else the account's. Failures counted for the account are others' too, so
// a step that passes forgets only the client's and the browser's.
func (a *accounts) stepLocks(r *http.Request, step signInLocks, username string, u store.User) []lock {
	client := lock{step.client, bucketFrom(r.Context()) + "|" + username, true}
	if device, known := a.knownDevice(r, u); known {
		return []lock{client, {step.device, device, true}}
	}
	return []lock{client, {step.account, username, false}}
}

// sessionLock counts the failures of one step of the changes confirmed from
// session s, apart from every sign-in: only its holder can fail there
// (D035).
func (a *accounts) sessionLock(s session, step string) lock {
	return lock{a.sessionLocks, step + "|" + encoding.EncodeToString(hashToken(s.token)), true}
}

// authenticate checks auth for username. A sign-in counts under the
// password step's lockouts; a change confirmed from session s, when s is
// not nil, under that session's own. An unknown username fails the same way
// and after the same work as a wrong secret, and counts against the same
// lockouts.
func (a *accounts) authenticate(r *http.Request, username string, auth []byte, s *session) (store.User, authResult) {
	ctx := r.Context()
	// The account comes first, since a device cookie counts only for the
	// account as it signs in now. A username without one is empty here and
	// takes the path of a browser the account does not know.
	u, err := a.store.UserByName(ctx, username)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		a.log.Error("load account", "err", err)
		return store.User{}, authError
	}
	locks := a.stepLocks(r, a.password, username, u)
	if s != nil {
		locks = []lock{a.sessionLock(*s, "password")}
	}
	try, why := admitAll(locks...)
	if why != 0 {
		return store.User{}, why.result()
	}
	defer try.end()
	ok, err := a.hasher.verify(ctx, u.AuthHash, auth)
	switch {
	case errors.Is(err, errBusy):
		return store.User{}, authBusy
	case err != nil:
		a.log.Error("verify password", "err", err)
		return store.User{}, authError
	case ok:
		try.pass()
		return u, authOK
	}
	client := clientFrom(ctx)
	a.audit.RecordAccount(ctx, audit.LoginFailed, u.ID, client)
	if try.fail() {
		a.audit.RecordAccount(ctx, audit.ClientLocked, u.ID, client)
	}
	return store.User{}, authFailed
}

// result is how a refused attempt is answered: a lockout in force asks for
// its whole period, attempts in flight only for a moment.
func (r refusal) result() authResult {
	if r == refusedBusy {
		return authBusy
	}
	return authLocked
}

// refuse answers an attempt that was not checked: a lockout is in force,
// too many attempts are in flight, or an error stopped it, which is already
// logged. A wrong secret is for the caller to answer.
func refuse(w http.ResponseWriter, result authResult) {
	switch result {
	case authLocked:
		w.Header().Set("Retry-After", strconv.Itoa(int(lockoutPeriod/time.Second)))
		writeError(w, http.StatusTooManyRequests, "locked", "too many failed attempts, try again later")
	case authBusy:
		busy(w)
	default:
		writeInternalError(w)
	}
}

// startSession signs the client in to u with a fresh session and answers
// with it.
func (a *accounts) startSession(w http.ResponseWriter, r *http.Request, u store.User, status int) {
	if !a.endPresentedSession(w, r) {
		return
	}
	token := randomBytes(tokenBytes)
	if err := a.store.CreateSession(r.Context(), hashToken(token), u.ID, a.now(), maxSessionsPerUser); err != nil {
		internalError(w, a.log, "create session", err)
		return
	}
	a.setSessionCookies(w, u, token)
	writeSession(w, status, a.signedIn(u, token))
}

// endPresentedSession ends the session cookie the client holds, if any, so
// a sign-in never reuses it and no one can fix a session on a victim before
// sign-in. It answers the request itself when that fails.
func (a *accounts) endPresentedSession(w http.ResponseWriter, r *http.Request) bool {
	old, ok := sessionToken(r)
	if !ok {
		return true
	}
	if err := a.store.DeleteSession(r.Context(), hashToken(old)); err != nil {
		internalError(w, a.log, "end session", err)
		return false
	}
	return true
}

// setSessionCookies sets the session and marks the browser as known to u as
// u signs in now, so callers pass u as the change they made left it.
func (a *accounts) setSessionCookies(w http.ResponseWriter, u store.User, token []byte) {
	setCookie(w, sessionCookie, encoding.EncodeToString(token), store.SessionLifetime)
	setCookie(w, deviceCookie, a.newDeviceCookie(u), deviceCookieAge)
}

// signedIn describes a fresh session, the sealed account key included.
func (a *accounts) signedIn(u store.User, token []byte) sessionResponse {
	return sessionResponse{
		Username:  u.Username,
		DeviceKey: a.deviceKey(token),
		SealedKey: encoding.EncodeToString(u.SealedKey),
		TOTP:      u.TOTPSecret != nil,
	}
}

func writeSession(w http.ResponseWriter, status int, resp sessionResponse) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, status, resp)
}

// currentHandler describes the signed-in account and returns the device key.
func (a *accounts) currentHandler(w http.ResponseWriter, r *http.Request) {
	s := sessionFrom(r.Context())
	writeSession(w, http.StatusOK, sessionResponse{
		Username:  s.user.Username,
		DeviceKey: a.deviceKey(s.token),
		TOTP:      s.user.TOTPSecret != nil,
	})
}

// logoutHandler ends the session the request carries, if any, even when the
// client hangs up meanwhile (F46).
func (a *accounts) logoutHandler(w http.ResponseWriter, r *http.Request) {
	ctx := context.WithoutCancel(r.Context())
	if token, ok := sessionToken(r); ok {
		hash := hashToken(token)
		u, valid, err := a.store.SessionUser(ctx, hash, a.now())
		if err == nil {
			err = a.store.DeleteSession(ctx, hash)
		}
		if err != nil {
			internalError(w, a.log, "end session", err)
			return
		}
		if valid {
			a.audit.RecordAccount(ctx, audit.SessionEnded, u.ID, clientFrom(ctx))
		}
	}
	clearCookie(w, sessionCookie)
	w.WriteHeader(http.StatusNoContent)
}

type passwordRequest struct {
	Auth      string `json:"auth"`
	Salt      string `json:"salt"`
	NewAuth   string `json:"new_auth"`
	SealedKey string `json:"sealed_key"`
	// Code is a TOTP or recovery code, needed while two-factor sign-in is on.
	Code string `json:"code,omitempty"`
}

// passwordHandler replaces the password: the current one is asked for
// again, and in the same transaction every session of the account ends and
// this browser gets a new one.
func (a *accounts) passwordHandler(w http.ResponseWriter, r *http.Request) {
	var req passwordRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	auth, okAuth := decodeFixed(req.Auth, authBytes)
	salt, okSalt := decodeFixed(req.Salt, saltBytes)
	newAuth, okNew := decodeFixed(req.NewAuth, authBytes)
	sealed, okSealed := decodeFixed(req.SealedKey, sealedKeyBytes)
	if !okAuth || !okSalt || !okNew || !okSealed {
		writeError(w, http.StatusBadRequest, "invalid_request", "auth, salt, new_auth and sealed_key must be base64url of 32, 16, 32 and 60 bytes")
		return
	}
	if overlongCode(w, req.Code) {
		return
	}
	ctx := r.Context()
	token := randomBytes(tokenBytes)
	var encoded string
	u, ok := a.confirm(w, r, auth, req.Code, "set password", func(u store.User, f *store.Factor) error {
		var err error
		if encoded, err = a.hasher.hash(ctx, newAuth); err != nil {
			return err
		}
		return a.store.SetPassword(ctx, u.ID, salt, encoded, sealed, a.renewal(token), f)
	})
	if !ok {
		return
	}
	a.audit.RecordAccount(ctx, audit.PasswordChanged, u.ID, clientFrom(ctx))
	u.AuthHash, u.SealedKey = encoded, sealed
	a.setSessionCookies(w, u, token)
	writeSession(w, http.StatusOK, a.signedIn(u, token))
}

// renewal is the session with token that replaces all of an account's
// sessions in the transaction of a change to how it signs in, so no step
// after the commit can leave the old ones (F46).
func (a *accounts) renewal(token []byte) store.Renewal {
	return store.Renewal{SessionHash: hashToken(token), Now: a.now()}
}

type confirmRequest struct {
	Auth string `json:"auth"`
	// Code is a TOTP or recovery code, needed while two-factor sign-in is on.
	Code string `json:"code,omitempty"`
}

// deleteHandler removes the account once the password is given again. Its
// files go with it.
func (a *accounts) deleteHandler(w http.ResponseWriter, r *http.Request) {
	var req confirmRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	auth, ok := decodeFixed(req.Auth, authBytes)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_request", "auth must be base64url of 32 bytes")
		return
	}
	if overlongCode(w, req.Code) {
		return
	}
	ctx := r.Context()
	u, ok := a.confirm(w, r, auth, req.Code, "delete account", func(u store.User, f *store.Factor) error {
		return a.store.DeleteUser(ctx, u.ID, a.now(), f)
	})
	if !ok {
		return
	}
	a.audit.RecordAccount(ctx, audit.AccountDeleted, u.ID, clientFrom(ctx))
	clearCookie(w, sessionCookie)
	clearCookie(w, deviceCookie)
	w.WriteHeader(http.StatusNoContent)
}

func invalidUsername(w http.ResponseWriter) {
	writeError(w, http.StatusBadRequest, "invalid_username",
		"a username has 3 to 32 lowercase letters, digits, dots, dashes or underscores, and starts with a letter or digit")
}

func busy(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "5")
	writeError(w, http.StatusServiceUnavailable, "busy", "too many sign-ins at once, try again shortly")
}
