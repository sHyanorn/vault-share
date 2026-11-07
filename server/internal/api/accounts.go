package api

import (
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
	// Sign-in lockouts: a client is refused a username after
	// lockoutFailures failures, unknown browsers are refused it after
	// accountFailures failures from anywhere, and a known browser after
	// lockoutFailures of its own.
	accountFailures = 20
)

var usernamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,31}$`)

type accounts struct {
	store  *store.Store
	audit  *audit.Recorder
	hasher *hasher
	keys   serverKeys
	// Failures per client and username, per username for browsers not known
	// to the account, per device cookie for known ones, and second steps per
	// account.
	clientLocks, accountLocks, deviceLocks, totpLocks *lockouts
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
		a.internalError(w, "create account", err)
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
		a.internalError(w, "load account", err)
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
	u, result := a.authenticate(r, req.Username, auth)
	if result != authOK {
		a.refuse(w, result, http.StatusUnauthorized, "login_failed", "wrong username or password")
		return
	}
	ctx := r.Context()
	if u.TOTPSecret != nil {
		ticket := randomBytes(tokenBytes)
		if err := a.store.CreateTicket(ctx, hashToken(ticket), u.ID, a.now().Add(ticketTTL)); err != nil {
			a.internalError(w, "create ticket", err)
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

// authenticate checks auth for username under the sign-in lockouts. An
// unknown username fails the same way and after the same work as a wrong
// secret, and counts against the same lockouts.
func (a *accounts) authenticate(r *http.Request, username string, auth []byte) (store.User, authResult) {
	ctx := r.Context()
	clientKey := bucketFrom(ctx) + "|" + username
	scope, scopeKey := a.accountLocks, username
	if device, known := a.knownDevice(r, username); known {
		scope, scopeKey = a.deviceLocks, device
	}
	byClient, why := a.clientLocks.admit(clientKey)
	if byClient == nil {
		return store.User{}, why.result()
	}
	defer byClient.end()
	inScope, why := scope.admit(scopeKey)
	if inScope == nil {
		return store.User{}, why.result()
	}
	defer inScope.end()
	// An attempt that cannot be checked ends uncounted.
	u, err := a.store.UserByName(ctx, username)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		a.log.Error("load account", "err", err)
		return store.User{}, authError
	}
	ok, err := a.hasher.verify(ctx, u.AuthHash, auth)
	switch {
	case errors.Is(err, errBusy):
		return store.User{}, authBusy
	case err != nil:
		a.log.Error("verify password", "err", err)
		return store.User{}, authError
	case ok:
		byClient.pass(true)
		inScope.pass(scope == a.deviceLocks)
		return u, authOK
	}
	client := clientFrom(ctx)
	a.audit.RecordAccount(ctx, audit.LoginFailed, u.ID, client)
	lockedClient := byClient.fail()
	if inScope.fail() || lockedClient {
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

// refuse answers a failed authenticate; status, code and message describe
// a wrong secret.
func (a *accounts) refuse(w http.ResponseWriter, result authResult, status int, code, message string) {
	switch result {
	case authLocked:
		w.Header().Set("Retry-After", strconv.Itoa(int(lockoutPeriod/time.Second)))
		writeError(w, http.StatusTooManyRequests, "locked", "too many failed attempts, try again later")
	case authBusy:
		busy(w)
	case authError:
		writeError(w, http.StatusInternalServerError, "internal", "internal error")
	default:
		writeError(w, status, code, message)
	}
}

// issueSession signs the client in to u with a fresh session and returns
// the token. A session cookie the client already holds is ended, never
// reused, so no one can fix a session on a victim before sign-in.
func (a *accounts) issueSession(w http.ResponseWriter, r *http.Request, u store.User) ([]byte, bool) {
	ctx := r.Context()
	if old, ok := sessionToken(r); ok {
		if err := a.store.DeleteSession(ctx, hashToken(old)); err != nil {
			a.internalError(w, "end session", err)
			return nil, false
		}
	}
	token := randomBytes(tokenBytes)
	if err := a.store.CreateSession(ctx, hashToken(token), u.ID, a.now(), maxSessionsPerUser); err != nil {
		a.internalError(w, "create session", err)
		return nil, false
	}
	setCookie(w, sessionCookie, encoding.EncodeToString(token), store.SessionLifetime)
	setCookie(w, deviceCookie, a.newDeviceCookie(u.Username), deviceCookieAge)
	return token, true
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

func (a *accounts) startSession(w http.ResponseWriter, r *http.Request, u store.User, status int) {
	token, ok := a.issueSession(w, r, u)
	if !ok {
		return
	}
	writeSession(w, status, a.signedIn(u, token))
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

// logoutHandler ends the session the request carries, if any.
func (a *accounts) logoutHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if token, ok := sessionToken(r); ok {
		u, valid, err := a.store.SessionUser(ctx, hashToken(token), a.now())
		if err == nil {
			err = a.store.DeleteSession(ctx, hashToken(token))
		}
		if err != nil {
			a.internalError(w, "end session", err)
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
// again, every session of the account ends, and this browser gets a new one.
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
	ctx := r.Context()
	u, ok := a.reauthenticate(w, r, auth, req.Code)
	if !ok {
		return
	}
	encoded, err := a.hasher.hash(ctx, newAuth)
	if err != nil {
		busy(w)
		return
	}
	if err := a.store.SetPassword(ctx, u.ID, salt, encoded, sealed); err != nil {
		a.internalError(w, "set password", err)
		return
	}
	a.audit.RecordAccount(ctx, audit.PasswordChanged, u.ID, clientFrom(ctx))
	u.SealedKey = sealed
	resp, ok := a.renewSessions(w, r, u)
	if !ok {
		return
	}
	writeSession(w, http.StatusOK, resp)
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
	ctx := r.Context()
	u, ok := a.reauthenticate(w, r, auth, req.Code)
	if !ok {
		return
	}
	if err := a.store.DeleteUser(ctx, u.ID, a.now()); err != nil {
		a.internalError(w, "delete account", err)
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

func (a *accounts) internalError(w http.ResponseWriter, what string, err error) {
	a.log.Error(what, "err", err)
	writeError(w, http.StatusInternalServerError, "internal", "internal error")
}
