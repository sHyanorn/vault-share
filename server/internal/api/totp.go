package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/sHyanorn/vault-share/server/internal/audit"
	"github.com/sHyanorn/vault-share/server/internal/store"
	"github.com/sHyanorn/vault-share/server/internal/totp"
)

// Two-factor sign-in with TOTP (D029).

const (
	// ticketTTL is how long a right password waits for its second step,
	// and maxTicketAttempts how many codes one ticket may try.
	ticketTTL         = 5 * time.Minute
	maxTicketAttempts = 5
)

type secondStepResponse struct {
	SecondStep bool   `json:"second_step"`
	Ticket     string `json:"ticket"`
}

// A factor is a second-step code that may be good: a TOTP time step whose
// code matched, or a well-formed recovery code, by its hash. Whether it is
// still unused is known only when it is spent.
type factor struct {
	step     int64
	recovery []byte
}

func (a *accounts) matchFactor(u store.User, code string) (factor, bool, error) {
	code = strings.NewReplacer(" ", "", "-", "").Replace(code)
	if len(code) == totp.Digits {
		secret, err := a.openTOTP(u.ID, u.TOTPSecret)
		if err != nil {
			return factor{}, false, err
		}
		step, ok := totp.Match(secret, code, a.now())
		return factor{step: step}, ok, nil
	}
	hash, ok := recoveryCodeHash(code)
	return factor{recovery: hash}, ok, nil
}

// secondFactor checks a code for the account under locks: match reads the
// code as a factor, and spend uses the factor up, reporting false if it
// already was. An error from either ends the attempt uncounted and is
// returned.
func (a *accounts) secondFactor(ctx context.Context, userID int64, locks []lock, match func() (factor, bool, error), spend func(factor) (bool, error)) (authResult, factor, error) {
	try, why := admitAll(locks...)
	if why != 0 {
		return why.result(), factor{}, nil
	}
	defer try.end()
	f, ok, err := match()
	if err == nil && ok {
		ok, err = spend(f)
	}
	if err != nil {
		return authError, f, err
	}
	client := clientFrom(ctx)
	if ok {
		try.pass()
		if f.recovery != nil {
			a.audit.RecordAccount(ctx, audit.RecoveryCodeUsed, userID, client)
		}
		return authOK, f, nil
	}
	a.audit.RecordAccount(ctx, audit.TOTPFailed, userID, client)
	if try.fail() {
		a.audit.RecordAccount(ctx, audit.ClientLocked, userID, client)
	}
	return authFailed, f, nil
}

// reauthenticate asks the signed-in owner for the password again before a
// change that could lock them out. Failures count in the session alone
// (D035). It answers the request itself when that fails.
func (a *accounts) reauthenticate(w http.ResponseWriter, r *http.Request, auth []byte) (store.User, bool) {
	s := sessionFrom(r.Context())
	u, result := a.authenticate(r, s.user.Username, auth, &s)
	switch result {
	case authOK:
		return u, true
	case authFailed:
		writeError(w, http.StatusForbidden, "wrong_password", "the password is wrong")
	default:
		refuse(w, result)
	}
	return store.User{}, false
}

// confirm makes a change once the signed-in owner has given the password
// again, and a code while two-factor sign-in is on. change makes the change
// and spends the code, nil without one, in one transaction, so a code is
// used up only by a change that happened (F59); it returns
// store.ErrFactorUsed for a code already used. confirm answers the request
// itself unless the change was made, and returns the account as it was.
func (a *accounts) confirm(w http.ResponseWriter, r *http.Request, auth []byte, code, what string, change func(store.User, *store.Factor) error) (store.User, bool) {
	u, ok := a.reauthenticate(w, r, auth)
	if !ok {
		return store.User{}, false
	}
	if u.TOTPSecret == nil {
		if err := change(u, nil); err != nil {
			a.changeFailed(w, what, err)
			return store.User{}, false
		}
		return u, true
	}
	ctx := r.Context()
	match := func() (factor, bool, error) { return a.matchFactor(u, code) }
	locks := []lock{a.sessionLock(sessionFrom(ctx), "code")}
	result, _, err := a.secondFactor(ctx, u.ID, locks, match, func(f factor) (bool, error) {
		err := change(u, &store.Factor{Step: f.step, RecoveryHash: f.recovery})
		if errors.Is(err, store.ErrFactorUsed) {
			return false, nil
		}
		return err == nil, err
	})
	switch {
	case err != nil:
		a.changeFailed(w, what, err)
	case result == authOK:
		return u, true
	case result == authFailed:
		writeError(w, http.StatusForbidden, "wrong_code", "the code is wrong")
	default:
		refuse(w, result)
	}
	return store.User{}, false
}

// changeFailed answers a change that could not be made: busy while every
// hashing slot is taken, an internal error otherwise.
func (a *accounts) changeFailed(w http.ResponseWriter, what string, err error) {
	if errors.Is(err, errBusy) {
		busy(w)
		return
	}
	internalError(w, a.log, what, err)
}

type secondStepRequest struct {
	Ticket string `json:"ticket"`
	Code   string `json:"code"`
}

// secondStepHandler completes a sign-in whose password was right. The
// ticket gives up one of its attempts before the code is checked, and a
// good code is spent together with the ticket (F38).
func (a *accounts) secondStepHandler(w http.ResponseWriter, r *http.Request) {
	var req secondStepRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	ticket, ok := decodeFixed(req.Ticket, tokenBytes)
	if !ok || req.Code == "" || len(req.Code) > 32 {
		writeError(w, http.StatusBadRequest, "invalid_request", "ticket and code must be well-formed")
		return
	}
	ctx := r.Context()
	now := a.now()
	ticketHash := hashToken(ticket)
	userID, valid, err := a.store.TicketAttempt(ctx, ticketHash, now, maxTicketAttempts)
	if err != nil {
		internalError(w, a.log, "take ticket attempt", err)
		return
	}
	var u store.User
	if valid {
		u, err = a.store.UserByID(ctx, userID)
	}
	switch {
	// Two-factor sign-in turned off since the ticket was issued ends it too.
	case !valid || errors.Is(err, store.ErrNotFound) || (err == nil && u.TOTPSecret == nil):
		expiredTicket(w)
		return
	case err != nil:
		internalError(w, a.log, "load account", err)
		return
	}
	if !a.endPresentedSession(w, r) {
		return
	}
	// The session opens in the transaction that spends the ticket and the
	// code, so neither is spent without it (F41).
	token := randomBytes(tokenBytes)
	var failures int
	match := func() (factor, bool, error) { return a.matchFactor(u, req.Code) }
	locks := a.stepLocks(r, a.secondStep, u.Username, u)
	result, f, err := a.secondFactor(ctx, u.ID, locks, match, func(f factor) (bool, error) {
		var err error
		failures, err = a.store.CompleteSecondStep(ctx, store.SecondStep{
			TicketHash: ticketHash, UserID: u.ID, Step: f.step, RecoveryHash: f.recovery,
			SessionHash: hashToken(token), KeepSessions: maxSessionsPerUser,
		}, now)
		if errors.Is(err, store.ErrFactorUsed) {
			return false, nil
		}
		return err == nil, err
	})
	switch {
	case errors.Is(err, store.ErrNotFound): // a sign-in at the same moment took the ticket
		expiredTicket(w)
		return
	case err != nil:
		internalError(w, a.log, "complete second step", err)
		return
	case result == authFailed:
		// Counted even if the client has hung up, so the owner hears of it (F45).
		if err := a.store.SecondStepFailed(context.WithoutCancel(ctx), u.ID); err != nil {
			internalError(w, a.log, "count failed second step", err)
			return
		}
		writeError(w, http.StatusUnauthorized, "wrong_code", "the code is wrong")
		return
	case result != authOK:
		refuse(w, result)
		return
	}
	a.audit.RecordAccount(ctx, audit.LoginSucceeded, u.ID, clientFrom(ctx))
	a.setSessionCookies(w, u, token)
	resp := a.signedIn(u, token)
	resp.SecondStepFailures = failures
	if f.recovery != nil {
		left, err := a.store.RecoveryCodesLeft(ctx, u.ID)
		if err != nil {
			a.log.Error("count recovery codes", "err", err)
		} else {
			resp.RecoveryCodesLeft = &left
		}
	}
	writeSession(w, http.StatusOK, resp)
}

func expiredTicket(w http.ResponseWriter) {
	writeError(w, http.StatusUnauthorized, "ticket_expired", "sign in again")
}

type totpSetupResponse struct {
	Secret string `json:"secret"`
	URI    string `json:"uri"`
}

// totpSetupHandler draws a secret for the owner's authenticator app. It is
// kept apart until a code from the app confirms it.
func (a *accounts) totpSetupHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	u := sessionFrom(ctx).user
	if u.TOTPSecret != nil {
		writeError(w, http.StatusConflict, "totp_on", "two-factor sign-in is already on")
		return
	}
	secret := randomBytes(totp.SecretBytes)
	if err := a.store.SetPendingTOTP(ctx, u.ID, a.sealTOTP(u.ID, secret)); err != nil {
		internalError(w, a.log, "keep TOTP secret", err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, totpSetupResponse{
		Secret: totp.Encoding.EncodeToString(secret),
		URI:    totp.URI(a.issuer, u.Username, secret),
	})
}

type totpRequest struct {
	Auth string `json:"auth"`
	Code string `json:"code"`
}

// totpEnableHandler turns two-factor sign-in on once the password and a
// code from the app are right. Every other session ends, this browser gets
// a new one, and the recovery codes are returned this once.
func (a *accounts) totpEnableHandler(w http.ResponseWriter, r *http.Request) {
	var req totpRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	auth, ok := decodeFixed(req.Auth, authBytes)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_request", "auth must be base64url of 32 bytes")
		return
	}
	ctx := r.Context()
	if sessionFrom(ctx).user.TOTPSecret != nil {
		writeError(w, http.StatusConflict, "totp_on", "two-factor sign-in is already on")
		return
	}
	u, ok := a.reauthenticate(w, r, auth)
	if !ok {
		return
	}
	sealed, err := a.store.PendingTOTP(ctx, u.ID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusConflict, "no_setup", "start the setup first")
		return
	}
	if err != nil {
		internalError(w, a.log, "load TOTP secret", err)
		return
	}
	secret, err := a.openTOTP(u.ID, sealed)
	if err != nil {
		internalError(w, a.log, "open TOTP secret", err)
		return
	}
	// Only a code from the app confirms the pending secret; EnableTOTP
	// records its step as used.
	match := func() (factor, bool, error) {
		step, ok := totp.Match(secret, strings.ReplaceAll(req.Code, " ", ""), a.now())
		return factor{step: step}, ok, nil
	}
	locks := []lock{a.sessionLock(sessionFrom(ctx), "code")}
	result, f, _ := a.secondFactor(ctx, u.ID, locks, match, func(factor) (bool, error) { return true, nil })
	switch result {
	case authOK:
	case authFailed:
		writeError(w, http.StatusForbidden, "wrong_code", "the code is wrong")
		return
	default:
		refuse(w, result)
		return
	}
	codes, hashes := newRecoveryCodes()
	token := randomBytes(tokenBytes)
	enabled, err := a.store.EnableTOTP(ctx, u.ID, sealed, f.step, hashes, a.renewal(token))
	if err != nil {
		internalError(w, a.log, "enable TOTP", err)
		return
	}
	if !enabled {
		writeError(w, http.StatusConflict, "no_setup", "start the setup first")
		return
	}
	a.audit.RecordAccount(ctx, audit.TOTPEnabled, u.ID, clientFrom(ctx))
	u.TOTPSecret = sealed
	a.setSessionCookies(w, u, token)
	resp := a.signedIn(u, token)
	resp.RecoveryCodes = codes
	writeSession(w, http.StatusOK, resp)
}

// totpDisableHandler turns two-factor sign-in off once the password and a
// code are right.
func (a *accounts) totpDisableHandler(w http.ResponseWriter, r *http.Request) {
	var req totpRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	auth, ok := decodeFixed(req.Auth, authBytes)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_request", "auth must be base64url of 32 bytes")
		return
	}
	ctx := r.Context()
	if sessionFrom(ctx).user.TOTPSecret == nil {
		writeError(w, http.StatusConflict, "totp_off", "two-factor sign-in is off")
		return
	}
	token := randomBytes(tokenBytes)
	u, ok := a.confirm(w, r, auth, req.Code, "disable TOTP", func(u store.User, f *store.Factor) error {
		return a.store.DisableTOTP(ctx, u.ID, a.renewal(token), f)
	})
	if !ok {
		return
	}
	a.audit.RecordAccount(ctx, audit.TOTPDisabled, u.ID, clientFrom(ctx))
	u.TOTPSecret = nil
	a.setSessionCookies(w, u, token)
	writeSession(w, http.StatusOK, a.signedIn(u, token))
}
