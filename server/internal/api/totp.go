package api

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base32"
	"errors"
	"net/http"
	"strconv"
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
	// Recovery codes: ten of 80 random bits each, shown as 16 characters.
	recoveryCodeCount = 10
	recoveryCodeBytes = 10
)

var recoveryEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

type secondStepResponse struct {
	SecondStep bool   `json:"second_step"`
	Ticket     string `json:"ticket"`
}

// sealTOTP seals a secret under the server's TOTP key. The account id is
// bound in, so a sealed secret cannot be moved to another account; a copy
// of the database alone does not hold the secrets.
func (a *accounts) sealTOTP(userID int64, secret []byte) []byte {
	gcm := a.totpCipher()
	nonce := randomBytes(gcm.NonceSize())
	return gcm.Seal(nonce, nonce, secret, totpAAD(userID))
}

func (a *accounts) openTOTP(userID int64, sealed []byte) ([]byte, error) {
	gcm := a.totpCipher()
	if len(sealed) < gcm.NonceSize()+gcm.Overhead() {
		return nil, errors.New("sealed TOTP secret too short")
	}
	return gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], totpAAD(userID))
}

func (a *accounts) totpCipher() cipher.AEAD {
	block, err := aes.NewCipher(a.keys.totp)
	if err != nil {
		panic(err) // the key is always 32 bytes
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return gcm
}

func totpAAD(userID int64) []byte {
	return []byte("vault-share/totp/" + strconv.FormatInt(userID, 10))
}

// newRecoveryCodes returns codes to show, grouped for reading, and the
// hashes to keep. A code holds 80 random bits, so SHA-256 is enough.
func newRecoveryCodes() ([]string, [][]byte) {
	codes := make([]string, recoveryCodeCount)
	hashes := make([][]byte, recoveryCodeCount)
	for i := range codes {
		raw := randomBytes(recoveryCodeBytes)
		text := recoveryEncoding.EncodeToString(raw)
		codes[i] = text[0:4] + "-" + text[4:8] + "-" + text[8:12] + "-" + text[12:16]
		hashes[i] = hashToken(raw)
	}
	return codes, hashes
}

// recoveryCodeHash reads a code as the user may type it: any case, with or
// without the dashes and spaces.
func recoveryCodeHash(code string) ([]byte, bool) {
	code = strings.ToLower(strings.NewReplacer("-", "", " ", "").Replace(code))
	raw, err := recoveryEncoding.DecodeString(code)
	if err != nil || len(raw) != recoveryCodeBytes || recoveryEncoding.EncodeToString(raw) != code {
		return nil, false
	}
	return hashToken(raw), true
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

// secondFactor checks code for u under the second-step lockout of the
// account, and spend uses the factor up, reporting false if it already was.
// An error from spend ends the attempt uncounted and is returned.
func (a *accounts) secondFactor(ctx context.Context, u store.User, code string, spend func(factor) (bool, error)) (authResult, factor, error) {
	try, why := a.totpLocks.admit(strconv.FormatInt(u.ID, 10))
	if try == nil {
		return why.result(), factor{}, nil
	}
	defer try.end()
	f, ok, err := a.matchFactor(u, code)
	if err == nil && ok {
		ok, err = spend(f)
	}
	if err != nil {
		return authError, f, err
	}
	if ok {
		try.pass(true)
		if f.recovery != nil {
			a.audit.RecordAccount(ctx, audit.RecoveryCodeUsed, u.ID, clientFrom(ctx))
		}
		return authOK, f, nil
	}
	client := clientFrom(ctx)
	a.audit.RecordAccount(ctx, audit.TOTPFailed, u.ID, client)
	if try.fail() {
		a.audit.RecordAccount(ctx, audit.ClientLocked, u.ID, client)
	}
	return authFailed, f, nil
}

// reauthenticate asks the signed-in owner for the password again, and for
// a code while two-factor sign-in is on, before a change that could lock
// them out. It answers the request itself when that fails.
func (a *accounts) reauthenticate(w http.ResponseWriter, r *http.Request, auth []byte, code string) (store.User, bool) {
	ctx := r.Context()
	u, result := a.authenticate(r, sessionFrom(ctx).user.Username, auth)
	if result != authOK {
		a.refuse(w, result, http.StatusForbidden, "wrong_password", "the password is wrong")
		return store.User{}, false
	}
	if u.TOTPSecret == nil {
		return u, true
	}
	result, _, err := a.secondFactor(ctx, u, code, func(f factor) (bool, error) {
		if f.recovery != nil {
			return a.store.UseRecoveryCode(ctx, u.ID, f.recovery)
		}
		return a.store.UseTOTPStep(ctx, u.ID, f.step)
	})
	if err != nil {
		a.log.Error("spend second factor", "err", err)
	}
	if result != authOK {
		a.refuse(w, result, http.StatusForbidden, "wrong_code", "the code is wrong")
		return store.User{}, false
	}
	return u, true
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
		a.internalError(w, "take ticket attempt", err)
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
		a.internalError(w, "load account", err)
		return
	}
	var failures int
	result, f, err := a.secondFactor(ctx, u, req.Code, func(f factor) (bool, error) {
		var err error
		failures, err = a.store.CompleteSecondStep(ctx, ticketHash, u.ID, now, f.step, f.recovery)
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
		a.internalError(w, "complete second step", err)
		return
	case result == authFailed:
		if err := a.store.SecondStepFailed(ctx, u.ID); err != nil {
			a.internalError(w, "count failed second step", err)
			return
		}
		writeError(w, http.StatusUnauthorized, "wrong_code", "the code is wrong")
		return
	case result != authOK:
		a.refuse(w, result, 0, "", "")
		return
	}
	a.audit.RecordAccount(ctx, audit.LoginSucceeded, u.ID, clientFrom(ctx))
	token, ok := a.issueSession(w, r, u)
	if !ok {
		return
	}
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
		a.internalError(w, "keep TOTP secret", err)
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
	u, ok := a.reauthenticate(w, r, auth, "")
	if !ok {
		return
	}
	sealed, err := a.store.PendingTOTP(ctx, u.ID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusConflict, "no_setup", "start the setup first")
		return
	}
	if err != nil {
		a.internalError(w, "load TOTP secret", err)
		return
	}
	secret, err := a.openTOTP(u.ID, sealed)
	if err != nil {
		a.internalError(w, "open TOTP secret", err)
		return
	}
	try, why := a.totpLocks.admit(strconv.FormatInt(u.ID, 10))
	if try == nil {
		a.refuse(w, why.result(), 0, "", "")
		return
	}
	defer try.end()
	step, ok := totp.Match(secret, strings.ReplaceAll(req.Code, " ", ""), a.now())
	if !ok {
		client := clientFrom(ctx)
		a.audit.RecordAccount(ctx, audit.TOTPFailed, u.ID, client)
		if try.fail() {
			a.audit.RecordAccount(ctx, audit.ClientLocked, u.ID, client)
		}
		writeError(w, http.StatusForbidden, "wrong_code", "the code is wrong")
		return
	}
	try.pass(true)
	codes, hashes := newRecoveryCodes()
	enabled, err := a.store.EnableTOTP(ctx, u.ID, sealed, step, hashes)
	if err != nil {
		a.internalError(w, "enable TOTP", err)
		return
	}
	if !enabled {
		writeError(w, http.StatusConflict, "no_setup", "start the setup first")
		return
	}
	a.audit.RecordAccount(ctx, audit.TOTPEnabled, u.ID, clientFrom(ctx))
	u.TOTPSecret = sealed
	resp, ok := a.renewSessions(w, r, u)
	if !ok {
		return
	}
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
	u, ok := a.reauthenticate(w, r, auth, req.Code)
	if !ok {
		return
	}
	if err := a.store.DisableTOTP(ctx, u.ID); err != nil {
		a.internalError(w, "disable TOTP", err)
		return
	}
	a.audit.RecordAccount(ctx, audit.TOTPDisabled, u.ID, clientFrom(ctx))
	u.TOTPSecret = nil
	resp, ok := a.renewSessions(w, r, u)
	if !ok {
		return
	}
	writeSession(w, http.StatusOK, resp)
}

// renewSessions ends every session of u after a change to how it signs in
// and gives this browser a new one (OWASP: renew the session ID after any
// privilege level change).
func (a *accounts) renewSessions(w http.ResponseWriter, r *http.Request, u store.User) (sessionResponse, bool) {
	if err := a.store.DeleteSessions(r.Context(), u.ID); err != nil {
		a.internalError(w, "end sessions", err)
		return sessionResponse{}, false
	}
	token, ok := a.issueSession(w, r, u)
	if !ok {
		return sessionResponse{}, false
	}
	return a.signedIn(u, token), true
}
