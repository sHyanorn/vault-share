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

// secondFactor checks a TOTP code or a recovery code for u, under a lockout
// of its own per account. It reports whether a recovery code was spent.
func (a *accounts) secondFactor(ctx context.Context, u store.User, code string) (authResult, bool) {
	key := strconv.FormatInt(u.ID, 10)
	if a.totpLocks.locked(key) {
		return authLocked, false
	}
	code = strings.NewReplacer(" ", "", "-", "").Replace(code)
	if len(code) == totp.Digits {
		secret, err := a.openTOTP(u.ID, u.TOTPSecret)
		if err != nil {
			a.log.Error("open TOTP secret", "err", err)
			return authError, false
		}
		if step, ok := totp.Match(secret, code, a.now()); ok {
			used, err := a.store.UseTOTPStep(ctx, u.ID, step)
			if err != nil {
				a.log.Error("use TOTP step", "err", err)
				return authError, false
			}
			if used {
				a.totpLocks.reset(key)
				return authOK, false
			}
		}
	} else if hash, ok := recoveryCodeHash(code); ok {
		used, err := a.store.UseRecoveryCode(ctx, u.ID, hash)
		if err != nil {
			a.log.Error("use recovery code", "err", err)
			return authError, false
		}
		if used {
			a.totpLocks.reset(key)
			a.audit.RecordAccount(ctx, audit.RecoveryCodeUsed, u.ID, clientFrom(ctx))
			return authOK, true
		}
	}
	client := clientFrom(ctx)
	a.audit.RecordAccount(ctx, audit.TOTPFailed, u.ID, client)
	if a.totpLocks.failed(key) {
		a.audit.RecordAccount(ctx, audit.ClientLocked, u.ID, client)
	}
	return authFailed, false
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
	if u.TOTPSecret != nil {
		if result, _ := a.secondFactor(ctx, u, code); result != authOK {
			a.refuse(w, result, http.StatusForbidden, "wrong_code", "the code is wrong")
			return store.User{}, false
		}
	}
	return u, true
}

type secondStepRequest struct {
	Ticket string `json:"ticket"`
	Code   string `json:"code"`
}

// secondStepHandler completes a sign-in whose password was right.
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
	userID, valid, err := a.store.TicketUser(ctx, ticketHash, now)
	if err != nil {
		a.internalError(w, "load ticket", err)
		return
	}
	var u store.User
	if valid {
		u, err = a.store.UserByID(ctx, userID)
	}
	switch {
	case !valid || errors.Is(err, store.ErrNotFound):
		expiredTicket(w)
		return
	case err != nil:
		a.internalError(w, "load account", err)
		return
	}
	result, recovery := a.secondFactor(ctx, u, req.Code)
	switch result {
	case authOK:
	case authFailed:
		err := a.store.TicketFailed(ctx, ticketHash, maxTicketAttempts)
		if err == nil {
			err = a.store.SecondStepFailed(ctx, u.ID)
		}
		if err != nil {
			a.internalError(w, "count failed second step", err)
			return
		}
		writeError(w, http.StatusUnauthorized, "wrong_code", "the code is wrong")
		return
	default:
		a.refuse(w, result, 0, "", "")
		return
	}
	if used, err := a.store.UseTicket(ctx, ticketHash, now); err != nil || !used {
		if err != nil {
			a.internalError(w, "use ticket", err)
		} else {
			expiredTicket(w)
		}
		return
	}
	failures, err := a.store.TakeSecondStepFailures(ctx, u.ID)
	if err != nil {
		a.internalError(w, "take failed second steps", err)
		return
	}
	a.audit.RecordAccount(ctx, audit.LoginSucceeded, u.ID, clientFrom(ctx))
	token, ok := a.issueSession(w, r, u)
	if !ok {
		return
	}
	resp := a.signedIn(u, token)
	resp.SecondStepFailures = failures
	if recovery {
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
	key := strconv.FormatInt(u.ID, 10)
	if a.totpLocks.locked(key) {
		a.refuse(w, authLocked, 0, "", "")
		return
	}
	step, ok := totp.Match(secret, strings.ReplaceAll(req.Code, " ", ""), a.now())
	if !ok {
		client := clientFrom(ctx)
		a.audit.RecordAccount(ctx, audit.TOTPFailed, u.ID, client)
		if a.totpLocks.failed(key) {
			a.audit.RecordAccount(ctx, audit.ClientLocked, u.ID, client)
		}
		writeError(w, http.StatusForbidden, "wrong_code", "the code is wrong")
		return
	}
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
