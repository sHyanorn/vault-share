package api

import (
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"net/http"
	"time"

	"github.com/sHyanorn/vault-share/server/internal/store"
)

// Cookies (D027). The __Host- prefix makes the browser refuse them unless
// they are Secure, for the whole origin and without a Domain, so neither a
// subdomain nor plain http can set or replace them.
const (
	sessionCookie = "__Host-vault_session"
	deviceCookie  = "__Host-vault_device"
	// deviceCookieAge keeps a browser known to the account for half a year.
	deviceCookieAge  = 180 * 24 * time.Hour
	deviceNonceBytes = 16
	deviceTagBytes   = 16
)

// serverKeys are the purpose keys derived from the account key file, so no
// key serves two purposes.
type serverKeys struct {
	// fakeSalt answers salt lookups for usernames that do not exist.
	fakeSalt []byte
	// device derives the key the browser seals its copy of the account key under.
	device []byte
	// deviceCookie signs the cookie that marks a browser that signed in before.
	deviceCookie []byte
	// totp seals TOTP secrets.
	totp []byte
}

func deriveServerKeys(master []byte) serverKeys {
	key := func(purpose string) []byte {
		k, err := hkdf.Key(sha256.New, master, nil, "vault-share/server/"+purpose, 32)
		if err != nil {
			panic(err) // only for lengths HKDF cannot produce
		}
		return k
	}
	return serverKeys{fakeSalt: key("fake-salt"), device: key("device-key"), deviceCookie: key("device-cookie"), totp: key("totp")}
}

func mac(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

// deviceKey is what the browser seals its copy of the account key under
// (D026). It follows from the session token, which only the cookie carries,
// so it ends with the session and a copy of the users table cannot produce it.
func (a *accounts) deviceKey(token []byte) string {
	return encoding.EncodeToString(mac(a.keys.device, token))
}

// fakeSalt is a stable salt for a username without an account, so a salt
// lookup does not tell whether the account exists.
func (a *accounts) fakeSalt(username string) []byte {
	return mac(a.keys.fakeSalt, []byte(username))[:saltBytes]
}

// The device cookie follows OWASP's "Slow Down Online Guessing Attacks with
// Device Cookies": a browser that signed in to an account before carries a
// signed mark of it, and its failures are counted on their own, so a
// guessing campaign that locks the account for unknown browsers does not
// lock its owner out.
func (a *accounts) newDeviceCookie(username string) string {
	nonce := randomBytes(deviceNonceBytes)
	return encoding.EncodeToString(append(nonce, a.deviceTag(username, nonce)...))
}

// knownDevice returns the request's device cookie if it marks username.
func (a *accounts) knownDevice(r *http.Request, username string) (string, bool) {
	c, err := r.Cookie(deviceCookie)
	if err != nil {
		return "", false
	}
	raw, ok := decodeFixed(c.Value, deviceNonceBytes+deviceTagBytes)
	if !ok {
		return "", false
	}
	nonce, tag := raw[:deviceNonceBytes], raw[deviceNonceBytes:]
	return c.Value, hmac.Equal(tag, a.deviceTag(username, nonce))
}

// A username never holds a zero byte and the nonce has a fixed length, so
// no two cookies sign the same input.
func (a *accounts) deviceTag(username string, nonce []byte) []byte {
	return mac(a.keys.deviceCookie, append([]byte(username+"\x00"), nonce...))[:deviceTagBytes]
}

func setCookie(w http.ResponseWriter, name, value string, maxAge time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   int(maxAge / time.Second),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

func clearCookie(w http.ResponseWriter, name string) {
	setCookie(w, name, "", -time.Second)
}

func sessionToken(r *http.Request) ([]byte, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil, false
	}
	return decodeFixed(c.Value, tokenBytes)
}

type sessionKey struct{}

// session is the signed-in account of a request.
type session struct {
	user  store.User
	token []byte
}

func sessionFrom(ctx context.Context) session {
	s, _ := ctx.Value(sessionKey{}).(session)
	return s
}

// withSession answers 401 unless the request carries a valid session.
func (a *accounts) withSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := sessionToken(r)
		if !ok {
			unauthenticated(w)
			return
		}
		ctx := r.Context()
		u, ok, err := a.store.SessionUser(ctx, hashToken(token), a.now())
		if err != nil {
			a.internalError(w, "load session", err)
			return
		}
		if !ok {
			clearCookie(w, sessionCookie)
			unauthenticated(w)
			return
		}
		next(w, r.WithContext(context.WithValue(ctx, sessionKey{}, session{user: u, token: token})))
	}
}

func unauthenticated(w http.ResponseWriter) {
	writeError(w, http.StatusUnauthorized, "unauthenticated", "sign in first")
}
