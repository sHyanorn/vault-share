// Package totp implements time-based one-time passwords (RFC 6238 over the
// HOTP of RFC 4226) with the parameters every authenticator app supports:
// HMAC-SHA-1, 30-second steps and six digits.
package totp

import (
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- RFC 6238's default, and what authenticator apps compute; HMAC-SHA-1 is not broken
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"time"
)

const (
	// Period is the length of a time step, RFC 6238's default.
	Period = 30 * time.Second
	// Digits is the length of a code.
	Digits = 6
	// SecretBytes is the length of a secret: RFC 4226 asks for at least 128
	// bits and recommends 160.
	SecretBytes = 20
)

// Encoding is how a secret is shown to the user and put in the URI.
var Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// Step is the time step t falls in.
func Step(t time.Time) int64 {
	return t.Unix() / int64(Period/time.Second)
}

// Code is the HOTP value of secret at counter: dynamic truncation of an
// HMAC-SHA-1, reduced to digits decimal digits (RFC 4226 section 5.3).
func Code(secret []byte, counter int64, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(counter)) // #nosec G115 -- steps are positive
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	mod := uint32(1)
	for range digits {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, value%mod)
}

// Match returns the latest step within one of now's whose code is code.
// One step either way covers the network delay and the clock drift RFC 6238
// sections 5.2 and 6 allow for; each candidate is compared in constant time.
// The caller must refuse a step already used, so no code works twice.
func Match(secret []byte, code string, now time.Time) (int64, bool) {
	if len(code) != Digits {
		return 0, false
	}
	step := Step(now)
	var matched int64
	found := false
	for s := step - 1; s <= step+1; s++ {
		if subtle.ConstantTimeCompare([]byte(Code(secret, s, Digits)), []byte(code)) == 1 {
			matched, found = s, true
		}
	}
	return matched, found
}

// URI is the otpauth URI that authenticator apps read from a QR code, in the
// Key URI Format of Google Authenticator that the other apps follow.
func URI(issuer, account string, secret []byte) string {
	q := url.Values{
		"secret":    {Encoding.EncodeToString(secret)},
		"issuer":    {issuer},
		"algorithm": {"SHA1"},
		"digits":    {fmt.Sprint(Digits)},
		"period":    {fmt.Sprint(int(Period / time.Second))},
	}
	return "otpauth://totp/" + url.PathEscape(issuer+":"+account) + "?" + q.Encode()
}
