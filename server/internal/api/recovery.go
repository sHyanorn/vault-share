package api

import (
	"encoding/base32"
	"strings"
)

// Recovery codes: ten of 80 random bits each, shown as 16 characters.
const (
	recoveryCodeCount = 10
	recoveryCodeBytes = 10
)

var recoveryEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

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
