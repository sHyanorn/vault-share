package api

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

// Server-side hashing of auth secrets (D027). The secret is already the
// output of Argon2id in the browser; hashing it again with Argon2id means a
// copy of the users table holds no value a client could sign in with.

type argonParams struct {
	memory  uint32 // KiB
	time    uint32
	threads uint8
}

// defaultAuthParams is the OWASP Password Storage Cheat Sheet minimum for
// Argon2id. Tests lower authParams; a stored hash names its own parameters.
var (
	defaultAuthParams = argonParams{memory: 19 << 10, time: 2, threads: 1}
	authParams        = defaultAuthParams
)

const (
	authSaltBytes = 16
	authHashBytes = 32
	// hashSlots bounds the hashes that run at once, each holding
	// authParams.memory, so a burst of sign-ins queues instead of
	// exhausting memory; hashWait bounds the queue.
	hashSlots = 4
	hashWait  = 10 * time.Second
)

var (
	errBusy    = errors.New("too many sign-ins at once")
	errBadHash = errors.New("malformed password hash")
)

type hasher struct {
	slots chan struct{}
	// dummy is verified for unknown usernames, so they take as long as known ones.
	dummy string
}

func newHasher() *hasher {
	return &hasher{
		slots: make(chan struct{}, hashSlots),
		dummy: encodeHash(authParams, randomBytes(authSaltBytes), randomBytes(authHashBytes)),
	}
}

func (h *hasher) acquire(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, hashWait)
	defer cancel()
	select {
	case h.slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return errBusy
	}
}

func (h *hasher) release() { <-h.slots }

func (h *hasher) hash(ctx context.Context, secret []byte) (string, error) {
	if err := h.acquire(ctx); err != nil {
		return "", err
	}
	defer h.release()
	p, salt := authParams, randomBytes(authSaltBytes)
	return encodeHash(p, salt, argon2.IDKey(secret, salt, p.time, p.memory, p.threads, authHashBytes)), nil
}

// verify reports whether secret matches encoded, comparing in constant time.
// An empty encoded stands for an unknown user: the dummy hash is checked
// instead and the answer is false.
func (h *hasher) verify(ctx context.Context, encoded string, secret []byte) (bool, error) {
	known := encoded != ""
	if !known {
		encoded = h.dummy
	}
	p, salt, want, err := decodeHash(encoded)
	if err != nil {
		return false, err
	}
	if err := h.acquire(ctx); err != nil {
		return false, err
	}
	defer h.release()
	got := argon2.IDKey(secret, salt, p.time, p.memory, p.threads, uint32(len(want))) // #nosec G115 -- decodeHash bounds the length
	return subtle.ConstantTimeCompare(got, want) == 1 && known, nil
}

var phc = base64.RawStdEncoding

// encodeHash writes the PHC string format, which names the parameters so
// they can be raised later without breaking the hashes already stored.
func encodeHash(p argonParams, salt, key []byte) string {
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.memory, p.time, p.threads, phc.EncodeToString(salt), phc.EncodeToString(key))
}

// decodeHash accepts only what encodeHash writes, within bounds this server
// would use, so a damaged row cannot make a sign-in allocate without limit.
func decodeHash(s string) (argonParams, []byte, []byte, error) {
	parts := strings.Split(s, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return argonParams{}, nil, nil, errBadHash
	}
	var p argonParams
	var version int
	if _, err := fmt.Sscanf(parts[2]+" "+parts[3], "v=%d m=%d,t=%d,p=%d", &version, &p.memory, &p.time, &p.threads); err != nil {
		return argonParams{}, nil, nil, errBadHash
	}
	salt, errSalt := phc.DecodeString(parts[4])
	key, errKey := phc.DecodeString(parts[5])
	switch {
	case errSalt != nil || errKey != nil, version != argon2.Version,
		p.memory < 8 || p.memory > 256<<10, p.time < 1 || p.time > 16, p.threads < 1 || p.threads > 4,
		len(salt) < 8 || len(salt) > 64, len(key) < 16 || len(key) > 64,
		encodeHash(p, salt, key) != s:
		return argonParams{}, nil, nil, errBadHash
	}
	return p, salt, key, nil
}
