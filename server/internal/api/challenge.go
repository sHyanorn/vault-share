package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"math"
	"time"
)

// A challenge is 32 bytes: expiry (8, Unix seconds) | nonce (8) | tag (16),
// where the tag is HMAC-SHA256 over the file id, expiry and nonce under a
// key the server draws at startup, truncated to 16 bytes. The server keeps
// no state: the tag proves the challenge was issued for this file and is
// still valid, and the client's signature over all 32 bytes proves it holds
// the auth key. Replaying a signed challenge within its lifetime only spends
// the holder's own download count.
type challenger struct {
	key []byte
}

const (
	challengeBytes = 32
	challengeTag   = 16
)

func newChallenger() *challenger {
	return &challenger{key: randomBytes(32)}
}

func (c *challenger) issue(fileID string, expiresAt time.Time) []byte {
	challenge := make([]byte, challengeBytes)
	binary.BigEndian.PutUint64(challenge[:8], uint64(max(expiresAt.Unix(), 0)))
	copy(challenge[8:16], randomBytes(8))
	copy(challenge[16:], c.tag(fileID, challenge[:16]))
	return challenge
}

func (c *challenger) valid(fileID string, challenge []byte, now time.Time) bool {
	if len(challenge) != challengeBytes {
		return false
	}
	raw := binary.BigEndian.Uint64(challenge[:8])
	if raw > math.MaxInt64 {
		return false
	}
	expiresAt := time.Unix(int64(raw), 0)
	return now.Before(expiresAt) && hmac.Equal(challenge[16:], c.tag(fileID, challenge[:16]))
}

func (c *challenger) tag(fileID string, prefix []byte) []byte {
	mac := hmac.New(sha256.New, c.key)
	mac.Write([]byte(fileID))
	mac.Write(prefix)
	return mac.Sum(nil)[:challengeTag]
}
