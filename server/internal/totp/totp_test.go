package totp

import (
	"net/url"
	"testing"
	"time"
)

var rfcSecret = []byte("12345678901234567890")

// RFC 4226 appendix D.
func TestHOTPVectors(t *testing.T) {
	want := []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"}
	for counter, code := range want {
		if got := Code(rfcSecret, int64(counter), 6); got != code {
			t.Errorf("counter %d: %s, want %s", counter, got, code)
		}
	}
}

// RFC 6238 appendix B, the SHA-1 rows, with eight digits as there.
func TestTOTPVectors(t *testing.T) {
	for unix, code := range map[int64]string{
		59:          "94287082",
		1111111109:  "07081804",
		1111111111:  "14050471",
		1234567890:  "89005924",
		2000000000:  "69279037",
		20000000000: "65353130",
	} {
		if got := Code(rfcSecret, Step(time.Unix(unix, 0)), 8); got != code {
			t.Errorf("T=%d: %s, want %s", unix, got, code)
		}
	}
}

func TestMatchAllowsOneStepEitherWay(t *testing.T) {
	now := time.Unix(1_800_000_015, 0)
	step := Step(now)
	for offset, want := range map[int64]bool{-2: false, -1: true, 0: true, 1: true, 2: false} {
		got, ok := Match(rfcSecret, Code(rfcSecret, step+offset, Digits), now)
		if ok != want || (ok && got != step+offset) {
			t.Errorf("offset %d: step %d %v", offset, got, ok)
		}
	}
	for _, bad := range []string{"", "12345", "1234567", "abcdef"} {
		if _, ok := Match(rfcSecret, bad, now); ok {
			t.Errorf("%q matched", bad)
		}
	}
}

func TestURI(t *testing.T) {
	uri := URI("share.example.com", "alice", rfcSecret)
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "otpauth" || u.Host != "totp" || u.Path != "/share.example.com:alice" {
		t.Fatalf("%q: %v", uri, err)
	}
	q := u.Query()
	if q.Get("secret") != "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" || q.Get("issuer") != "share.example.com" ||
		q.Get("algorithm") != "SHA1" || q.Get("digits") != "6" || q.Get("period") != "30" {
		t.Errorf("query %v", q)
	}
}
