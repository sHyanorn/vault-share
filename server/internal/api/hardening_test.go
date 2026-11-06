package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sHyanorn/vault-share/server/internal/audit"
)

func TestClientAddr(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("fe80::/10")}
	cases := []struct {
		name, remote, forwarded, want string
		unnamed                       bool
	}{
		{"no proxy", "203.0.113.9:4000", "198.51.100.1", "203.0.113.9", false},
		{"trusted proxy", "10.1.2.3:4000", "198.51.100.1", "198.51.100.1", false},
		{"trusted proxy, chain", "10.1.2.3:4000", "198.51.100.1, 192.0.2.2", "192.0.2.2", false},
		{"trusted proxy, garbage", "10.1.2.3:4000", "not-an-ip", "10.1.2.3", true},
		{"trusted proxy, no header", "10.1.2.3:4000", "", "10.1.2.3", true},
		{"ipv6", "[2001:db8::1]:4000", "198.51.100.1", "2001:db8::1", false},
		{"mapped ipv4", "[::ffff:203.0.113.9]:4000", "", "203.0.113.9", false},
		{"zone on the connection", "[fe80::9%eth0]:4000", "", "fe80::9", true},
		{"zone in the header", "10.1.2.3:4000", "fe80::1%eth0", "fe80::1", false},
		{"zone in the header, encoded", "10.1.2.3:4000", "fe80::1%25eth2", "fe80::1", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tc.remote
			if tc.forwarded != "" {
				r.Header.Set("X-Forwarded-For", tc.forwarded)
			}
			addr, unnamed := clientAddr(r, trusted)
			if addr.String() != tc.want || unnamed != tc.unnamed {
				t.Errorf("got (%q, %v), want (%q, %v)", addr, unnamed, tc.want, tc.unnamed)
			}
		})
	}
}

func TestBucketKey(t *testing.T) {
	key := func(s string) string { return bucketKey(netip.MustParseAddr(s)) }
	if key("203.0.113.9") == key("203.0.113.10") {
		t.Error("two IPv4 addresses share a bucket")
	}
	if key("2001:db8:1:2::1") != key("2001:db8:1:2:ffff:ffff:ffff:ffff") {
		t.Error("one IPv6 /64 spans two buckets")
	}
	if key("2001:db8:1:2::1") == key("2001:db8:1:3::1") {
		t.Error("two IPv6 /64s share a bucket")
	}
	if got := key("2001:db8:1:2:3:4:5:6"); got != "2001:db8:1:2::/64" {
		t.Errorf("key %q", got)
	}
}

func TestWarnsWhenTrustedProxyNamesNoClient(t *testing.T) {
	var logs bytes.Buffer
	e := newEnvWith(t, func(o *Options) {
		o.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}
		o.Logger = slog.New(slog.NewJSONHandler(&logs, nil))
	})
	e.request(http.MethodGet, "/api/v1/nope", nil, map[string]string{"X-Forwarded-For": "198.51.100.1"}, nil)
	if strings.Contains(logs.String(), "X-Forwarded-For") {
		t.Fatal("warned although the proxy named the client")
	}
	for i := 0; i < 3; i++ {
		e.request(http.MethodGet, "/api/v1/nope", nil, nil, nil)
	}
	if n := strings.Count(logs.String(), "trusted proxy sent no usable X-Forwarded-For"); n != 1 {
		t.Errorf("%d warnings, want exactly one per minute", n)
	}
	if strings.Contains(logs.String(), "127.0.0.1") || strings.Contains(logs.String(), "198.51.100.1") {
		t.Error("an address reached the log")
	}
}

func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	e := newEnv(t)
	for _, path := range []string{"/healthz", "/api/v1/nope", "/api/v1/files"} {
		status, _ := e.request(http.MethodGet, path, nil, nil, nil)
		resp, err := e.srv.Client().Get(e.srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.Header.Get("Content-Security-Policy") == "" || resp.Header.Get("Referrer-Policy") != "no-referrer" {
			t.Errorf("%s (%d): headers missing: %v", path, status, resp.Header)
		}
	}
}

func TestRateLimits(t *testing.T) {
	e := newEnvWith(t, func(o *Options) { o.Limits = nil }) // the defaults
	valid := createRequest{Size: 1000, Meta: encoding.EncodeToString(randomContent(64)),
		AuthKey: encoding.EncodeToString(randomContent(32)), ExpiresIn: 3600, MaxDownloads: 1}
	created := 0
	var limited *http.Response
	for i := 0; i < DefaultLimits.Create.Burst+1; i++ {
		req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/api/v1/files", bytes.NewReader(mustJSON(valid)))
		req.Header.Set("Content-Type", "application/json")
		resp, err := e.srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusCreated:
			created++
		case http.StatusTooManyRequests:
			limited = resp
		default:
			t.Fatalf("status %d", resp.StatusCode)
		}
	}
	if created != DefaultLimits.Create.Burst || limited == nil {
		t.Fatalf("%d created, limited=%v", created, limited != nil)
	}
	if limited.Header.Get("Retry-After") == "" {
		t.Error("429 without Retry-After")
	}
	// The create pool is separate from the general one: reads still work.
	if _, status := e.meta("AAAAAAAAAAAAAAAAAAAAAA"); status != http.StatusNotFound {
		t.Errorf("meta while create pool is empty: %d", status)
	}
	// Tokens come back with time.
	e.advance(time.Minute)
	if status, _ := e.request(http.MethodPost, "/api/v1/files", valid, nil, nil); status != http.StatusCreated {
		t.Errorf("after a minute: %d", status)
	}
}

func TestLockoutAfterFailedSignatures(t *testing.T) {
	e := newEnvWith(t, func(o *Options) {
		o.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}
	})
	sh := e.shared(100, 50, 3600)
	attacker := map[string]string{"X-Forwarded-For": "203.0.113.1"}
	victim := map[string]string{"X-Forwarded-For": "203.0.113.2"}
	wrongKey := randomContent(32)

	attempt := func(headers map[string]string, key []byte) int {
		m, _ := e.meta(sh.id)
		status, _ := e.request(http.MethodPost, "/api/v1/files/"+sh.id+"/download",
			downloadRequest{Challenge: m.Challenge, Signature: sign(key, m.Challenge)}, headers, nil)
		return status
	}
	for i := 0; i < lockoutFailures; i++ {
		if status := attempt(attacker, wrongKey); status != http.StatusNotFound {
			t.Fatalf("attempt %d: %d", i, status)
		}
	}
	if status := attempt(attacker, sh.authKey); status != http.StatusNotFound {
		t.Errorf("locked client with the right key: %d", status)
	}
	if status := attempt(victim, sh.authKey); status != http.StatusOK {
		t.Errorf("other client: %d", status)
	}
	e.advance(lockoutPeriod + time.Second)
	if status := attempt(attacker, sh.authKey); status != http.StatusOK {
		t.Errorf("after the lockout: %d", status)
	}

	entries, err := e.store.RecentAudit(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, entry := range entries {
		counts[entry.Event]++
	}
	if counts[audit.DownloadDenied] != lockoutFailures || counts[audit.ClientLocked] != 1 || counts[audit.DownloadGranted] != 2 {
		t.Errorf("audit counts %v", counts)
	}
}

func TestAuditTrail(t *testing.T) {
	e := newEnv(t)
	sh := e.shared(100, 1, 3600)
	dl, _ := e.token(sh)
	e.content(sh.id, dl.Token)
	other := e.shared(100, 1, 3600)
	e.remove(other.id, other.owner)

	entries, err := e.store.RecentAudit(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	var events []string
	for i := len(entries) - 1; i >= 0; i-- {
		events = append(events, entries[i].Event)
		if entries[i].FileID != "" && len(entries[i].IPHash) != 16 {
			t.Errorf("%s: client not hashed: %+v", entries[i].Event, entries[i])
		}
		if bytes.Contains(entries[i].IPHash, []byte("127")) || bytes.Contains(entries[i].UAHash, []byte("Go-http")) {
			t.Errorf("raw identifier stored: %+v", entries[i])
		}
	}
	want := []string{audit.FileCreated, audit.FileUploaded, audit.DownloadGranted, audit.FileCreated, audit.FileUploaded, audit.FileDeleted}
	if strings.Join(events, ",") != strings.Join(want, ",") {
		t.Errorf("events %v, want %v", events, want)
	}
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func TestRateLimitsCountAnIPv6PrefixOnce(t *testing.T) {
	e := newEnvWith(t, func(o *Options) {
		o.Limits = nil // the defaults
		o.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}
	})
	valid := createRequest{Size: 1000, Meta: encoding.EncodeToString(randomContent(64)),
		AuthKey: encoding.EncodeToString(randomContent(32)), ExpiresIn: 3600, MaxDownloads: 1}
	created := 0
	for i := 1; i <= DefaultLimits.Create.Burst+2; i++ {
		from := map[string]string{"X-Forwarded-For": fmt.Sprintf("2001:db8:1:2::%x", i)}
		if status, _ := e.request(http.MethodPost, "/api/v1/files", valid, from, nil); status == http.StatusCreated {
			created++
		}
	}
	if created != DefaultLimits.Create.Burst {
		t.Errorf("%d created from one /64, want %d", created, DefaultLimits.Create.Burst)
	}
	other := map[string]string{"X-Forwarded-For": "2001:db8:1:3::1"}
	if status, _ := e.request(http.MethodPost, "/api/v1/files", valid, other, nil); status != http.StatusCreated {
		t.Errorf("neighbouring /64: %d", status)
	}
}

func TestLockoutCoversTheWholeIPv6Prefix(t *testing.T) {
	e := newEnvWith(t, func(o *Options) {
		o.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}
	})
	sh := e.shared(100, 50, 3600)
	attempt := func(from string, key []byte) int {
		m, _ := e.meta(sh.id)
		status, _ := e.request(http.MethodPost, "/api/v1/files/"+sh.id+"/download",
			downloadRequest{Challenge: m.Challenge, Signature: sign(key, m.Challenge)},
			map[string]string{"X-Forwarded-For": from}, nil)
		return status
	}
	for i := 1; i <= lockoutFailures; i++ {
		attempt(fmt.Sprintf("2001:db8:1:2::%x", i), randomContent(32))
	}
	if status := attempt("2001:db8:1:2::ffff", sh.authKey); status != http.StatusNotFound {
		t.Errorf("fresh address in the locked /64: %d", status)
	}
	if status := attempt("2001:db8:1:3::1", sh.authKey); status != http.StatusOK {
		t.Errorf("neighbouring /64: %d", status)
	}
}

func TestLimiterTableStaysBounded(t *testing.T) {
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	set := newLimiterSet(Budget{PerMinute: 60, Burst: 1}, func() time.Time { return now })
	start := time.Now()
	for i := 0; i < 3*maxEntries; i++ {
		set.allow(strconv.Itoa(i))
	}
	if n := len(set.table.entries); n > maxEntries {
		t.Errorf("%d entries, cap %d", n, maxEntries)
	}
	// Quadratic sweeping took minutes here; bounded inserts take well under a second.
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Errorf("%d fresh keys took %v", 3*maxEntries, elapsed)
	}
	if !set.allow("fresh") {
		t.Error("a new client was refused")
	}
	now = now.Add(idleAfter + time.Minute)
	set.allow("after-idle")
	if n := len(set.table.entries); n != 1 {
		t.Errorf("%d entries after everyone went idle, want 1", n)
	}
}

func TestLockoutTableStaysBounded(t *testing.T) {
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	l := newLockouts(func() time.Time { return now })
	start := time.Now()
	for i := 0; i < 3*maxEntries; i++ {
		l.failed(strconv.Itoa(i), "file")
	}
	if n := len(l.table.entries); n > maxEntries {
		t.Errorf("%d entries, cap %d", n, maxEntries)
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Errorf("%d fresh keys took %v", 3*maxEntries, elapsed)
	}
	// Below the cap nothing is evicted: a lockout holds.
	small := newLockouts(func() time.Time { return now })
	for i := 0; i < lockoutFailures; i++ {
		small.failed("attacker", "file")
	}
	for i := 0; i < 1000; i++ {
		small.failed(strconv.Itoa(i), "file")
	}
	if !small.locked("attacker", "file") {
		t.Error("lockout lost below the cap")
	}
}
