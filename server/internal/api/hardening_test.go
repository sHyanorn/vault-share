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
	"github.com/sHyanorn/vault-share/server/internal/store"
)

// loopbackProxies trusts the test server's own connections as a proxy, so a
// test can name its client in X-Forwarded-For.
var loopbackProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}

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

// Proxies such as HAProxy append their own header line instead of extending
// the client's, so the first line is the client's own claim (F15).
func TestClientAddrUsesTheLastHeaderLine(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.1.2.3:4000"
	r.Header.Add("X-Forwarded-For", "192.0.2.50")                 // the client's claim
	r.Header.Add("X-Forwarded-For", "198.51.100.1, 198.51.100.7") // the proxy's line
	if addr, unnamed := clientAddr(r, trusted); addr.String() != "198.51.100.7" || unnamed {
		t.Errorf("got (%s, %v)", addr, unnamed)
	}
	r.Header.Set("X-Forwarded-For", "garbage")
	r.Header.Add("X-Forwarded-For", "198.51.100.7")
	if addr, unnamed := clientAddr(r, trusted); addr.String() != "198.51.100.7" || unnamed {
		t.Errorf("garbage first line: got (%s, %v)", addr, unnamed)
	}
}

func TestSpoofedFirstLineGetsNoFreshBucket(t *testing.T) {
	e := newEnvWith(t, func(o *Options) {
		o.Limits = nil
		o.TrustedProxies = loopbackProxies
	})
	body := mustJSON(validCreate(1000))
	created := 0
	for i := 1; i <= DefaultLimits.Create.Burst+2; i++ {
		req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/api/v1/files", bytes.NewReader(body))
		req.Header["X-Forwarded-For"] = []string{fmt.Sprintf("203.0.113.%d", i), "198.51.100.7"}
		resp, err := e.srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusCreated {
			created++
		}
	}
	if created != DefaultLimits.Create.Burst {
		t.Errorf("%d created with a rotating first line, want %d", created, DefaultLimits.Create.Burst)
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
	// Ranges whose /64 spans many IPv4 clients count the embedded client.
	if key("64:ff9b::203.0.113.9") != key("203.0.113.9") || key("64:ff9b::203.0.113.9") == key("64:ff9b::203.0.113.10") {
		t.Error("NAT64 addresses are not keyed by their IPv4 client")
	}
	// RFC 4380's example: client 192.0.2.45 behind Teredo server 65.54.227.120.
	if got := key("2001:0:4136:e378:8000:63bf:3fff:fdd2"); got != "192.0.2.45" {
		t.Errorf("Teredo key %q", got)
	}
}

func TestWarnsWhenTrustedProxyNamesNoClient(t *testing.T) {
	var logs bytes.Buffer
	e := newEnvWith(t, func(o *Options) {
		o.TrustedProxies = loopbackProxies
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
	quiet := newEnvWith(t, func(o *Options) {
		o.TrustedProxies = loopbackProxies
		o.Logger = slog.New(slog.NewJSONHandler(&logs, nil))
	})
	logs.Reset()
	quiet.request(http.MethodGet, "/healthz", nil, nil, nil)
	if strings.Contains(logs.String(), "X-Forwarded-For") {
		t.Error("a health probe, which is not rate limited, triggered the warning")
	}
	if strings.Contains(logs.String(), "127.0.0.1") || strings.Contains(logs.String(), "198.51.100.1") {
		t.Error("an address reached the log")
	}
}

func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	e := newEnv(t)
	for _, path := range []string{"/healthz", "/api/v1/nope", "/api/v1/files"} {
		resp, err := e.srv.Client().Get(e.srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.Header.Get("Content-Security-Policy") == "" || resp.Header.Get("Referrer-Policy") != "no-referrer" {
			t.Errorf("%s (%d): headers missing: %v", path, resp.StatusCode, resp.Header)
		}
	}
}

func TestRateLimits(t *testing.T) {
	e := newEnvWith(t, func(o *Options) { o.Limits = nil }) // the defaults
	valid := validCreate(1000)
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

// downloadFrom walks the challenge flow as the client at address from,
// signing with key, and returns the status of the download request.
func (e *env) downloadFrom(sh share, from string, key []byte) int {
	e.t.Helper()
	m, _ := e.meta(sh.id)
	status, _ := e.request(http.MethodPost, "/api/v1/files/"+sh.id+"/download",
		downloadRequest{Challenge: m.Challenge, Signature: sign(key, m.Challenge)},
		map[string]string{"X-Forwarded-For": from}, nil)
	return status
}

func TestLockoutAfterFailedSignatures(t *testing.T) {
	e := newEnvWith(t, func(o *Options) {
		o.TrustedProxies = loopbackProxies
	})
	sh := e.shared(100, 50, 3600)
	attacker, victim := "203.0.113.1", "203.0.113.2"
	wrongKey := randomBytes(32)

	for i := 0; i < lockoutFailures; i++ {
		if status := e.downloadFrom(sh, attacker, wrongKey); status != http.StatusNotFound {
			t.Fatalf("attempt %d: %d", i, status)
		}
	}
	if status := e.downloadFrom(sh, attacker, sh.authKey); status != http.StatusNotFound {
		t.Errorf("locked client with the right key: %d", status)
	}
	if status := e.downloadFrom(sh, victim, sh.authKey); status != http.StatusOK {
		t.Errorf("other client: %d", status)
	}
	e.advance(lockoutPeriod + time.Second)
	if status := e.downloadFrom(sh, attacker, sh.authKey); status != http.StatusOK {
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
		o.TrustedProxies = loopbackProxies
	})
	valid := validCreate(1000)
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
		o.TrustedProxies = loopbackProxies
	})
	sh := e.shared(100, 50, 3600)
	for i := 1; i <= lockoutFailures; i++ {
		e.downloadFrom(sh, fmt.Sprintf("2001:db8:1:2::%x", i), randomBytes(32))
	}
	if status := e.downloadFrom(sh, "2001:db8:1:2::ffff", sh.authKey); status != http.StatusNotFound {
		t.Errorf("fresh address in the locked /64: %d", status)
	}
	if status := e.downloadFrom(sh, "2001:db8:1:3::1", sh.authKey); status != http.StatusOK {
		t.Errorf("neighbouring /64: %d", status)
	}
	// The /64 is only the bucket: the audit log still tells the addresses apart.
	entries, err := e.store.RecentAudit(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	hashes := map[string]bool{}
	for _, entry := range entries {
		if entry.Event == audit.DownloadDenied {
			hashes[string(entry.IPHash)] = true
		}
	}
	if len(hashes) != lockoutFailures {
		t.Errorf("%d distinct addresses audited for %d denials", len(hashes), lockoutFailures)
	}
}

// fill drives n fresh keys with the clock advancing a millisecond per key,
// so the once-a-minute sweep runs; it stops at the first key past the deadline.
func fill(t *testing.T, n int, now *time.Time, insert func(key string)) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for i := 0; i < n; i++ {
		*now = now.Add(time.Millisecond)
		insert(strconv.Itoa(i))
		// Quadratic sweeping took minutes here; bounded inserts take well under a second.
		if i%1000 == 0 && time.Now().After(deadline) {
			t.Fatalf("%d fresh keys took over 10s", i)
		}
	}
}

func TestLimiterTableStaysBounded(t *testing.T) {
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	set := newLimiterSet(Budget{PerMinute: 60, Burst: 1}, func() time.Time { return now })
	fill(t, 3*maxEntries, &now, func(key string) { set.allow(key) })
	if n := len(set.table.entries); n > maxEntries {
		t.Errorf("%d entries, cap %d", n, maxEntries)
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
	l := newLockouts(lockoutFailures, func() time.Time { return now })
	fill(t, 3*maxEntries, &now, func(key string) {
		l.admit(key + "|file")
		l.failed(key + "|file")
	})
	if n := len(l.table.entries); n > maxEntries {
		t.Errorf("%d entries, cap %d", n, maxEntries)
	}
	// Below the cap nothing is evicted: a lockout holds.
	small := newLockouts(lockoutFailures, func() time.Time { return now })
	for i := 0; i < lockoutFailures; i++ {
		small.admit("attacker|file")
		small.failed("attacker|file")
	}
	for i := 0; i < 1000; i++ {
		small.admit(strconv.Itoa(i) + "|file")
		small.failed(strconv.Itoa(i) + "|file")
	}
	if small.admit("attacker|file") {
		t.Error("lockout lost below the cap")
	}
}

func TestStorageQuota(t *testing.T) {
	charge := store.Charge(1000, 64) // e.create uses 64 bytes of metadata
	e := newEnvWith(t, func(o *Options) { o.MaxTotalBytes = 3 * charge })
	var shares []share
	for i := 0; i < 3; i++ {
		shares = append(shares, e.create(1000, 1, 3600))
	}
	body := validCreate(1000)
	status, data := e.request(http.MethodPost, "/api/v1/files", body, nil, nil)
	if status != http.StatusServiceUnavailable || !strings.Contains(string(data), `"capacity"`) {
		t.Fatalf("over quota: %d %s", status, data)
	}
	// Deleting a file frees its share.
	if status := e.remove(shares[0].id, shares[0].owner); status != http.StatusNoContent {
		t.Fatalf("delete: %d", status)
	}
	if status, _ := e.request(http.MethodPost, "/api/v1/files", body, nil, nil); status != http.StatusCreated {
		t.Errorf("after delete: %d", status)
	}
	// So does the purge of uploads that never arrived.
	e.advance(2 * time.Hour)
	if err := e.job.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if used, _ := e.store.Usage(context.Background()); used != 0 {
		t.Errorf("usage %d after every record was purged", used)
	}
}

func TestStorageBudgetPerClient(t *testing.T) {
	charge := store.Charge(maxTestFileBytes, 64)
	limits := Limits{General: Budget{1e9, 1e9}, Create: Budget{1e9, 1e9}, Download: Budget{1e9, 1e9},
		Storage: Budget{PerMinute: 1, Burst: int(3 * charge)}}
	e := newEnvWith(t, func(o *Options) {
		o.Limits = &limits
		o.TrustedProxies = loopbackProxies
		o.MaxTotalBytes = 2 * charge
	})
	body := validCreate(maxTestFileBytes)
	create := func(from string) (int, createResponse) {
		var resp createResponse
		status, _ := e.request(http.MethodPost, "/api/v1/files", body, map[string]string{"X-Forwarded-For": from}, &resp)
		return status, resp
	}
	expect := func(step string, got, want int) {
		t.Helper()
		if got != want {
			t.Fatalf("%s: %d, want %d", step, got, want)
		}
	}
	alice, bob := "198.51.100.1", "198.51.100.2"
	status, _ := create(alice)
	expect("first file", status, http.StatusCreated)
	status, second := create(alice)
	expect("second file", status, http.StatusCreated)
	status, _ = create(alice)
	expect("over the quota", status, http.StatusServiceUnavailable)
	expect("delete", e.remove(second.ID, second.OwnerToken), http.StatusNoContent)
	// The refused create was refunded, so the third share of budget is still there.
	status, third := create(alice)
	expect("third file after the refund", status, http.StatusCreated)
	expect("delete", e.remove(third.ID, third.OwnerToken), http.StatusNoContent)
	// Deleting frees quota, not budget: alice has spent all three shares.
	status, _ = create(alice)
	expect("fourth file from one client", status, http.StatusTooManyRequests)
	status, _ = create(bob)
	expect("another client", status, http.StatusCreated)
}

func TestStorageRefundWithARealClock(t *testing.T) {
	set := newLimiterSet(Budget{PerMinute: 1, Burst: 100}, time.Now)
	refund, ok := set.take("k", 100)
	if !ok {
		t.Fatal("first take refused")
	}
	time.Sleep(5 * time.Millisecond)
	refund()
	if _, ok := set.take("k", 100); !ok {
		t.Error("the refund did not restore the tokens")
	}
	if _, ok := set.take("k", 101); ok {
		t.Error("a take above the burst was granted")
	}
}

// Another site must not reach the API through its visitors' browsers;
// non-browser clients are unaffected.
func TestCrossOriginRequestsAreRefused(t *testing.T) {
	e := newEnv(t)
	create := func(headers map[string]string) (int, []byte) {
		return e.request(http.MethodPost, "/api/v1/files", validCreate(100), headers, nil)
	}
	for _, headers := range []map[string]string{
		{"Sec-Fetch-Site": "cross-site", "Content-Type": "text/plain"},
		{"Sec-Fetch-Site": "same-site"},
		{"Origin": "https://attacker.example"},
	} {
		status, data := create(headers)
		if status != http.StatusForbidden || !strings.Contains(string(data), `"cross_origin"`) {
			t.Errorf("%v: %d %s", headers, status, data)
		}
	}
	if used, _ := e.store.Usage(context.Background()); used != 0 {
		t.Errorf("refused creates were charged %d bytes", used)
	}
	for _, headers := range []map[string]string{
		{"Sec-Fetch-Site": "same-origin"},
		{"Origin": e.srv.URL},
		nil,
	} {
		if status, data := create(headers); status != http.StatusCreated {
			t.Errorf("%v: %d %s", headers, status, data)
		}
	}

	// Requests are refused even with valid credentials, reads included.
	pending := e.create(100, 1, 3600)
	cross := map[string]string{"Sec-Fetch-Site": "cross-site", "Authorization": "Bearer " + pending.owner}
	if status, _ := e.request(http.MethodPut, "/api/v1/files/"+pending.id+"/content", pending.content, cross, nil); status != http.StatusForbidden {
		t.Errorf("cross-site upload: %d", status)
	}
	sh := e.shared(100, 5, 3600)
	cross["Authorization"] = "Bearer " + sh.owner
	if status, _ := e.request(http.MethodDelete, "/api/v1/files/"+sh.id, nil, cross, nil); status != http.StatusForbidden {
		t.Errorf("cross-site delete: %d", status)
	}
	if status, _ := e.request(http.MethodGet, "/api/v1/files/"+sh.id+"/meta", nil, cross, nil); status != http.StatusForbidden {
		t.Errorf("cross-site metadata read: %d", status)
	}
	m, status := e.meta(sh.id)
	if status != http.StatusOK {
		t.Fatalf("same-origin metadata read: %d", status)
	}
	signed := downloadRequest{Challenge: m.Challenge, Signature: sign(sh.authKey, m.Challenge)}
	if status, _ := e.request(http.MethodPost, "/api/v1/files/"+sh.id+"/download", signed, cross, nil); status != http.StatusForbidden {
		t.Errorf("cross-site download: %d", status)
	}
	if _, status := e.download(sh.id, m.Challenge, signed.Signature); status != http.StatusOK {
		t.Errorf("same-origin download after the refusals: %d", status)
	}
}

// Refused requests never reach the limiter, so another site cannot drain a
// visitor's budget with reads it is not allowed to see.
func TestCrossSiteRequestsSpendNoBudget(t *testing.T) {
	e := newEnvWith(t, func(o *Options) {
		o.Limits = &Limits{General: Budget{PerMinute: 1, Burst: 3}, Create: Budget{PerMinute: 1000, Burst: 1000},
			Download: Budget{PerMinute: 1000, Burst: 1000}, Storage: Budget{PerMinute: 1e12, Burst: 1 << 40}}
	})
	path := "/api/v1/files/" + encoding.EncodeToString(randomBytes(16)) + "/meta"
	cross := map[string]string{"Sec-Fetch-Site": "cross-site"}
	for i := 0; i < 10; i++ {
		if status, _ := e.request(http.MethodGet, path, nil, cross, nil); status != http.StatusForbidden {
			t.Fatalf("cross-site read %d: %d", i, status)
		}
	}
	for i := 0; i < 3; i++ {
		if status, _ := e.request(http.MethodGet, path, nil, nil, nil); status != http.StatusNotFound {
			t.Fatalf("read %d of the burst: %d", i, status)
		}
	}
	if status, _ := e.request(http.MethodGet, path, nil, nil, nil); status != http.StatusTooManyRequests {
		t.Errorf("read past the burst: %d", status)
	}
}

// A page that rebinds its name to the server's address looks same-origin to
// the browser, but it cannot pick the Host its requests carry.
func TestAPIAnswersOnlyForItsHost(t *testing.T) {
	e := newEnvWith(t, func(o *Options) { o.Host = "vault.example" })
	path := "/api/v1/files/" + encoding.EncodeToString(randomBytes(16)) + "/meta"
	for host, want := range map[string]int{
		"vault.example":      http.StatusNotFound,
		"vault.example:8443": http.StatusNotFound,
		"VAULT.example.":     http.StatusNotFound,
		"attacker.example":   http.StatusMisdirectedRequest,
		"127.0.0.1":          http.StatusMisdirectedRequest,
	} {
		if status, data := e.request(http.MethodGet, path, nil, map[string]string{"Host": host}, nil); status != want {
			t.Errorf("%s: %d %s", host, status, data)
		}
	}
	rebound := map[string]string{"Host": "attacker.example", "Origin": "http://attacker.example", "Sec-Fetch-Site": "same-origin"}
	body := validCreate(100)
	if status, data := e.request(http.MethodPost, "/api/v1/files", body, rebound, nil); status != http.StatusMisdirectedRequest ||
		!strings.Contains(string(data), `"misdirected"`) {
		t.Errorf("create from a rebound name: %d %s", status, data)
	}
	if status, _ := e.request(http.MethodGet, "/healthz", nil, map[string]string{"Host": "attacker.example"}, nil); status != http.StatusOK {
		t.Errorf("health check under another name: %d", status)
	}
}
