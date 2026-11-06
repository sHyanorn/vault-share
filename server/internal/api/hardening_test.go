package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/sHyanorn/vault-share/server/internal/audit"
)

func TestClientIP(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	cases := []struct {
		name, remote, forwarded, want string
	}{
		{"no proxy", "203.0.113.9:4000", "198.51.100.1", "203.0.113.9"},
		{"trusted proxy", "10.1.2.3:4000", "198.51.100.1", "198.51.100.1"},
		{"trusted proxy, chain", "10.1.2.3:4000", "198.51.100.1, 192.0.2.2", "192.0.2.2"},
		{"trusted proxy, garbage", "10.1.2.3:4000", "not-an-ip", "10.1.2.3"},
		{"trusted proxy, no header", "10.1.2.3:4000", "", "10.1.2.3"},
		{"ipv6", "[2001:db8::1]:4000", "198.51.100.1", "2001:db8::1"},
		{"mapped ipv4", "[::ffff:203.0.113.9]:4000", "", "203.0.113.9"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tc.remote
			if tc.forwarded != "" {
				r.Header.Set("X-Forwarded-For", tc.forwarded)
			}
			if got := clientIP(r, trusted); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
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
