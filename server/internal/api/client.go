package api

import (
	"context"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sHyanorn/vault-share/server/internal/audit"
)

type requesterKey struct{}

// requester is what the middleware learns about a request, once.
type requester struct {
	client audit.Client
	// bucket keys rate limits and lockouts: one IPv4 address or one IPv6 /64.
	bucket string
}

// proxyWarnEvery spaces out the warning about a trusted proxy that names no client.
const proxyWarnEvery = time.Minute

// withClient resolves the requester. X-Forwarded-For is honoured only when
// the connection comes from a trusted proxy, and then only its last entry
// of its last line, the one that proxy appended; anything else is
// attacker-controlled. Some proxies append a line, others extend the last.
func withClient(trusted []netip.Prefix, log *slog.Logger) func(http.Handler) http.Handler {
	// Measured on the monotonic clock, so a wall-clock step cannot silence it.
	start := time.Now()
	var lastWarn atomic.Int64
	lastWarn.Store(-int64(proxyWarnEvery))
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			addr, unnamed := clientAddr(r, trusted)
			// Only API requests are rate limited; a health probe without the header is expected.
			if unnamed && strings.HasPrefix(r.URL.Path, "/api/") {
				now := int64(time.Since(start))
				last := lastWarn.Load()
				if now-last >= int64(proxyWarnEvery) && lastWarn.CompareAndSwap(last, now) {
					log.Warn("trusted proxy sent no usable X-Forwarded-For; its clients share one rate limit")
				}
			}
			req := requester{client: audit.Client{UserAgent: r.UserAgent()}}
			if addr.IsValid() {
				req.client.IP = addr.String()
				req.bucket = bucketKey(addr)
			} else {
				req.client.IP = r.RemoteAddr
				req.bucket = r.RemoteAddr
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requesterKey{}, req)))
		})
	}
}

func clientFrom(ctx context.Context) audit.Client {
	req, _ := ctx.Value(requesterKey{}).(requester)
	return req.client
}

func bucketFrom(ctx context.Context) string {
	req, _ := ctx.Value(requesterKey{}).(requester)
	return req.bucket
}

// clientAddr returns the client's address without zone, and whether a
// trusted proxy failed to name one, in which case the proxy's own address
// stands in. The zero Addr means the connection address did not parse.
func clientAddr(r *http.Request, trusted []netip.Prefix) (addr netip.Addr, unnamed bool) {
	remote, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, false
	}
	// Prefix.Contains never matches an address with a zone, so strip it first.
	addr = remote.Addr().Unmap().WithZone("")
	if !contains(trusted, addr) {
		return addr, false
	}
	var forwarded string
	if lines := r.Header.Values("X-Forwarded-For"); len(lines) > 0 {
		forwarded = lines[len(lines)-1]
	}
	if i := strings.LastIndex(forwarded, ","); i >= 0 {
		forwarded = forwarded[i+1:]
	}
	fwd, err := netip.ParseAddr(strings.TrimSpace(forwarded))
	if err != nil {
		return addr, true
	}
	return fwd.Unmap().WithZone(""), false
}

var (
	nat64  = netip.MustParsePrefix("64:ff9b::/96")
	teredo = netip.MustParsePrefix("2001::/32")
)

// bucketKey groups the addresses one client can be expected to hold: a
// single IPv4 address, or an IPv6 /64, the smallest prefix a network hands
// to a home or a phone. Addresses that carry an IPv4 client inside them
// count as that IPv4 address, since their /64 spans many clients.
func bucketKey(addr netip.Addr) string {
	b := addr.As16()
	switch {
	case addr.Is4():
		return addr.String()
	case nat64.Contains(addr): // RFC 6052: the IPv4 address is the low 32 bits
		return netip.AddrFrom4([4]byte(b[12:])).String()
	case teredo.Contains(addr): // RFC 4380: the client's IPv4 address, inverted
		return netip.AddrFrom4([4]byte{^b[12], ^b[13], ^b[14], ^b[15]}).String()
	default:
		return netip.PrefixFrom(addr, 64).Masked().String()
	}
}

func contains(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
