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
// the connection comes from a trusted proxy, and then only its last entry,
// the one that proxy appended; anything else is attacker-controlled.
func withClient(trusted []netip.Prefix, log *slog.Logger) func(http.Handler) http.Handler {
	var lastWarn atomic.Int64
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			addr, unnamed := clientAddr(r, trusted)
			if unnamed {
				now := time.Now().UnixNano()
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
	forwarded := r.Header.Get("X-Forwarded-For")
	if i := strings.LastIndex(forwarded, ","); i >= 0 {
		forwarded = forwarded[i+1:]
	}
	fwd, err := netip.ParseAddr(strings.TrimSpace(forwarded))
	if err != nil {
		return addr, true
	}
	return fwd.Unmap().WithZone(""), false
}

// bucketKey groups the addresses one client can be expected to hold: a
// single IPv4 address, or an IPv6 /64, the smallest prefix a network hands
// to a home or a phone.
func bucketKey(addr netip.Addr) string {
	if addr.Is6() {
		return netip.PrefixFrom(addr, 64).Masked().String()
	}
	return addr.String()
}

func contains(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
