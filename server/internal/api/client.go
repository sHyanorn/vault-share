package api

import (
	"context"
	"net/http"
	"net/netip"
	"strings"

	"github.com/sHyanorn/vault-share/server/internal/audit"
)

type clientKey struct{}

// withClient resolves the requester once per request. X-Forwarded-For is
// honoured only when the connection comes from a trusted proxy, and then
// only its last entry, the one that proxy appended; anything else is
// attacker-controlled.
func withClient(trusted []netip.Prefix) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			client := audit.Client{IP: clientIP(r, trusted), UserAgent: r.UserAgent()}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), clientKey{}, client)))
		})
	}
}

func clientFrom(ctx context.Context) audit.Client {
	client, _ := ctx.Value(clientKey{}).(audit.Client)
	return client
}

func clientIP(r *http.Request, trusted []netip.Prefix) string {
	remote, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	addr := remote.Addr().Unmap()
	if !contains(trusted, addr) {
		return addr.String()
	}
	forwarded := r.Header.Get("X-Forwarded-For")
	if i := strings.LastIndex(forwarded, ","); i >= 0 {
		forwarded = forwarded[i+1:]
	}
	if fwd, err := netip.ParseAddr(strings.TrimSpace(forwarded)); err == nil {
		return fwd.Unmap().String()
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
