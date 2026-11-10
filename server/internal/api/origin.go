package api

import (
	"net"
	"net/http"
	"strings"
)

// sameOrigin refuses API requests a browser sends on behalf of another site.
// Such a page can send a write that looks like a form post without a CORS
// preflight; it cannot read the answer, but the write happens. Reads are
// refused too, because each one would still spend the visitor's budget.
func sameOrigin() func(http.Handler) http.Handler {
	refuse := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusForbidden, "cross_origin", "cross-origin request refused")
	})
	// Writes from browsers that send no Fetch Metadata are judged by Origin.
	writes := http.NewCrossOriginProtection()
	writes.SetDenyHandler(refuse)
	return func(next http.Handler) http.Handler {
		next = writes.Handler(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// The answer depends on these headers, so a cache must keep the
			// answers apart (OWASP CSRF Prevention Cheat Sheet).
			w.Header().Add("Vary", "Sec-Fetch-Site, Origin")
			switch r.Header.Get("Sec-Fetch-Site") {
			case "cross-site", "same-site":
				refuse.ServeHTTP(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// onlyHost answers only requests addressed to host, compared without port
// or case. A page that rebinds its own name to this server's address is
// same-origin to the browser, but its requests still carry that name.
func onlyHost(host string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.EqualFold(hostname(r.Host), host) {
				writeError(w, http.StatusMisdirectedRequest, "misdirected", "unknown host")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func hostname(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.TrimSuffix(strings.Trim(host, "[]"), ".")
}
