package api

import "net/http"

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
			switch r.Header.Get("Sec-Fetch-Site") {
			case "cross-site", "same-site":
				refuse.ServeHTTP(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
