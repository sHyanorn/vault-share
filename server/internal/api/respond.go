package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

// errorBody is the envelope every API error uses: {"error":{"code":..,"message":..}}.
type errorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	var body errorBody
	body.Error.Code = code
	body.Error.Message = message
	writeJSON(w, status, body)
}

// internalError logs err, the one place it is logged, and answers without
// detail.
func internalError(w http.ResponseWriter, log *slog.Logger, what string, err error) {
	log.Error(what, "err", err)
	writeInternalError(w)
}

// writeInternalError answers for a failure that is already logged.
func writeInternalError(w http.ResponseWriter) {
	writeError(w, http.StatusInternalServerError, "internal", "internal error")
}

func notFound(w http.ResponseWriter, _ *http.Request) {
	writeError(w, http.StatusNotFound, "not_found", "not found")
}

var knownMethods = []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodDelete}

func methodNotAllowed(w http.ResponseWriter, r *http.Request) {
	// chi hands the root router to a mounted subrouter's handler, so match
	// the full request path.
	rctx := chi.RouteContext(r.Context())
	path := r.URL.RawPath
	if path == "" {
		path = r.URL.Path
	}
	var allowed []string
	for _, method := range knownMethods {
		if rctx.Routes.Match(chi.NewRouteContext(), method, path) {
			allowed = append(allowed, method)
		}
	}
	w.Header().Set("Allow", strings.Join(allowed, ", "))
	writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
}
