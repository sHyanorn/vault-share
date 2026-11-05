// Package api wires the HTTP routes and middleware of vaultd.
package api

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// Options configures NewRouter.
type Options struct {
	Logger *slog.Logger
	// WebDir is the built frontend served for every path outside /api and
	// /healthz. Empty disables static serving.
	WebDir string
}

// NewRouter returns the root handler of vaultd.
func NewRouter(opts Options) (http.Handler, error) {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Use(requestLog(opts.Logger))

	r.Get("/healthz", healthz)
	r.Route("/api/v1", func(r chi.Router) {
		r.NotFound(notFound)
	})

	if opts.WebDir != "" {
		spa, err := newSPAHandler(opts.WebDir)
		if err != nil {
			return nil, err
		}
		r.Handle("/*", spa)
	}
	return r, nil
}

func healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// requestLog writes one structured line per request. The query string is
// deliberately omitted because download tokens travel in it.
func requestLog(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(ww, r)
			log.Info("request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", ww.Status(),
				"bytes", ww.BytesWritten(),
				"duration_ms", time.Since(start).Milliseconds(),
			)
		})
	}
}
