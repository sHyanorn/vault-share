// Package api wires the HTTP routes and middleware of vaultd.
package api

import (
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"net/netip"
	"runtime/debug"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/sHyanorn/vault-share/server/internal/audit"
	"github.com/sHyanorn/vault-share/server/internal/blob"
	"github.com/sHyanorn/vault-share/server/internal/store"
)

// Options configures NewRouter.
type Options struct {
	Logger *slog.Logger
	Store  *store.Store
	Blobs  blob.Store
	Audit  *audit.Recorder
	// TrustedProxies are the sources whose X-Forwarded-For names the client.
	TrustedProxies []netip.Prefix
	// MaxFileBytes caps the declared ciphertext size of an upload.
	MaxFileBytes int64
	// MaxTotalBytes caps what all records together may be charged
	// (store.Charge); zero disables the quota.
	MaxTotalBytes int64
	// Limits default to DefaultLimits.
	Limits *Limits
	// Now defaults to time.Now; tests move it.
	Now func() time.Time
	// WebDir is the built frontend served for every path outside /api and
	// /healthz. Empty disables static serving.
	WebDir string
}

// NewRouter returns the root handler of vaultd.
func NewRouter(opts Options) (http.Handler, error) {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	limits := DefaultLimits
	if opts.Limits != nil {
		limits = *opts.Limits
	}
	// One file of the maximum size must always fit a client's storage budget.
	if need := store.Charge(opts.MaxFileBytes, maxMetaBytes); int64(limits.Storage.Burst) < need {
		limits.Storage.Burst = int(need) // #nosec G115 -- bounded by the configured file size
	}
	quota := opts.MaxTotalBytes
	if quota <= 0 {
		quota = math.MaxInt64 / 2
	}
	h := &files{
		store:        opts.Store,
		blobs:        opts.Blobs,
		audit:        opts.Audit,
		challenges:   newChallenger(),
		locks:        newLockouts(now),
		storage:      newLimiterSet(limits.Storage, now),
		maxFileBytes: opts.MaxFileBytes,
		quota:        quota,
		now:          now,
		log:          opts.Logger,
	}

	r := chi.NewRouter()
	r.Use(requestLog(opts.Logger))
	r.Use(recoverer(opts.Logger))
	r.Use(securityHeaders)
	r.Use(withClient(opts.TrustedProxies, opts.Logger))

	r.Get("/healthz", healthz)
	r.Head("/healthz", healthz)
	r.Route("/api/v1", func(r chi.Router) {
		r.Use(rateLimit(newLimiterSet(limits.General, now)))
		r.NotFound(notFound)
		r.MethodNotAllowed(methodNotAllowed)
		r.With(rateLimit(newLimiterSet(limits.Create, now))).Post("/files", h.create)
		r.Put("/files/{id}/content", h.upload)
		r.Get("/files/{id}/meta", h.meta)
		r.With(rateLimit(newLimiterSet(limits.Download, now))).Post("/files/{id}/download", h.download)
		r.Get("/files/{id}/content", h.content)
		r.Delete("/files/{id}", h.remove)
	})

	if opts.WebDir != "" {
		spa, err := newSPAHandler(opts.WebDir)
		if err != nil {
			return nil, err
		}
		// Every path that is not a server route belongs to the web client.
		r.NotFound(spa.ServeHTTP)
	}
	return r, nil
}

func healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// requestLog writes one structured line per request, panics included. The
// query string is deliberately omitted because download tokens travel in it.
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

// recoverer turns a panic into a 500 and records it through the structured
// logger rather than on raw stderr, so log redaction covers it.
func recoverer(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				rec := recover()
				if rec == nil {
					return
				}
				if rec == http.ErrAbortHandler {
					panic(rec)
				}
				log.Error("panic",
					"method", r.Method,
					"path", r.URL.Path,
					"value", fmt.Sprint(rec),
					"stack", string(debug.Stack()),
				)
				writeError(w, http.StatusInternalServerError, "internal", "internal error")
			}()
			next.ServeHTTP(w, r)
		})
	}
}
