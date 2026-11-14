// Package api wires the HTTP routes and middleware of vaultd.
package api

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"runtime/debug"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/sHyanorn/vault-share/server/internal/audit"
	"github.com/sHyanorn/vault-share/server/internal/blob"
	"github.com/sHyanorn/vault-share/server/internal/store"
)

// Options configures NewRouter. Every field is required unless it says
// otherwise: none has a fallback that would let vaultd run unprotected.
type Options struct {
	Logger *slog.Logger
	Store  *store.Store
	Blobs  blob.Store
	Audit  *audit.Recorder
	// TrustedProxies are the sources whose X-Forwarded-For names the client.
	// Optional.
	TrustedProxies []netip.Prefix
	// Host is the name the API answers for.
	Host string
	// MaxFileBytes caps the declared ciphertext size of an upload.
	MaxFileBytes int64
	// MaxTotalBytes caps what all records together may be charged
	// (store.Charge).
	MaxTotalBytes int64
	// Limits default to DefaultLimits. Optional.
	Limits *Limits
	Now    func() time.Time
	// WebDir is the built frontend served for every path outside /api and
	// /healthz. Empty disables static serving.
	WebDir string
	// AccountKey is the 32-byte key the server keys for accounts derive from.
	AccountKey []byte
	// SignupClosed refuses new accounts; existing ones still sign in.
	SignupClosed bool
	// MaxAccounts caps the number of accounts.
	MaxAccounts int
	// Health reports why vaultd cannot serve, or nil; /healthz answers 503
	// while it fails.
	Health func(context.Context) error
}

// missing names the first required option that is not set.
func (o Options) missing() string {
	for _, f := range []struct {
		name string
		set  bool
	}{
		{"Logger", o.Logger != nil},
		{"Store", o.Store != nil},
		{"Blobs", o.Blobs != nil},
		{"Audit", o.Audit != nil},
		{"Host", o.Host != ""},
		{"MaxFileBytes", o.MaxFileBytes > 0},
		{"MaxTotalBytes", o.MaxTotalBytes > 0},
		{"Now", o.Now != nil},
		{"AccountKey", len(o.AccountKey) > 0},
		{"MaxAccounts", o.MaxAccounts > 0},
		{"Health", o.Health != nil},
	} {
		if !f.set {
			return f.name
		}
	}
	return ""
}

// NewRouter returns the root handler of vaultd.
func NewRouter(opts Options) (http.Handler, error) {
	return newRouter(opts, defaultAuthParams)
}

// newRouter hashes auth secrets with hashing, which tests lower.
func newRouter(opts Options, hashing argonParams) (http.Handler, error) {
	if name := opts.missing(); name != "" {
		return nil, fmt.Errorf("api: option %s is not set", name)
	}
	now := opts.Now
	limits := DefaultLimits
	if opts.Limits != nil {
		limits = *opts.Limits
	}
	// One file of the maximum size must always fit a client's storage budget.
	if need := store.Charge(opts.MaxFileBytes, maxMetaBytes); int64(limits.Storage.Burst) < need {
		limits.Storage.Burst = int(need) // #nosec G115 -- bounded by the configured file size
	}
	h := &files{
		store:        opts.Store,
		blobs:        opts.Blobs,
		audit:        opts.Audit,
		challenges:   newChallenger(),
		locks:        newLockouts(lockoutFailures, now),
		storage:      newLimiterSet(limits.Storage, now),
		maxFileBytes: opts.MaxFileBytes,
		quota:        opts.MaxTotalBytes,
		now:          now,
		log:          opts.Logger,
	}

	a := &accounts{
		store:        opts.Store,
		audit:        opts.Audit,
		hasher:       newHasher(hashing),
		keys:         deriveServerKeys(opts.AccountKey),
		password:     newSignInLocks(accountFailures, now),
		secondStep:   newSignInLocks(lockoutFailures, now),
		sessionLocks: newLockouts(lockoutFailures, now),
		issuer:       opts.Host,
		signup:       !opts.SignupClosed,
		maxAccounts:  opts.MaxAccounts,
		now:          now,
		log:          opts.Logger,
	}

	r := chi.NewRouter()
	r.Use(requestLog(opts.Logger))
	r.Use(recoverer(opts.Logger))
	r.Use(securityHeaders)
	r.Use(withClient(opts.TrustedProxies, opts.Logger))

	r.Get("/healthz", healthz(opts.Health))
	r.Head("/healthz", healthz(opts.Health))
	r.Route("/api/v1", func(r chi.Router) {
		// Before the limiter, so refused requests spend no client budget.
		r.Use(onlyHost(opts.Host))
		r.Use(sameOrigin())
		r.Use(rateLimit(newLimiterSet(limits.General, now)))
		r.NotFound(notFound)
		r.MethodNotAllowed(methodNotAllowed)
		r.With(rateLimit(newLimiterSet(limits.Create, now))).Post("/files", h.create)
		r.Put("/files/{id}/content", h.upload)
		r.Get("/files/{id}/meta", h.meta)
		r.With(rateLimit(newLimiterSet(limits.Download, now))).Post("/files/{id}/download", h.download)
		r.Get("/files/{id}/content", h.content)
		r.Delete("/files/{id}", h.remove)

		signup := rateLimit(newLimiterSet(limits.Signup, now))
		login := rateLimit(newLimiterSet(limits.Login, now))
		r.With(signup).Post("/account", a.signupHandler)
		r.With(login).Post("/account/salt", a.saltHandler)
		r.With(login).Post("/account/password", a.withSession(a.passwordHandler))
		r.With(login).Delete("/account", a.withSession(a.deleteHandler))
		r.With(login).Post("/session", a.loginHandler)
		r.With(login).Post("/session/totp", a.secondStepHandler)
		r.With(login).Post("/account/totp/setup", a.withSession(a.totpSetupHandler))
		r.With(login).Post("/account/totp", a.withSession(a.totpEnableHandler))
		r.With(login).Delete("/account/totp", a.withSession(a.totpDisableHandler))
		r.Get("/account/files", a.withSession(h.keptFiles))
		r.Put("/account/files/{id}", a.withSession(h.keepFile))
		r.Get("/session", a.withSession(a.currentHandler))
		r.Delete("/session", a.logoutHandler)
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

// healthz answers 200 while check passes and 503 otherwise. The probe is
// public, so the answer never says what failed; check logs that.
func healthz(check func(context.Context) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if check(r.Context()) != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// requestLog writes one structured line per request, panics included. The
// query string is deliberately omitted because download tokens travel in
// it, and the path is cut by logPath.
func requestLog(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(ww, r)
			log.Info("request",
				"method", r.Method,
				"path", logPath(r),
				"status", ww.Status(),
				"bytes", ww.BytesWritten(),
				"duration_ms", time.Since(start).Milliseconds(),
			)
		})
	}
}

// logPath is the request's path as sent, up to its first escaped
// character. No path vaultd serves holds one, while a link whose # reached
// the browser as %23 carries its key there (F65).
func logPath(r *http.Request) string {
	path, _, _ := strings.Cut(r.URL.EscapedPath(), "%")
	return path
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
					"path", logPath(r),
					"value", fmt.Sprint(rec),
					"stack", string(debug.Stack()),
				)
				writeInternalError(w)
			}()
			next.ServeHTTP(w, r)
		})
	}
}
