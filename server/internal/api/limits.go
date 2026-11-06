package api

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Budget is a per-client token bucket: sustained rate plus burst.
type Budget struct {
	PerMinute float64
	Burst     int
}

// Limits are the per-client budgets. Uploads and download authentication
// get their own pools on top of the general one, as SPEC section 8 asks.
type Limits struct {
	General  Budget
	Create   Budget
	Download Budget
}

// DefaultLimits suit a small public instance.
var DefaultLimits = Limits{
	General:  Budget{PerMinute: 120, Burst: 60},
	Create:   Budget{PerMinute: 10, Burst: 10},
	Download: Budget{PerMinute: 30, Burst: 15},
}

const (
	// A client that fails download authentication this often for one file
	// is refused that file for lockoutPeriod.
	lockoutFailures = 5
	lockoutWindow   = 15 * time.Minute
	lockoutPeriod   = 15 * time.Minute

	// Idle entries are dropped once the tables grow past this size.
	sweepAbove = 10_000
	idleAfter  = 30 * time.Minute
)

// limiterSet keeps one token bucket per key.
type limiterSet struct {
	mu      sync.Mutex
	entries map[string]*limiterEntry
	limit   rate.Limit
	burst   int
	now     func() time.Time
}

type limiterEntry struct {
	limiter *rate.Limiter
	seen    time.Time
}

func newLimiterSet(b Budget, now func() time.Time) *limiterSet {
	return &limiterSet{entries: map[string]*limiterEntry{}, limit: rate.Limit(b.PerMinute / 60), burst: b.Burst, now: now}
}

func (s *limiterSet) allow(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	entry, ok := s.entries[key]
	if !ok {
		if len(s.entries) >= sweepAbove {
			s.sweep(now)
		}
		entry = &limiterEntry{limiter: rate.NewLimiter(s.limit, s.burst)}
		s.entries[key] = entry
	}
	entry.seen = now
	return entry.limiter.AllowN(now, 1)
}

func (s *limiterSet) sweep(now time.Time) {
	for key, entry := range s.entries {
		if now.Sub(entry.seen) > idleAfter {
			delete(s.entries, key)
		}
	}
}

// rateLimit answers 429 once the client's bucket is empty.
func rateLimit(set *limiterSet) func(http.Handler) http.Handler {
	retryAfter := strconv.Itoa(int(max(1, time.Duration(float64(time.Second)/float64(set.limit)).Seconds())))
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !set.allow(clientFrom(r.Context()).IP) {
				w.Header().Set("Retry-After", retryAfter)
				writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// lockouts counts failed download authentications per client and file.
type lockouts struct {
	mu      sync.Mutex
	entries map[string]*lockoutEntry
	now     func() time.Time
}

type lockoutEntry struct {
	failures int
	first    time.Time
	until    time.Time
}

func newLockouts(now func() time.Time) *lockouts {
	return &lockouts{entries: map[string]*lockoutEntry{}, now: now}
}

// locked reports whether the client is currently refused the file.
func (l *lockouts) locked(client, fileID string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	entry, ok := l.entries[client+"|"+fileID]
	return ok && l.now().Before(entry.until)
}

// failed records a failure and reports whether it triggered a lockout.
func (l *lockouts) failed(client, fileID string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	key := client + "|" + fileID
	entry, ok := l.entries[key]
	if !ok || now.Sub(entry.first) > lockoutWindow {
		if len(l.entries) >= sweepAbove {
			l.sweep(now)
		}
		entry = &lockoutEntry{first: now}
		l.entries[key] = entry
	}
	entry.failures++
	if entry.failures == lockoutFailures {
		entry.until = now.Add(lockoutPeriod)
		return true
	}
	return false
}

func (l *lockouts) sweep(now time.Time) {
	for key, entry := range l.entries {
		if now.After(entry.until) && now.Sub(entry.first) > lockoutWindow {
			delete(l.entries, key)
		}
	}
}
