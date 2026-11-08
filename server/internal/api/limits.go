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

// Limits are the per-client budgets. Uploads, download authentication,
// sign-up and sign-in get their own pools on top of the general one, as
// SPEC section 8 asks. Storage counts bytes charged against the quota
// rather than requests.
type Limits struct {
	General  Budget
	Create   Budget
	Download Budget
	Storage  Budget
	Signup   Budget
	Login    Budget
}

// DefaultLimits suit a small public instance. The storage budget lets one
// client reserve 4 GiB a day, so filling the default 20 GiB quota takes
// several clients rather than one. A client may open five accounts an hour;
// the sign-in budget covers the salt lookup, the sign-in and the account
// changes that ask for the password again.
var DefaultLimits = Limits{
	General:  Budget{PerMinute: 120, Burst: 60},
	Create:   Budget{PerMinute: 10, Burst: 10},
	Download: Budget{PerMinute: 30, Burst: 15},
	Storage:  Budget{PerMinute: float64(4<<30) / (24 * 60), Burst: 4 << 30},
	Signup:   Budget{PerMinute: 5.0 / 60, Burst: 5},
	Login:    Budget{PerMinute: 10, Burst: 20},
}

const (
	// A key that fails lockoutFailures times (fewer or more where a caller
	// says so) within lockoutWindow is refused for lockoutPeriod.
	lockoutFailures = 5
	lockoutWindow   = 15 * time.Minute
	lockoutPeriod   = 15 * time.Minute

	// Past sweepAbove entries a table drops idle ones, at most once per
	// sweepEvery; at maxEntries an arbitrary entry makes room. Memory and
	// the cost of an insert therefore stay bounded whatever the key space.
	sweepAbove = 10_000
	maxEntries = 50_000
	sweepEvery = time.Minute
	idleAfter  = 30 * time.Minute
)

// table is a map that never holds more than maxEntries entries besides those
// keep names. Callers hold the lock.
type table[V any] struct {
	entries map[string]V
	stale   func(V, time.Time) bool
	// keep, when set, names entries that must not be evicted to make room.
	keep      func(V) bool
	lastSweep time.Time
}

func newTable[V any](stale func(V, time.Time) bool) table[V] {
	return table[V]{entries: map[string]V{}, stale: stale}
}

// makeRoom runs before an insert. Evicting an arbitrary entry can hand a
// client a fresh bucket or end its lockout early; reaching that takes tens
// of thousands of distinct keys, each of which is rate limited itself.
func (t *table[V]) makeRoom(now time.Time) {
	if len(t.entries) < sweepAbove {
		return
	}
	if now.Sub(t.lastSweep) >= sweepEvery {
		t.lastSweep = now
		// Rebuilding rather than deleting in place also releases the storage
		// that eviction churn leaves behind: Go maps never shrink.
		kept := make(map[string]V, len(t.entries))
		for key, v := range t.entries {
			if !t.stale(v, now) {
				kept[key] = v
			}
		}
		t.entries = kept
	}
	for key, v := range t.entries { // map order is randomised
		if len(t.entries) < maxEntries {
			break
		}
		if t.keep != nil && t.keep(v) {
			continue
		}
		delete(t.entries, key)
	}
}

// limiterSet keeps one token bucket per key.
type limiterSet struct {
	mu    sync.Mutex
	table table[*limiterEntry]
	limit rate.Limit
	burst int
	now   func() time.Time
}

type limiterEntry struct {
	limiter *rate.Limiter
	seen    time.Time
}

func newLimiterSet(b Budget, now func() time.Time) *limiterSet {
	stale := func(e *limiterEntry, now time.Time) bool { return now.Sub(e.seen) > idleAfter }
	return &limiterSet{table: newTable(stale), limit: rate.Limit(b.PerMinute / 60), burst: b.Burst, now: now}
}

// lookup returns key's bucket, creating it. The caller holds s.mu.
func (s *limiterSet) lookup(key string, now time.Time) *rate.Limiter {
	entry, ok := s.table.entries[key]
	if !ok {
		s.table.makeRoom(now)
		entry = &limiterEntry{limiter: rate.NewLimiter(s.limit, s.burst)}
		s.table.entries[key] = entry
	}
	entry.seen = now
	return entry.limiter
}

func (s *limiterSet) allow(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	return s.lookup(key, now).AllowN(now, 1)
}

// take spends n tokens from key's bucket if they are there now, and returns
// a function that gives them back.
func (s *limiterSet) take(key string, n int64) (refund func(), ok bool) {
	if n > int64(s.burst) {
		return nil, false
	}
	s.mu.Lock()
	now := s.now()
	lim := s.lookup(key, now)
	s.mu.Unlock()
	r := lim.ReserveN(now, int(n)) // #nosec G115 -- n is at most s.burst, an int
	if !r.OK() {
		return nil, false
	}
	if r.DelayFrom(now) > 0 {
		r.CancelAt(now)
		return nil, false
	}
	// CancelAt only reverses a reservation when given a time at or before
	// the reservation's own, so the refund reuses now.
	return func() { r.CancelAt(now) }, true
}

// rateLimit answers 429 once the client's bucket is empty.
func rateLimit(set *limiterSet) func(http.Handler) http.Handler {
	retryAfter := strconv.Itoa(int(max(1, time.Duration(float64(time.Second)/float64(set.limit)).Seconds())))
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !set.allow(bucketFrom(r.Context())) {
				w.Header().Set("Retry-After", retryAfter)
				writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// lockouts counts failures per key, such as a client and a file. An
// attempt is admitted before it is checked and ends once, as a failure or
// not, so attempts that arrive together cannot outnumber the failures
// allowed (F39).
type lockouts struct {
	mu       sync.Mutex
	table    table[*lockoutEntry]
	failures int
	now      func() time.Time
}

type lockoutEntry struct {
	failures int
	// inflight counts admitted attempts that have not ended yet.
	inflight int
	first    time.Time
	until    time.Time
}

func newLockouts(failures int, now func() time.Time) *lockouts {
	l := &lockouts{failures: failures, now: now}
	l.table = newTable(func(e *lockoutEntry, now time.Time) bool {
		return e.inflight == 0 && now.After(e.until) && now.Sub(e.first) > lockoutWindow
	})
	// Evicting an entry with attempts in flight would lose their count (F44).
	l.table.keep = func(e *lockoutEntry) bool { return e.inflight > 0 }
	return l
}

// refusal says why an attempt was not admitted.
type refusal int

const (
	// refusedLocked: a lockout is in force.
	refusedLocked refusal = iota + 1
	// refusedBusy: the attempts in flight could reach the limit, should they
	// all fail; one of them ends shortly (F42).
	refusedBusy
)

// attempt is an admitted try at a key. It ends once: with fail or pass, or
// with end, which callers defer so that an attempt left without either still
// ends, uncounted. An entry with an attempt in flight is never swept or
// evicted, so the entry stays the one in the table.
type attempt struct {
	l     *lockouts
	key   string
	entry *lockoutEntry
	ended bool
}

// entry returns key's entry, its window restarted if due. The caller holds
// l.mu.
func (l *lockouts) entry(key string, now time.Time) *lockoutEntry {
	entry, ok := l.table.entries[key]
	if !ok {
		l.table.makeRoom(now)
		entry = &lockoutEntry{first: now}
		l.table.entries[key] = entry
	} else {
		entry.restartWindow(now)
	}
	return entry
}

// restartWindow starts a new window once the last one is over and no
// refusal is in force. The caller holds the lock of the entry's lockouts.
func (e *lockoutEntry) restartWindow(now time.Time) {
	if now.Sub(e.first) > lockoutWindow && !now.Before(e.until) {
		e.failures, e.first = 0, now
	}
}

// admit reserves an attempt for key, or says why it may not be tried now.
func (l *lockouts) admit(key string) (*attempt, refusal) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	entry := l.entry(key, now)
	switch {
	case now.Before(entry.until):
		return nil, refusedLocked
	case entry.failures+entry.inflight >= l.failures:
		return nil, refusedBusy
	}
	entry.inflight++
	return &attempt{l: l, key: key, entry: entry}, 0
}

// fail ends the attempt as a failure and reports whether it locked the key.
func (a *attempt) fail() bool {
	l := a.l
	l.mu.Lock()
	defer l.mu.Unlock()
	if a.ended {
		return false
	}
	a.ended = true
	now := l.now()
	e := a.entry
	e.inflight--
	e.restartWindow(now)
	e.failures++
	if e.failures == l.failures {
		e.until = now.Add(lockoutPeriod)
		return true
	}
	return false
}

// pass ends the attempt without a failure. forget also drops the failures
// counted so far; a refusal in force stays.
func (a *attempt) pass(forget bool) {
	l := a.l
	l.mu.Lock()
	defer l.mu.Unlock()
	if a.ended {
		return
	}
	a.ended = true
	now := l.now()
	e := a.entry
	e.inflight--
	if forget && !now.Before(e.until) {
		e.failures = 0
	}
	// An entry that holds nothing leaves, so attempts that pass leave the
	// table as they found it (F44).
	if e.failures == 0 && e.inflight == 0 && !now.Before(e.until) && l.table.entries[a.key] == e {
		delete(l.table.entries, a.key)
	}
}

// end ends the attempt uncounted, unless it has ended already.
func (a *attempt) end() {
	a.pass(false)
}
