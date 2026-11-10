package api

import (
	"sync"
	"time"
)

// A key that fails lockoutFailures times (fewer or more where a caller says
// so) within lockoutWindow is refused for lockoutPeriod.
const (
	lockoutFailures = 5
	lockoutWindow   = 15 * time.Minute
	lockoutPeriod   = 15 * time.Minute
)

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
