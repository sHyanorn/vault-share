// Package audit records security-relevant events. Client addresses and
// user agents are stored only as keyed hashes under a key that never leaves
// the data directory, so the log supports abuse investigation without
// being a list of who fetched what.
package audit

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"github.com/sHyanorn/vault-share/server/internal/store"
)

// Event names.
const (
	FileCreated     = "file.created"
	FileUploaded    = "file.uploaded"
	DownloadGranted = "download.granted"
	DownloadDenied  = "download.denied"
	FileDeleted     = "file.deleted"
	FilePurged      = "file.purged"
	ClientLocked    = "client.locked"
)

// Retention is how long entries are kept.
const Retention = 30 * 24 * time.Hour

// MaxEntries caps the table: about 100 MB of rows. The cleanup job trims
// it every minute, so it can overshoot by one minute of writes.
const MaxEntries = 1_000_000

// Failure events are what anyone can produce at will from many addresses,
// so they share one process-wide budget and a flood of them cannot push
// the other events out of the table.
const (
	failuresPerSecond = 1
	failureBurst      = 60
)

func isFailure(event string) bool {
	return event == DownloadDenied || event == ClientLocked
}

const keyFile = "audit.key"

// Client identifies the requester; both fields may be empty.
type Client struct {
	IP        string
	UserAgent string
}

type Recorder struct {
	store    *store.Store
	key      []byte
	log      *slog.Logger
	failures *rate.Limiter
	skipped  atomic.Int64
	max      int
	// Now defaults to time.Now; tests move it.
	Now func() time.Time
}

// New loads the hashing key from dir, creating it on first use.
func New(dir string, st *store.Store, log *slog.Logger) (*Recorder, error) {
	path := filepath.Join(dir, keyFile)
	key, err := os.ReadFile(path) // #nosec G304 -- path is inside the configured data dir
	if errors.Is(err, fs.ErrNotExist) {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		err = os.WriteFile(path, key, 0o600)
	}
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, errors.New("audit key has the wrong length")
	}
	return &Recorder{
		store:    st,
		key:      key,
		log:      log,
		failures: rate.NewLimiter(failuresPerSecond, failureBurst),
		max:      MaxEntries,
		Now:      time.Now,
	}, nil
}

// Record stores the event. A failure is logged, never surfaced to the
// request: the audit trail must not become a way to break the service.
// A nil Recorder records nothing.
func (r *Recorder) Record(ctx context.Context, event, fileID string, client Client) {
	if r == nil {
		return
	}
	now := r.Now()
	if isFailure(event) && !r.failures.AllowN(now, 1) {
		r.skipped.Add(1)
		return
	}
	ctx = context.WithoutCancel(ctx) // a client that hangs up still gets recorded
	entry := store.AuditEntry{
		Event:  event,
		FileID: fileID,
		IPHash: r.hash(client.IP),
		UAHash: r.hash(client.UserAgent),
		At:     now,
	}
	if err := r.store.RecordAudit(ctx, entry); err != nil {
		r.log.Error("audit record", "event", event, "err", err)
	}
}

// Purge drops entries older than Retention and trims the table to its cap.
// What was skipped or dropped since the last run is logged as counts.
func (r *Recorder) Purge(ctx context.Context) error {
	if r == nil {
		return nil
	}
	if n := r.skipped.Swap(0); n > 0 {
		r.log.Warn("audit failure events over budget were not recorded", "count", n)
	}
	if err := r.store.PurgeAudit(ctx, r.Now().Add(-Retention)); err != nil {
		return err
	}
	dropped, err := r.store.TrimAudit(ctx, r.max)
	if err != nil {
		return err
	}
	if dropped > 0 {
		r.log.Warn("audit log over capacity, oldest entries dropped", "count", dropped)
	}
	return nil
}

func (r *Recorder) hash(value string) []byte {
	if value == "" {
		return nil
	}
	mac := hmac.New(sha256.New, r.key)
	mac.Write([]byte(value))
	return mac.Sum(nil)[:16]
}
