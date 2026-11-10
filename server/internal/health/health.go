// Package health tells whether vaultd can serve: the database answers, the
// blob store takes writes and the data directory has room left.
package health

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/sHyanorn/vault-share/server/internal/blob"
	"github.com/sHyanorn/vault-share/server/internal/store"
)

// MinFreeBytes is the free space below which the data directory's
// filesystem counts as full: the database and, on disk, uploads write there.
const MinFreeBytes = 128 << 20

const (
	// maxAge is how long a result is reused. The probe is public and not
	// rate limited, so it must not turn each request into storage requests.
	maxAge = 5 * time.Second
	// timeout bounds one check, so a stalled storage service reads as down.
	timeout = 5 * time.Second
)

type Checker struct {
	store   *store.Store
	blobs   blob.Store
	dir     string
	minFree uint64
	log     *slog.Logger
	now     func() time.Time

	mu      sync.Mutex
	checked time.Time
	err     error
}

// New returns a checker for the data directory dir, whose filesystem must
// have minFree bytes free. Results age by now.
func New(st *store.Store, blobs blob.Store, dir string, minFree uint64, log *slog.Logger, now func() time.Time) *Checker {
	return &Checker{store: st, blobs: blobs, dir: dir, minFree: minFree, log: log, now: now}
}

// Check reports the first failing check, or nil. Callers within maxAge of
// a check share its result. The reason is logged here, once per check, and
// is not meant for the client.
func (c *Checker) Check(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.checked.IsZero() && c.now().Sub(c.checked) < maxAge {
		return c.err
	}
	// Without the request's cancellation: a client that hangs up must not
	// leave a failure behind for the callers that share the result.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()
	c.err = c.check(ctx)
	c.checked = c.now()
	if c.err != nil {
		c.log.Warn("health check failed", "err", c.err)
	}
	return c.err
}

func (c *Checker) check(ctx context.Context) error {
	if _, err := c.store.Usage(ctx); err != nil {
		return fmt.Errorf("database: %w", err)
	}
	if err := c.blobs.Check(ctx); err != nil {
		return fmt.Errorf("blob store: %w", err)
	}
	free, err := freeBytes(c.dir)
	if err != nil {
		return fmt.Errorf("data directory: %w", err)
	}
	if free < c.minFree {
		return fmt.Errorf("data directory: %d bytes free, below the minimum of %d", free, c.minFree)
	}
	return nil
}
