// Package cleanup deletes files that expired, were downloaded for the last
// time or never received their content, and sweeps abandoned uploads.
package cleanup

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/sHyanorn/vault-share/server/internal/audit"
	"github.com/sHyanorn/vault-share/server/internal/blob"
	"github.com/sHyanorn/vault-share/server/internal/store"
)

type Job struct {
	Store *store.Store
	Blobs blob.Store
	Audit *audit.Recorder
	Log   *slog.Logger
	// Now defaults to time.Now; tests move it.
	Now func() time.Time
}

// Run performs one sweep. For files with content the blob goes first, so a
// failed deletion is retried on the next run instead of leaving an orphan.
// A record whose content never arrived is deleted conditionally, so an upload
// completing at the same moment keeps both its record and its bytes.
func (j *Job) Run(ctx context.Context) error {
	now := time.Now()
	if j.Now != nil {
		now = j.Now()
	}
	purges, err := j.Store.Purgeable(ctx, now)
	if err != nil {
		return err
	}
	var errs []error
	purged := 0
	for _, p := range purges {
		if p.Pending {
			deleted, err := j.Store.DeleteIfPending(ctx, p.ID)
			if err != nil {
				errs = append(errs, fmt.Errorf("record %s: %w", p.ID, err))
			}
			if err == nil && deleted {
				purged++
			}
			continue
		}
		if err := j.Blobs.Delete(ctx, p.ID); err != nil {
			errs = append(errs, fmt.Errorf("blob %s: %w", p.ID, err))
			continue
		}
		if err := j.Store.DeleteFile(ctx, p.ID); err != nil {
			errs = append(errs, fmt.Errorf("record %s: %w", p.ID, err))
			continue
		}
		j.Audit.Record(ctx, audit.FilePurged, p.ID, audit.Client{})
		purged++
	}
	if purged > 0 {
		j.Log.Info("purged files", "count", purged)
	}
	if err := j.Store.ExpireTokens(ctx, now); err != nil {
		errs = append(errs, err)
	}
	if err := j.Audit.Purge(ctx); err != nil {
		errs = append(errs, err)
	}
	if err := j.Blobs.Sweep(ctx, now.Add(-store.UploadGrace)); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// Loop runs a sweep immediately and then every interval until ctx is done.
func (j *Job) Loop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := j.Run(ctx); err != nil && ctx.Err() == nil {
			j.Log.Error("cleanup failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
