// Package cleanup deletes files that expired, were downloaded for the last
// time or never received their content, and sweeps abandoned uploads.
package cleanup

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/sHyanorn/vault-share/server/internal/blob"
	"github.com/sHyanorn/vault-share/server/internal/store"
)

type Job struct {
	Store *store.Store
	Blobs blob.Store
	Log   *slog.Logger
	// Now defaults to time.Now; tests move it.
	Now func() time.Time
}

// Run performs one sweep. Content is deleted before the record, so a failed
// blob deletion is retried on the next run instead of leaving an orphan.
func (j *Job) Run(ctx context.Context) error {
	now := time.Now()
	if j.Now != nil {
		now = j.Now()
	}
	ids, err := j.Store.Purgeable(ctx, now)
	if err != nil {
		return err
	}
	var errs []error
	purged := 0
	for _, id := range ids {
		if err := j.Blobs.Delete(ctx, id); err != nil {
			errs = append(errs, fmt.Errorf("blob %s: %w", id, err))
			continue
		}
		if err := j.Store.DeleteFile(ctx, id); err != nil {
			errs = append(errs, fmt.Errorf("record %s: %w", id, err))
			continue
		}
		purged++
	}
	if purged > 0 {
		j.Log.Info("purged files", "count", purged)
	}
	if err := j.Store.ExpireTokens(ctx, now); err != nil {
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
