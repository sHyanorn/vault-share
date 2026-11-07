// Package cleanup deletes files that expired, were downloaded for the last
// time or never received their content, sweeps abandoned uploads and deletes
// content left without a record.
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
		// A file whose upload is running waits for a later run.
		if !j.Store.Claim(p.ID) {
			continue
		}
		done, err := j.purge(ctx, p)
		j.Store.Release(p.ID)
		if err != nil {
			errs = append(errs, err)
		}
		if done {
			purged++
		}
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
	if err := j.deleteOrphans(ctx); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (j *Job) purge(ctx context.Context, p store.Purge) (bool, error) {
	if p.Pending {
		deleted, err := j.Store.DeleteIfPending(ctx, p.ID)
		if err != nil {
			return false, fmt.Errorf("record %s: %w", p.ID, err)
		}
		return deleted, nil
	}
	if err := j.Blobs.Delete(ctx, p.ID); err != nil {
		return false, fmt.Errorf("blob %s: %w", p.ID, err)
	}
	if err := j.Store.DeleteFile(ctx, p.ID); err != nil {
		return false, fmt.Errorf("record %s: %w", p.ID, err)
	}
	j.Audit.Record(ctx, audit.FilePurged, p.ID, audit.Client{})
	return true, nil
}

// deleteOrphans deletes content that has no record. A crash between the two
// deletions, a content deletion that failed after its record was gone, or a
// lost answer from the store leaves such content behind. Each id is listed
// before its record is looked up, and a record always exists before its
// content, so content still being uploaded is never taken.
func (j *Job) deleteOrphans(ctx context.Context) error {
	var errs []error
	deleted := 0
	for id, err := range j.Blobs.IDs(ctx) {
		if err != nil {
			errs = append(errs, fmt.Errorf("list blobs: %w", err))
			break
		}
		exists, err := j.Store.FileExists(ctx, id)
		if err != nil {
			errs = append(errs, fmt.Errorf("record %s: %w", id, err))
			break
		}
		if exists {
			continue
		}
		if err := j.Blobs.Delete(ctx, id); err != nil {
			errs = append(errs, fmt.Errorf("orphaned blob %s: %w", id, err))
			continue
		}
		deleted++
	}
	if deleted > 0 {
		j.Log.Info("deleted orphaned content", "count", deleted)
	}
	return errors.Join(errs...)
}

// Loop runs a sweep immediately and then every interval until ctx is done.
// A run gets five intervals at most, so a stalled storage service delays
// cleanup instead of stopping it.
func (j *Job) Loop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		run, cancel := context.WithTimeout(ctx, 5*interval)
		err := j.Run(run)
		cancel()
		if err != nil && ctx.Err() == nil {
			j.Log.Error("cleanup failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
