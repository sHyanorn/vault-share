package cleanup

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sHyanorn/vault-share/server/internal/audit"
	"github.com/sHyanorn/vault-share/server/internal/blob"
	"github.com/sHyanorn/vault-share/server/internal/store"
)

// stalledBlobs never finishes a sweep, as a storage service that stopped
// answering would.
type stalledBlobs struct {
	blob.Store
	runs atomic.Int32
}

func (s *stalledBlobs) Sweep(ctx context.Context, _ time.Time) error {
	s.runs.Add(1)
	<-ctx.Done()
	return ctx.Err()
}

func TestLoopOutlivesAStalledStore(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(context.Background(), filepath.Join(dir, "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	disk, err := blob.NewDisk(filepath.Join(dir, "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.DiscardHandler)
	auditor, err := audit.New(dir, st, logger)
	if err != nil {
		t.Fatal(err)
	}
	blobs := &stalledBlobs{Store: disk}
	job := &Job{Store: st, Blobs: blobs, Audit: auditor, Log: logger}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	job.Loop(ctx, 20*time.Millisecond)
	if n := blobs.runs.Load(); n < 3 {
		t.Errorf("%d runs in a second: a stalled store stopped cleanup", n)
	}
}

func TestRunEndsUnusableSessions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.db")
	st, err := store.Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	disk, err := blob.NewDisk(filepath.Join(dir, "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.DiscardHandler)
	auditor, err := audit.New(dir, st, logger)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	t0 := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	id, err := st.CreateUser(ctx, store.User{Username: "alice", Salt: []byte("s"), AuthHash: "h", SealedKey: []byte("k"), CreatedAt: t0}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateSession(ctx, []byte("token"), id, t0, 10); err != nil {
		t.Fatal(err)
	}
	job := &Job{Store: st, Blobs: disk, Audit: auditor, Log: logger, Now: func() time.Time { return t0.Add(store.SessionIdle) }}
	if err := job.Run(ctx); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&n); err != nil || n != 0 {
		t.Errorf("%d idle sessions left after cleanup: %v", n, err)
	}
}

// orphanJob is a job over a new database and disk store whose clock the
// returned function moves.
func orphanJob(t *testing.T, logger *slog.Logger) (*Job, *blob.Disk, func(time.Duration)) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(context.Background(), filepath.Join(dir, "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	disk, err := blob.NewDisk(filepath.Join(dir, "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	auditor, err := audit.New(dir, st, logger)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	job := &Job{Store: st, Blobs: disk, Audit: auditor, Log: logger, Now: func() time.Time { return now }}
	return job, disk, func(d time.Duration) { now = now.Add(d) }
}

// putOrphans stores n blobs that have no record.
func putOrphans(t *testing.T, disk *blob.Disk, n int) {
	t.Helper()
	for i := range n {
		id := fmt.Sprintf("orphan%016d", i)
		if err := disk.Put(context.Background(), id, 1, strings.NewReader("x")); err != nil {
			t.Fatal(err)
		}
	}
}

func stored(t *testing.T, disk *blob.Disk) int {
	t.Helper()
	n := 0
	for _, err := range disk.IDs(context.Background()) {
		if err != nil {
			t.Fatal(err)
		}
		n++
	}
	return n
}

// A vaultd started on the wrong database sees all stored content as
// orphaned; nothing is deleted before the operator had an interval to notice.
func TestFirstRunsDeleteNoOrphans(t *testing.T) {
	job, disk, advance := orphanJob(t, slog.New(slog.DiscardHandler))
	putOrphans(t, disk, 3)
	ctx := context.Background()
	for _, wait := range []time.Duration{0, time.Minute, orphanInterval - 2*time.Minute} {
		advance(wait)
		if err := job.Run(ctx); err != nil {
			t.Fatal(err)
		}
		if n := stored(t, disk); n != 3 {
			t.Fatalf("%d of 3 blobs left within the first interval", n)
		}
	}
	advance(time.Minute)
	if err := job.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if n := stored(t, disk); n != 0 {
		t.Errorf("%d orphans left after the first interval", n)
	}
}

func TestOrphanSweepDeletesAtMostItsLimit(t *testing.T) {
	var logs bytes.Buffer
	job, disk, advance := orphanJob(t, slog.New(slog.NewJSONHandler(&logs, nil)))
	const extra = 7
	putOrphans(t, disk, maxOrphanDeletes+extra)
	ctx := context.Background()
	if err := job.Run(ctx); err != nil {
		t.Fatal(err)
	}
	advance(orphanInterval)
	if err := job.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if n := stored(t, disk); n != extra {
		t.Errorf("%d blobs left after one sweep, want %d", n, extra)
	}
	want := fmt.Sprintf(`"found":%d,"deleted":%d,"limit":%d`, maxOrphanDeletes+extra, maxOrphanDeletes, maxOrphanDeletes)
	if !strings.Contains(logs.String(), `"level":"WARN"`) || !strings.Contains(logs.String(), want) {
		t.Errorf("no warning with %s in the log: %s", want, logs.String())
	}
	// The rest goes with the next sweep, not with the next run.
	if err := job.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if n := stored(t, disk); n != extra {
		t.Errorf("%d blobs left before the next sweep was due, want %d", n, extra)
	}
	advance(orphanInterval)
	if err := job.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if n := stored(t, disk); n != 0 {
		t.Errorf("%d blobs left after the second sweep", n)
	}
}
