package cleanup

import (
	"context"
	"iter"
	"log/slog"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sHyanorn/vault-share/server/internal/audit"
	"github.com/sHyanorn/vault-share/server/internal/blob"
	"github.com/sHyanorn/vault-share/server/internal/store"
)

// stalledBlobs never finishes a listing, as a storage service that stopped
// answering would.
type stalledBlobs struct {
	blob.Store
	runs atomic.Int32
}

func (s *stalledBlobs) IDs(ctx context.Context) iter.Seq2[string, error] {
	return func(yield func(string, error) bool) {
		s.runs.Add(1)
		<-ctx.Done()
		yield("", ctx.Err())
	}
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
