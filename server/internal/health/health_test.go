package health

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sHyanorn/vault-share/server/internal/blob"
	"github.com/sHyanorn/vault-share/server/internal/store"
)

// countingBlobs counts the checks that reach the store.
type countingBlobs struct {
	blob.Store
	checks atomic.Int32
}

func (c *countingBlobs) Check(ctx context.Context) error {
	c.checks.Add(1)
	return c.Store.Check(ctx)
}

func newChecker(t *testing.T) (*Checker, *countingBlobs, string) {
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
	blobs := &countingBlobs{Store: disk}
	return New(st, blobs, dir, 1, slog.New(slog.DiscardHandler), time.Now), blobs, dir
}

func TestEachFailureIsReported(t *testing.T) {
	cases := []struct {
		name    string
		breakIt func(c *Checker, dir string)
		want    string
	}{
		{"database closed", func(c *Checker, _ string) { c.store.Close() }, "database"},
		{"blob directory removed", func(_ *Checker, dir string) { os.RemoveAll(filepath.Join(dir, "blobs")) }, "blob store"},
		{"too little space", func(c *Checker, _ string) { c.minFree = 1 << 62 }, "bytes free"},
		{"data directory removed", func(c *Checker, _ string) { c.dir = filepath.Join(c.dir, "missing") }, "data directory"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _, dir := newChecker(t)
			tc.breakIt(c, dir)
			err := c.Check(context.Background())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("got %v, want a failure naming %q", err, tc.want)
			}
		})
	}
}

// The probe is public: requests in quick succession share one check, and
// a failure shows once the result has aged.
func TestResultIsSharedForAWhile(t *testing.T) {
	c, blobs, _ := newChecker(t)
	ctx := context.Background()
	for range 20 {
		if err := c.Check(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if n := blobs.checks.Load(); n != 1 {
		t.Errorf("20 probes made %d checks, want 1", n)
	}
	c.minFree = 1 << 62
	if err := c.Check(ctx); err != nil {
		t.Errorf("a fresh result was not reused: %v", err)
	}
	c.now = func() time.Time { return time.Now().Add(maxAge) }
	if err := c.Check(ctx); err == nil {
		t.Error("an aged result hid a failure")
	}
}

func TestAHungUpClientLeavesNoFailureBehind(t *testing.T) {
	c, _, _ := newChecker(t)
	gone, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.Check(gone); err != nil {
		t.Errorf("a cancelled request made the instance unhealthy: %v", err)
	}
}
