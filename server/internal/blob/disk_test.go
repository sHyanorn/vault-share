package blob

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const id = "AAAAAAAAAAAAAAAAAAAAAA"

func newDisk(t *testing.T) (*Disk, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "blobs")
	d, err := NewDisk(root)
	if err != nil {
		t.Fatal(err)
	}
	return d, root
}

func TestValidID(t *testing.T) {
	for _, ok := range []string{id, "abcdefghijklmnopqrstuv", "-_-_-_-_-_-_-_-_-_-_-_"} {
		if !ValidID(ok) {
			t.Errorf("%q rejected", ok)
		}
	}
	for _, bad := range []string{"", "../../../../etc/passwd", "AAAAAAAAAAAAAAAAAAAAA", "AAAAAAAAAAAAAAAAAAAAAAA",
		"AAAAAAAAAAAAAAAAAAAA+/", "AAAAAAAAAAAAAAAAAAAAA\n", "tmp/AAAAAAAAAAAAAAAAA"} {
		if ValidID(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestInvalidIDsNeverTouchTheFilesystem(t *testing.T) {
	d, root := newDisk(t)
	ctx := context.Background()
	for _, bad := range []string{"../escape", "AAAAAAAAAAAAAAAAAAAAA"} {
		if err := d.Put(ctx, bad, 1, strings.NewReader("x")); !errors.Is(err, ErrInvalidID) {
			t.Errorf("Put(%q): %v", bad, err)
		}
		if _, err := d.Open(ctx, bad); !errors.Is(err, ErrInvalidID) {
			t.Errorf("Open(%q): %v", bad, err)
		}
		if err := d.Delete(ctx, bad); !errors.Is(err, ErrInvalidID) {
			t.Errorf("Delete(%q): %v", bad, err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "..", "escape")); err == nil {
		t.Error("a file escaped the root")
	}
}

type failingReader struct{ n int }

// Read delivers n bytes in total, then fails as a dropped connection does.
func (r *failingReader) Read(p []byte) (int, error) {
	if r.n <= 0 {
		return 0, errors.New("connection reset")
	}
	n := min(len(p), r.n)
	r.n -= n
	return n, nil
}

func TestSweepRemovesOnlyOldTempFiles(t *testing.T) {
	d, root := newDisk(t)
	old := filepath.Join(root, "tmp", "upload-old")
	fresh := filepath.Join(root, "tmp", "upload-fresh")
	for _, name := range []string{old, fresh} {
		if err := os.WriteFile(name, []byte("partial"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	stale := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(old, stale, stale); err != nil {
		t.Fatal(err)
	}
	if err := d.Sweep(context.Background(), time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(old); err == nil {
		t.Error("old temp file survived")
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Error("fresh temp file was removed")
	}
}
