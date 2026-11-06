package blob

import (
	"bytes"
	"context"
	"errors"
	"io"
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

func TestPutOpenDelete(t *testing.T) {
	d, root := newDisk(t)
	ctx := context.Background()
	content := bytes.Repeat([]byte("cipher"), 1000)

	if err := d.Put(ctx, id, int64(len(content)), bytes.NewReader(content)); err != nil {
		t.Fatal(err)
	}
	rc, err := d.Open(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(rc)
	rc.Close()
	if !bytes.Equal(got, content) {
		t.Error("content differs")
	}
	if entries, _ := os.ReadDir(filepath.Join(root, "tmp")); len(entries) != 0 {
		t.Errorf("temp files left behind: %d", len(entries))
	}

	if err := d.Delete(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Open(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Errorf("Open after Delete: %v", err)
	}
	if err := d.Delete(ctx, id); err != nil {
		t.Errorf("second Delete: %v", err)
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

func (r *failingReader) Read(p []byte) (int, error) {
	if r.n <= 0 {
		return 0, errors.New("connection reset")
	}
	r.n -= len(p)
	return len(p), nil
}

func TestFailedPutLeavesNothing(t *testing.T) {
	d, root := newDisk(t)
	if err := d.Put(context.Background(), id, 200_000, &failingReader{n: 100_000}); err == nil {
		t.Fatal("want error")
	}
	if _, err := os.Stat(filepath.Join(root, id)); err == nil {
		t.Error("partial blob was published")
	}
	if entries, _ := os.ReadDir(filepath.Join(root, "tmp")); len(entries) != 0 {
		t.Errorf("temp files left behind: %d", len(entries))
	}
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

func TestPutNeverReplacesAndChecksSize(t *testing.T) {
	d, root := newDisk(t)
	ctx := context.Background()
	if err := d.Put(ctx, id, 5, strings.NewReader("first")); err != nil {
		t.Fatal(err)
	}
	if err := d.Put(ctx, id, 6, strings.NewReader("second")); !errors.Is(err, ErrExists) {
		t.Errorf("second Put: %v", err)
	}
	rc, _ := d.Open(ctx, id)
	got, _ := io.ReadAll(rc)
	rc.Close()
	if string(got) != "first" {
		t.Errorf("content replaced: %q", got)
	}

	other := "BBBBBBBBBBBBBBBBBBBBBB"
	for _, size := range []int64{4, 6} {
		if err := d.Put(ctx, other, size, strings.NewReader("short")); !errors.Is(err, ErrSize) {
			t.Errorf("size %d: %v", size, err)
		}
		if _, err := os.Stat(filepath.Join(root, other)); err == nil {
			t.Errorf("size %d: blob published", size)
		}
	}
	if entries, _ := os.ReadDir(filepath.Join(root, "tmp")); len(entries) != 0 {
		t.Errorf("temp files left behind: %d", len(entries))
	}
}
