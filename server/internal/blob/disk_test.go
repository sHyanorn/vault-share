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
	// The contract checks what every operation returns for an invalid id;
	// this checks that a refused write left nothing outside the root.
	if err := d.Put(context.Background(), "../escape", 1, strings.NewReader("x")); !errors.Is(err, ErrInvalidID) {
		t.Errorf("Put: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "..", "escape")); err == nil {
		t.Error("a file escaped the root")
	}
}

func TestIDsListOnlyBlobs(t *testing.T) {
	d, root := newDisk(t)
	if err := d.Put(context.Background(), id, 1, strings.NewReader("x")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"notes.txt", "tmp/upload-partial"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var listed []string
	for got, err := range d.IDs(context.Background()) {
		if err != nil {
			t.Fatal(err)
		}
		listed = append(listed, got)
	}
	if len(listed) != 1 || listed[0] != id {
		t.Errorf("listed %q", listed)
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
