package keyfile

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadCreatesOnceThenReads(t *testing.T) {
	dir := t.TempDir()
	key, err := Load(dir, "a.key")
	if err != nil || len(key) != Size {
		t.Fatalf("first load: %d bytes, %v", len(key), err)
	}
	if bytes.Equal(key, make([]byte, Size)) {
		t.Error("the new key is all zeroes")
	}
	info, err := os.Stat(filepath.Join(dir, "a.key"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("key file: %v, %v, want mode 0600", info, err)
	}
	again, err := Load(dir, "a.key")
	if err != nil || !bytes.Equal(again, key) {
		t.Errorf("second load: %v, a different key: %t", err, !bytes.Equal(again, key))
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Errorf("data dir holds %d entries, want the key alone: %v", len(entries), err)
	}
}

func TestReadNeverCreates(t *testing.T) {
	dir := t.TempDir()
	if _, err := Read(dir, "a.key"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing key: %v, want fs.ErrNotExist", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("reading a missing key left %d files", len(entries))
	}
	want, err := Load(dir, "a.key")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Read(dir, "a.key"); err != nil || !bytes.Equal(got, want) {
		t.Errorf("read: %v, the stored key: %t", err, bytes.Equal(got, want))
	}
}

func TestWrongLengthIsAnErrorNotANewKey(t *testing.T) {
	for _, size := range []int{0, Size - 1, Size + 1} {
		dir := t.TempDir()
		path := filepath.Join(dir, "a.key")
		short := make([]byte, size)
		if err := os.WriteFile(path, short, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Read(dir, "a.key"); err == nil || errors.Is(err, fs.ErrNotExist) {
			t.Errorf("read of %d bytes: %v, want a length error", size, err)
		}
		if _, err := Load(dir, "a.key"); err == nil {
			t.Errorf("load of %d bytes succeeded", size)
		}
		if got, _ := os.ReadFile(path); !bytes.Equal(got, short) {
			t.Errorf("a %d-byte key file was overwritten", size)
		}
	}
}
