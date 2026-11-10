// Package keyfile keeps the random keys vaultd holds in its data directory.
package keyfile

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Size is the length of every key, in bytes.
const Size = 32

// Read returns the key named name in dir, or an error matching
// fs.ErrNotExist when there is none.
func Read(dir, name string) ([]byte, error) {
	key, err := os.ReadFile(filepath.Join(dir, name)) // #nosec G304 -- path is inside the configured data dir
	if err != nil {
		return nil, err
	}
	if len(key) != Size {
		return nil, fmt.Errorf("%s has the wrong length", name)
	}
	return key, nil
}

// Load reads the key named name in dir, creating it owner-only on first use.
func Load(dir, name string) ([]byte, error) {
	key, err := Read(dir, name)
	if !errors.Is(err, fs.ErrNotExist) {
		return key, err
	}
	key = make([]byte, Size)
	_, _ = rand.Read(key) // crypto/rand never fails on supported platforms
	if err := create(dir, name, key); err != nil {
		return nil, err
	}
	return key, nil
}

// create writes the key so that a crash leaves either no file or the whole
// key: a file cut short would stop every later start.
func create(dir, name string, key []byte) error {
	tmp, err := os.CreateTemp(dir, name+".*") // owner-only
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(key); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), filepath.Join(dir, name)); err != nil {
		return err
	}
	d, err := os.Open(dir) // #nosec G304 -- the configured data dir
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
