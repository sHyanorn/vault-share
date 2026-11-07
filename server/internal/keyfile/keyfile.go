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

// Load reads the key named name in dir, creating it owner-only on first use.
func Load(dir, name string) ([]byte, error) {
	path := filepath.Join(dir, name)
	key, err := os.ReadFile(path) // #nosec G304 -- path is inside the configured data dir
	if errors.Is(err, fs.ErrNotExist) {
		key = make([]byte, Size)
		_, _ = rand.Read(key) // crypto/rand never fails on supported platforms
		err = os.WriteFile(path, key, 0o600)
	}
	if err != nil {
		return nil, err
	}
	if len(key) != Size {
		return nil, fmt.Errorf("%s has the wrong length", name)
	}
	return key, nil
}
