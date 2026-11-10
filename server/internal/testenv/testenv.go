// Package testenv sets up what the tests of several packages start from.
package testenv

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/sHyanorn/vault-share/server/internal/blob"
	"github.com/sHyanorn/vault-share/server/internal/store"
)

// Open returns a temporary data directory with a new database, vault.db,
// and a new disk store in it.
func Open(t testing.TB) (dir string, st *store.Store, disk *blob.Disk) {
	t.Helper()
	dir = t.TempDir()
	st, err := store.Open(context.Background(), filepath.Join(dir, "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	disk, err = blob.NewDisk(filepath.Join(dir, "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	return dir, st, disk
}
