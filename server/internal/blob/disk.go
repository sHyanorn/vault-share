package blob

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"iter"
	"os"
	"time"
)

const tmpDir = "tmp"

// Disk stores each blob as <id> inside an os.Root, so no operation can reach
// outside the directory even through a symlink. An upload is written to
// tmp/ and linked into place only once it is complete, so a reader never
// sees a partial file and an existing blob is never replaced.
type Disk struct {
	root *os.Root
}

func NewDisk(dir string) (*Disk, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	if err := root.Mkdir(tmpDir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, err
	}
	return &Disk{root: root}, nil
}

func (d *Disk) Put(ctx context.Context, id string, size int64, r io.Reader) error {
	if !ValidID(id) {
		return ErrInvalidID
	}
	tmpName := tmpDir + "/upload-" + rand.Text()
	tmp, err := d.root.OpenFile(tmpName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	// The temp name is dropped in every case; after a successful link the
	// blob lives on under its own name.
	defer d.root.Remove(tmpName) //nolint:errcheck // best effort
	defer tmp.Close()

	n, err := io.Copy(tmp, r)
	if err != nil {
		return err
	}
	if n != size {
		return ErrSize
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := d.root.Link(tmpName, id); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return ErrExists
		}
		return err
	}
	return d.syncDir()
}

func (d *Disk) Open(_ context.Context, id string) (io.ReadCloser, error) {
	if !ValidID(id) {
		return nil, ErrInvalidID
	}
	f, err := d.root.Open(id)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, ErrNotFound
	case err != nil:
		return nil, err
	}
	return f, nil
}

func (d *Disk) Delete(_ context.Context, id string) error {
	if !ValidID(id) {
		return ErrInvalidID
	}
	err := d.root.Remove(id)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

func (d *Disk) IDs(context.Context) iter.Seq2[string, error] {
	return func(yield func(string, error) bool) {
		entries, err := fs.ReadDir(d.root.FS(), ".")
		if err != nil {
			yield("", err)
			return
		}
		for _, entry := range entries {
			if id := entry.Name(); entry.Type().IsRegular() && ValidID(id) && !yield(id, nil) {
				return
			}
		}
	}
}

func (d *Disk) Sweep(_ context.Context, before time.Time) error {
	entries, err := fs.ReadDir(d.root.FS(), tmpDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil || !info.ModTime().Before(before) {
			continue
		}
		if err := d.root.Remove(tmpDir + "/" + entry.Name()); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("sweep %s: %w", entry.Name(), err)
		}
	}
	return nil
}

// syncDir makes the link durable.
func (d *Disk) syncDir() error {
	f, err := d.root.Open(".")
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
