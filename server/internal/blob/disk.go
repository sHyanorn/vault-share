package blob

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// Disk stores each blob as root/<id>; uploads are written to root/tmp and
// renamed into place only once complete, so a reader never sees a partial file.
type Disk struct {
	root string
}

func NewDisk(root string) (*Disk, error) {
	if err := os.MkdirAll(filepath.Join(root, "tmp"), 0o700); err != nil {
		return nil, err
	}
	return &Disk{root: root}, nil
}

func (d *Disk) Put(ctx context.Context, id string, r io.Reader) (n int64, err error) {
	if !ValidID(id) {
		return 0, ErrInvalidID
	}
	tmp, err := os.CreateTemp(filepath.Join(d.root, "tmp"), "upload-*")
	if err != nil {
		return 0, err
	}
	defer func() {
		if err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()
	if n, err = io.Copy(tmp, r); err != nil {
		return n, err
	}
	if err = ctx.Err(); err != nil {
		return n, err
	}
	if err = tmp.Sync(); err != nil {
		return n, err
	}
	if err = tmp.Close(); err != nil {
		return n, err
	}
	if err = os.Rename(tmp.Name(), filepath.Join(d.root, id)); err != nil {
		return n, err
	}
	return n, syncDir(d.root)
}

func (d *Disk) Open(_ context.Context, id string) (io.ReadCloser, error) {
	if !ValidID(id) {
		return nil, ErrInvalidID
	}
	f, err := os.Open(filepath.Join(d.root, id))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotFound
	}
	return f, err
}

func (d *Disk) Delete(_ context.Context, id string) error {
	if !ValidID(id) {
		return ErrInvalidID
	}
	err := os.Remove(filepath.Join(d.root, id))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

func (d *Disk) Sweep(_ context.Context, before time.Time) error {
	entries, err := os.ReadDir(filepath.Join(d.root, "tmp"))
	if err != nil {
		return err
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil || !info.ModTime().Before(before) {
			continue
		}
		if err := os.Remove(filepath.Join(d.root, "tmp", entry.Name())); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("sweep %s: %w", entry.Name(), err)
		}
	}
	return nil
}

// syncDir makes the rename durable.
func syncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
