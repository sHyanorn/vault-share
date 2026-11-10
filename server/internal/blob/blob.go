// Package blob stores ciphertext behind a small interface, on local disk or
// in an S3-compatible bucket. Ids are opaque to this package except for the
// strict format check that keeps them path-safe.
package blob

import (
	"context"
	"errors"
	"io"
	"iter"
	"regexp"
	"time"
)

var (
	// ErrNotFound is returned by Open for an id with no content.
	ErrNotFound = errors.New("blob not found")
	// ErrInvalidID is returned for an id that is not 22 base64url characters.
	ErrInvalidID = errors.New("invalid blob id")
	// ErrExists is returned by Put when content for the id is already stored.
	ErrExists = errors.New("blob already exists")
	// ErrSize is returned by Put when r did not deliver exactly size bytes.
	ErrSize = errors.New("blob size mismatch")
)

// Store holds ciphertext by id.
type Store interface {
	// Put stores exactly size bytes read from r under id. Content is never
	// replaced, and a failed or interrupted Put leaves nothing behind.
	Put(ctx context.Context, id string, size int64, r io.Reader) error
	// Open returns the content stored under id.
	Open(ctx context.Context, id string) (io.ReadCloser, error)
	// Delete removes the content; a missing id is not an error. A reader
	// opened before Delete still reads the whole content.
	Delete(ctx context.Context, id string) error
	// IDs lists the ids of the stored content.
	IDs(ctx context.Context) iter.Seq2[string, error]
	// Sweep removes partial uploads abandoned before the given time.
	Sweep(ctx context.Context, before time.Time) error
	// Check reports whether the store is there to take content: the disk store
	// writes a file, the S3 store asks for the bucket.
	Check(ctx context.Context) error
}

// File ids are 16 random bytes in unpadded base64url: 22 characters.
var idPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)

// ValidID reports whether id has the format every store accepts.
func ValidID(id string) bool {
	return idPattern.MatchString(id)
}
