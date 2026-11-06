// Package blob stores ciphertext behind a small interface, first on local
// disk and later on S3-compatible object storage. Ids are opaque to this
// package except for the strict format check that keeps them path-safe.
package blob

import (
	"context"
	"errors"
	"io"
	"regexp"
	"time"
)

// ErrNotFound is returned by Open for an id with no content.
var ErrNotFound = errors.New("blob not found")

// ErrInvalidID is returned for an id that is not 22 base64url characters.
var ErrInvalidID = errors.New("invalid blob id")

// Store holds ciphertext by id.
type Store interface {
	// Put stores everything read from r under id and returns the byte count.
	// A failed or interrupted Put leaves nothing behind.
	Put(ctx context.Context, id string, r io.Reader) (int64, error)
	// Open returns the content stored under id.
	Open(ctx context.Context, id string) (io.ReadCloser, error)
	// Delete removes the content; a missing id is not an error.
	Delete(ctx context.Context, id string) error
	// Sweep removes partial uploads abandoned before the given time.
	Sweep(ctx context.Context, before time.Time) error
}

// File ids are 16 random bytes in unpadded base64url: 22 characters.
var idPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)

// ValidID reports whether id has the format every store accepts.
func ValidID(id string) bool {
	return idPattern.MatchString(id)
}
