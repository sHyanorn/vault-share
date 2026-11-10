package blob

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
)

// testStore checks what every Store promises. Ids are fresh for every case,
// so a bucket can be reused between runs.
func testStore(t *testing.T, s Store) {
	// Above 2 MB the S3 client waits for the service to accept the request
	// before it sends the body, so both of its request paths run.
	const large = 3 << 20
	ctx := context.Background()
	read := func(t *testing.T, id string) []byte {
		t.Helper()
		rc, err := s.Open(ctx, id)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer rc.Close()
		data, err := io.ReadAll(rc)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		return data
	}
	absent := func(t *testing.T, id string) {
		t.Helper()
		if rc, err := s.Open(ctx, id); !errors.Is(err, ErrNotFound) {
			if err == nil {
				rc.Close()
			}
			t.Errorf("Open: want ErrNotFound, got %v", err)
		}
	}
	ids := func(t *testing.T) map[string]bool {
		t.Helper()
		listed := map[string]bool{}
		for id, err := range s.IDs(ctx) {
			if err != nil {
				t.Fatal(err)
			}
			listed[id] = true
		}
		return listed
	}

	t.Run("stores and returns the exact bytes", func(t *testing.T) {
		for _, size := range []int64{0, 1, 1000, large} {
			id, content := newID(), randomBytes(size)
			if err := s.Put(ctx, id, size, bytes.NewReader(content)); err != nil {
				t.Fatalf("size %d: %v", size, err)
			}
			if !bytes.Equal(read(t, id), content) {
				t.Errorf("size %d: content differs", size)
			}
		}
	})

	t.Run("never replaces content", func(t *testing.T) {
		id := newID()
		if err := s.Put(ctx, id, 5, strings.NewReader("first")); err != nil {
			t.Fatal(err)
		}
		if err := s.Put(ctx, id, 6, strings.NewReader("second")); !errors.Is(err, ErrExists) {
			t.Errorf("second Put: %v", err)
		}
		if got := read(t, id); string(got) != "first" {
			t.Errorf("content replaced: %q", got)
		}
	})

	t.Run("refuses a body of another size and keeps nothing", func(t *testing.T) {
		for _, c := range []struct{ declared, actual int64 }{{0, 1}, {10, 9}, {10, 11}, {large, large - 1}, {large, large + 1}} {
			id := newID()
			if err := s.Put(ctx, id, c.declared, bytes.NewReader(randomBytes(c.actual))); !errors.Is(err, ErrSize) {
				t.Errorf("%d bytes declared, %d sent: %v", c.declared, c.actual, err)
			}
			absent(t, id)
			if err := s.Put(ctx, id, c.declared, bytes.NewReader(randomBytes(c.declared))); err != nil {
				t.Errorf("the right size after a refusal: %v", err)
			}
		}
	})

	t.Run("keeps nothing from a body that fails", func(t *testing.T) {
		for _, size := range []int64{1000, large} {
			id := newID()
			if err := s.Put(ctx, id, size, &failingReader{n: int(size / 2)}); err == nil || errors.Is(err, ErrSize) {
				t.Errorf("size %d: %v", size, err)
			}
			absent(t, id)
		}
	})

	t.Run("keeps nothing when the request is cancelled", func(t *testing.T) {
		for _, size := range []int64{1000, large} {
			id := newID()
			cctx, cancel := context.WithCancel(ctx)
			body := &cancellingReader{r: bytes.NewReader(randomBytes(size)), after: size / 2, cancel: cancel}
			if err := s.Put(cctx, id, size, body); err == nil {
				t.Errorf("size %d: Put succeeded after cancellation", size)
			}
			cancel()
			absent(t, id)
		}
	})

	t.Run("stores one of several concurrent uploads", func(t *testing.T) {
		id := newID()
		contents := make([][]byte, 6)
		errs := make([]error, len(contents))
		var wg sync.WaitGroup
		for i := range contents {
			contents[i] = randomBytes(2000)
			wg.Go(func() { errs[i] = s.Put(ctx, id, 2000, bytes.NewReader(contents[i])) })
		}
		wg.Wait()
		winner := -1
		for i, err := range errs {
			if err == nil {
				if winner >= 0 {
					t.Fatalf("uploads %d and %d both succeeded", winner, i)
				}
				winner = i
			}
		}
		if winner < 0 {
			t.Fatalf("no upload succeeded: %v", errs)
		}
		if !bytes.Equal(read(t, id), contents[winner]) {
			t.Error("stored content is not the successful upload")
		}
	})

	t.Run("deletes, and a missing id is no error", func(t *testing.T) {
		id := newID()
		if err := s.Delete(ctx, id); err != nil {
			t.Errorf("Delete of a missing id: %v", err)
		}
		if err := s.Put(ctx, id, 3, strings.NewReader("abc")); err != nil {
			t.Fatal(err)
		}
		if err := s.Delete(ctx, id); err != nil {
			t.Fatal(err)
		}
		absent(t, id)
	})

	t.Run("an open reader outlives a delete", func(t *testing.T) {
		id, content := newID(), randomBytes(large)
		if err := s.Put(ctx, id, large, bytes.NewReader(content)); err != nil {
			t.Fatal(err)
		}
		rc, err := s.Open(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Delete(ctx, id); err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(rc)
		rc.Close()
		if err != nil || !bytes.Equal(got, content) {
			t.Errorf("read after Delete: %d of %d bytes, %v", len(got), len(content), err)
		}
		absent(t, id)
	})

	t.Run("lists the stored ids", func(t *testing.T) {
		kept, deleted := newID(), newID()
		for _, id := range []string{kept, deleted} {
			if err := s.Put(ctx, id, 3, strings.NewReader("abc")); err != nil {
				t.Fatal(err)
			}
		}
		if err := s.Delete(ctx, deleted); err != nil {
			t.Fatal(err)
		}
		listed := ids(t)
		if !listed[kept] || listed[deleted] {
			t.Errorf("listed %v: kept %v, deleted %v", len(listed), listed[kept], listed[deleted])
		}
	})

	t.Run("passes its check and leaves nothing behind", func(t *testing.T) {
		before := ids(t)
		if err := s.Check(ctx); err != nil {
			t.Fatalf("Check on a working store: %v", err)
		}
		for id := range ids(t) {
			if !before[id] {
				t.Errorf("Check left %s behind", id)
			}
		}
	})

	t.Run("refuses invalid ids", func(t *testing.T) {
		for _, bad := range []string{"../escape", "AAAAAAAAAAAAAAAAAAAAA", "tmp/AAAAAAAAAAAAAAAAA"} {
			if err := s.Put(ctx, bad, 1, strings.NewReader("x")); !errors.Is(err, ErrInvalidID) {
				t.Errorf("Put(%q): %v", bad, err)
			}
			if _, err := s.Open(ctx, bad); !errors.Is(err, ErrInvalidID) {
				t.Errorf("Open(%q): %v", bad, err)
			}
			if err := s.Delete(ctx, bad); !errors.Is(err, ErrInvalidID) {
				t.Errorf("Delete(%q): %v", bad, err)
			}
		}
	})
}

func TestDiskContract(t *testing.T) {
	d, root := newDisk(t)
	testStore(t, d)
	if entries, _ := os.ReadDir(root + "/tmp"); len(entries) != 0 {
		t.Errorf("temp files left behind: %d", len(entries))
	}
}

func newID() string {
	return base64.RawURLEncoding.EncodeToString(randomBytes(16))
}

func randomBytes(n int64) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// cancellingReader cancels its request's context after the given number of
// bytes and keeps delivering, as a client that hangs up mid-upload would.
type cancellingReader struct {
	r      io.Reader
	after  int64
	read   int64
	cancel context.CancelFunc
}

func (c *cancellingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if c.read += int64(n); c.read >= c.after {
		c.cancel()
	}
	return n, err
}

// failingReader delivers n bytes in total, then fails as a dropped connection
// does.
type failingReader struct{ n int }

func (r *failingReader) Read(p []byte) (int, error) {
	if r.n <= 0 {
		return 0, errors.New("connection reset")
	}
	n := min(len(p), r.n)
	r.n -= n
	return n, nil
}
