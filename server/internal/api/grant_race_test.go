package api

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sHyanorn/vault-share/server/internal/blob"
	"github.com/sHyanorn/vault-share/server/internal/store"
)

// A download that takes the last count while an earlier token is being
// redeemed must still get its token and its bytes: the count and the token
// are one transaction, so the file is never removed between the two. Many
// files at once keep the database's write lock contended, which is what
// opens the gap between two separate statements.
func TestLastDownloadGrantedDuringAnEarlierOneDelivers(t *testing.T) {
	e := newEnv(t)
	const workers, rounds = 16, 40
	var failed atomic.Int32
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for range rounds {
				sh := e.shared(64, 2, 3600)
				first, status := e.token(sh)
				if status != http.StatusOK {
					t.Errorf("first token: %d", status)
					return
				}
				m, status := e.meta(sh.id)
				if status != http.StatusOK {
					t.Errorf("meta: %d", status)
					return
				}
				var pair sync.WaitGroup
				var firstStatus, secondStatus int
				var second downloadResponse
				pair.Go(func() { firstStatus, _, _ = e.content(sh.id, first.Token) })
				pair.Go(func() { second, secondStatus = e.download(sh.id, m.Challenge, sign(sh.authKey, m.Challenge)) })
				pair.Wait()
				if firstStatus != http.StatusOK || secondStatus != http.StatusOK {
					failed.Add(1)
					continue
				}
				if status, _, _ := e.content(sh.id, second.Token); status != http.StatusOK {
					failed.Add(1)
				}
			}
		})
	}
	wg.Wait()
	if n := failed.Load(); n > 0 {
		t.Errorf("%d of %d files lost their last download", n, workers*rounds)
	}
}

// gatedBlobs holds the first Open until release is closed.
type gatedBlobs struct {
	blob.Store
	once    sync.Once
	opened  chan struct{}
	release chan struct{}
}

func (g *gatedBlobs) Open(ctx context.Context, id string) (io.ReadCloser, error) {
	first := false
	g.once.Do(func() { first = true; close(g.opened) })
	if first {
		<-g.release
	}
	return g.Store.Open(ctx, id)
}

// When the last download is redeemed while an earlier one is still being
// redeemed, the file goes as soon as both are done, whichever redeems its
// token last (F58).
func TestOverlappingLastDownloadsBurnTheFile(t *testing.T) {
	gate := &gatedBlobs{opened: make(chan struct{}), release: make(chan struct{})}
	e := newEnvWith(t, func(o *Options) {
		gate.Store = o.Blobs
		o.Blobs = gate
	})
	sh := e.shared(100, 2, 3600)
	first, status := e.token(sh)
	if status != http.StatusOK {
		t.Fatalf("first token: %d", status)
	}
	firstDone := make(chan int, 1)
	go func() {
		status, _, _ := e.content(sh.id, first.Token) // has read the record, waits in Open
		firstDone <- status
	}()
	<-gate.opened
	last, status := e.token(sh)
	if status != http.StatusOK || last.DownloadsLeft != 0 {
		t.Fatalf("last token: %d, %d left", status, last.DownloadsLeft)
	}
	if status, _, _ := e.content(sh.id, last.Token); status != http.StatusOK {
		t.Fatalf("last download: %d", status)
	}
	close(gate.release)
	if status := <-firstDone; status != http.StatusOK {
		t.Fatalf("first download: %d", status)
	}
	if _, err := e.store.GetFile(context.Background(), sh.id); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("the record after both downloads: %v", err)
	}
	if e.blobExists(sh.id) {
		t.Error("the content after both downloads")
	}
}
