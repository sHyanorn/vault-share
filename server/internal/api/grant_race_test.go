package api

import (
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
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
