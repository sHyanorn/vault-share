package store

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func sample(id string) File {
	return File{
		ID:             id,
		SizeBytes:      1234,
		MetaCiphertext: []byte("meta"),
		AuthKey:        []byte("auth-key-32-bytes-long-exactly!!"),
		OwnerTokenHash: []byte("owner-hash"),
		DownloadsLeft:  3,
		ExpiresAt:      t0.Add(24 * time.Hour),
		CreatedAt:      t0,
	}
}

func mustCreate(t *testing.T, s *Store, f File, uploaded bool) {
	t.Helper()
	ctx := context.Background()
	if err := s.CreateFile(ctx, f); err != nil {
		t.Fatal(err)
	}
	if uploaded {
		if ok, err := s.MarkUploaded(ctx, f.ID, f.CreatedAt); err != nil || !ok {
			t.Fatalf("MarkUploaded: ok=%v err=%v", ok, err)
		}
	}
}

func TestMigrationsAreIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	for i := 0; i < 2; i++ {
		s, err := Open(context.Background(), path)
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		s.Close()
	}
}

func TestFileRoundTrip(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	f := sample("file-a")
	mustCreate(t, s, f, false)

	got, err := s.GetFile(ctx, f.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Uploaded || got.Live(t0) {
		t.Errorf("new file must not be uploaded or live: %+v", got)
	}
	f.Uploaded = false
	got.Uploaded = false
	if string(got.MetaCiphertext) != "meta" || got.SizeBytes != 1234 || got.DownloadsLeft != 3 ||
		!got.ExpiresAt.Equal(f.ExpiresAt) || !got.CreatedAt.Equal(f.CreatedAt) {
		t.Errorf("got %+v, want %+v", got, f)
	}

	if ok, err := s.MarkUploaded(ctx, f.ID, t0); err != nil || !ok {
		t.Fatalf("first MarkUploaded: ok=%v err=%v", ok, err)
	}
	if ok, err := s.MarkUploaded(ctx, f.ID, t0); err != nil || ok {
		t.Fatalf("second MarkUploaded must report false: ok=%v err=%v", ok, err)
	}
	got, _ = s.GetFile(ctx, f.ID)
	if !got.Uploaded || !got.Live(t0) || got.Live(t0.Add(25*time.Hour)) {
		t.Errorf("liveness wrong: %+v", got)
	}

	if _, err := s.GetFile(ctx, "missing"); err != ErrNotFound {
		t.Errorf("missing file: %v", err)
	}
	if err := s.DeleteFile(ctx, f.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetFile(ctx, f.ID); err != ErrNotFound {
		t.Errorf("after delete: %v", err)
	}
}

func TestChallengesAreOneTime(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	mustCreate(t, s, sample("file-a"), true)
	mustCreate(t, s, sample("file-b"), true)
	nonce := []byte("nonce-1")
	if err := s.CreateChallenge(ctx, "file-a", nonce, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.ConsumeChallenge(ctx, "file-b", nonce, t0); ok {
		t.Error("challenge accepted for another file")
	}
	if ok, _ := s.ConsumeChallenge(ctx, "file-a", nonce, t0.Add(2*time.Minute)); ok {
		t.Error("expired challenge accepted")
	}
	if ok, _ := s.ConsumeChallenge(ctx, "file-a", nonce, t0); !ok {
		t.Error("valid challenge rejected")
	}
	if ok, _ := s.ConsumeChallenge(ctx, "file-a", nonce, t0); ok {
		t.Error("challenge accepted twice")
	}
}

func TestChallengesPerFileAreCapped(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	mustCreate(t, s, sample("file-a"), true)
	for i := 0; i < 40; i++ {
		nonce := []byte{byte(i)}
		if err := s.CreateChallenge(ctx, "file-a", nonce, t0.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM challenges`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != challengesPerFile {
		t.Errorf("%d challenges kept, want %d", n, challengesPerFile)
	}
	if ok, _ := s.ConsumeChallenge(ctx, "file-a", []byte{39}, t0); !ok {
		t.Error("newest challenge was dropped")
	}
	if ok, _ := s.ConsumeChallenge(ctx, "file-a", []byte{0}, t0); ok {
		t.Error("oldest challenge survived the cap")
	}
}

func TestConsumeDownloadIsAtomic(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	mustCreate(t, s, sample("file-a"), true)

	const workers = 64
	var wg sync.WaitGroup
	var mu sync.Mutex
	granted := 0
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, ok, err := s.ConsumeDownload(ctx, "file-a", t0)
			if err != nil {
				t.Error(err)
				return
			}
			if ok {
				mu.Lock()
				granted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if granted != 3 {
		t.Errorf("%d downloads granted, want 3", granted)
	}
	f, _ := s.GetFile(ctx, "file-a")
	if f.DownloadsLeft != 0 {
		t.Errorf("downloads_left = %d", f.DownloadsLeft)
	}
}

func TestConsumeDownloadRequiresLiveFile(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	mustCreate(t, s, sample("pending"), false)
	mustCreate(t, s, sample("live"), true)
	if _, ok, _ := s.ConsumeDownload(ctx, "pending", t0); ok {
		t.Error("download granted before upload")
	}
	if _, ok, _ := s.ConsumeDownload(ctx, "live", t0.Add(48*time.Hour)); ok {
		t.Error("download granted after expiry")
	}
	if left, ok, _ := s.ConsumeDownload(ctx, "live", t0); !ok || left != 2 {
		t.Errorf("live download: ok=%v left=%d", ok, left)
	}
}

func TestDownloadTokensAreOneTime(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	mustCreate(t, s, sample("file-a"), true)
	hash := []byte("token-hash")
	if err := s.CreateDownloadToken(ctx, "file-a", hash, t0.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.ConsumeDownloadToken(ctx, "other", hash, t0); ok {
		t.Error("token accepted for another file")
	}
	if ok, _ := s.ConsumeDownloadToken(ctx, "file-a", hash, t0.Add(6*time.Minute)); ok {
		t.Error("expired token accepted")
	}
	if ok, _ := s.ConsumeDownloadToken(ctx, "file-a", hash, t0); !ok {
		t.Error("valid token rejected")
	}
	if ok, _ := s.ConsumeDownloadToken(ctx, "file-a", hash, t0); ok {
		t.Error("token accepted twice")
	}
}

func TestPurgeable(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	mustCreate(t, s, sample("live"), true)
	mustCreate(t, s, sample("expired"), true)
	burned := sample("burned")
	mustCreate(t, s, burned, true)
	pendingToken := sample("pending-token")
	mustCreate(t, s, pendingToken, true)
	stale := sample("stale-upload")
	stale.CreatedAt = t0.Add(-2 * time.Hour)
	mustCreate(t, s, stale, false)
	fresh := sample("fresh-upload")
	fresh.CreatedAt = t0.Add(-30 * time.Minute)
	mustCreate(t, s, fresh, false)

	for _, id := range []string{"burned", "pending-token"} {
		for i := 0; i < 3; i++ {
			if _, ok, _ := s.ConsumeDownload(ctx, id, t0); !ok {
				t.Fatalf("%s: download %d not granted", id, i)
			}
		}
	}
	if err := s.CreateDownloadToken(ctx, "pending-token", []byte("h"), t0.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateDownloadToken(ctx, "burned", []byte("h2"), t0.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE files SET expires_at = ? WHERE id = 'expired'`, t0.Add(-time.Second).Unix()); err != nil {
		t.Fatal(err)
	}

	purgeable := func(now time.Time) map[string]bool {
		ids, err := s.Purgeable(ctx, now)
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]bool{}
		for _, id := range ids {
			got[id] = true
		}
		return got
	}
	// At t0 the fresh upload is inside its grace period and the pending
	// token keeps its file alive; two hours later both are purgeable.
	cases := []struct {
		now  time.Time
		want []string
	}{
		{t0, []string{"expired", "burned", "stale-upload"}},
		{t0.Add(2 * time.Hour), []string{"expired", "burned", "stale-upload", "fresh-upload", "pending-token"}},
	}
	for _, tc := range cases {
		got := purgeable(tc.now)
		if len(got) != len(tc.want) {
			t.Errorf("at %v purgeable = %v, want %v", tc.now, got, tc.want)
		}
		for _, id := range tc.want {
			if !got[id] {
				t.Errorf("at %v %s missing from %v", tc.now, id, got)
			}
		}
	}

	if err := s.ExpireTokens(ctx, t0); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM download_tokens`).Scan(&n); err != nil || n != 1 {
		t.Errorf("download tokens after ExpireTokens = %d, err %v", n, err)
	}
}
