package store

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"testing/fstest"
	"time"
)

var t0 = time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)

const noQuota = 1 << 50

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
	if ok, err := s.CreateFile(ctx, f, noQuota); err != nil || !ok {
		t.Fatalf("CreateFile: ok=%v err=%v", ok, err)
	}
	if uploaded {
		if ok, err := s.MarkUploaded(ctx, f.ID, f.CreatedAt); err != nil || !ok {
			t.Fatalf("MarkUploaded: ok=%v err=%v", ok, err)
		}
	}
}

func TestOpenIsIdempotentAndPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	for i := 0; i < 2; i++ {
		s, err := Open(context.Background(), path)
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		s.Close()
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		info, err := os.Stat(path + suffix)
		if err != nil {
			continue // WAL files may be removed on close
		}
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Errorf("%s has mode %o, want 600", path+suffix, mode)
		}
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

func TestDeleteIfPending(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	mustCreate(t, s, sample("pending"), false)
	mustCreate(t, s, sample("uploaded"), true)
	if ok, err := s.DeleteIfPending(ctx, "uploaded"); err != nil || ok {
		t.Errorf("uploaded file deleted as pending: ok=%v err=%v", ok, err)
	}
	if ok, err := s.DeleteIfPending(ctx, "pending"); err != nil || !ok {
		t.Errorf("pending file not deleted: ok=%v err=%v", ok, err)
	}
	if ok, _ := s.DeleteIfPending(ctx, "pending"); ok {
		t.Error("deleted twice")
	}
}

func TestDeleteIfBurned(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	f := sample("file-a")
	f.DownloadsLeft = 2
	mustCreate(t, s, f, true)
	if ok, _ := s.DeleteIfBurned(ctx, "file-a", t0); ok {
		t.Error("deleted with downloads left")
	}
	for i := 0; i < 2; i++ {
		if _, ok, _ := s.ConsumeDownload(ctx, "file-a", t0); !ok {
			t.Fatal("download not granted")
		}
	}
	if err := s.CreateDownloadToken(ctx, "file-a", []byte("pending"), t0.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.DeleteIfBurned(ctx, "file-a", t0); ok {
		t.Error("deleted while a token was pending")
	}
	if ok, _ := s.DeleteIfBurned(ctx, "file-a", t0.Add(6*time.Minute)); !ok {
		t.Error("not deleted after the pending token expired")
	}
}

func TestDeleteCascadesToTokens(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	mustCreate(t, s, sample("file-a"), true)
	hash := []byte("token-hash")
	if err := s.CreateDownloadToken(ctx, "file-a", hash, t0.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteFile(ctx, "file-a"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.ConsumeDownloadToken(ctx, "file-a", hash, t0); ok {
		t.Error("token survived the deletion of its file")
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
	mustCreate(t, s, sample("expired-pending-token"), true)
	mustCreate(t, s, sample("burned"), true)
	mustCreate(t, s, sample("burned-pending-token"), true)
	stale := sample("stale-upload")
	stale.CreatedAt = t0.Add(-2 * time.Hour)
	mustCreate(t, s, stale, false)
	fresh := sample("fresh-upload")
	fresh.CreatedAt = t0.Add(-30 * time.Minute)
	mustCreate(t, s, fresh, false)

	for _, id := range []string{"burned", "burned-pending-token"} {
		for i := 0; i < 3; i++ {
			if _, ok, _ := s.ConsumeDownload(ctx, id, t0); !ok {
				t.Fatalf("%s: download %d not granted", id, i)
			}
		}
	}
	for _, id := range []string{"expired-pending-token", "burned-pending-token"} {
		if err := s.CreateDownloadToken(ctx, id, []byte(id), t0.Add(5*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.CreateDownloadToken(ctx, "burned", []byte("old"), t0.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"expired", "expired-pending-token"} {
		if _, err := s.db.Exec(`UPDATE files SET expires_at = ? WHERE id = ?`, t0.Add(-time.Second).Unix(), id); err != nil {
			t.Fatal(err)
		}
	}

	purgeable := func(now time.Time) map[string]bool {
		purges, err := s.Purgeable(ctx, now)
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]bool{}
		for _, p := range purges {
			got[p.ID] = p.Pending
		}
		return got
	}
	// At t0 the pending tokens keep their files alive and the fresh upload is
	// inside its grace period; six minutes later only the fresh upload is kept.
	cases := []struct {
		now  time.Time
		want map[string]bool
	}{
		{t0, map[string]bool{"expired": false, "burned": false, "stale-upload": true}},
		{t0.Add(6 * time.Minute), map[string]bool{"expired": false, "burned": false, "stale-upload": true,
			"expired-pending-token": false, "burned-pending-token": false}},
		{t0.Add(2 * time.Hour), map[string]bool{"expired": false, "burned": false, "stale-upload": true,
			"expired-pending-token": false, "burned-pending-token": false, "fresh-upload": true}},
	}
	for _, tc := range cases {
		got := purgeable(tc.now)
		if len(got) != len(tc.want) {
			t.Errorf("at %v purgeable = %v, want %v", tc.now, got, tc.want)
		}
		for id, pending := range tc.want {
			if p, ok := got[id]; !ok || p != pending {
				t.Errorf("at %v %s: got (%v,%v), want pending=%v", tc.now, id, ok, p, pending)
			}
		}
	}

	if err := s.ExpireTokens(ctx, t0); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM download_tokens`).Scan(&n); err != nil || n != 2 {
		t.Errorf("download tokens after ExpireTokens = %d, err %v", n, err)
	}
}

func TestAuditLog(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	entries := []AuditEntry{
		{Event: "file.created", FileID: "file-a", IPHash: []byte{1}, UAHash: []byte{2}, At: t0},
		{Event: "file.purged", At: t0.Add(time.Hour)},
	}
	for _, e := range entries {
		if err := s.RecordAudit(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.RecentAudit(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Event != "file.purged" || got[0].FileID != "" || got[1].FileID != "file-a" ||
		string(got[1].IPHash) != "\x01" || !got[1].At.Equal(t0) {
		t.Errorf("got %+v", got)
	}
	if err := s.PurgeAudit(ctx, t0.Add(30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.RecentAudit(ctx, 10); len(got) != 1 || got[0].Event != "file.purged" {
		t.Errorf("after purge: %+v", got)
	}
}

func TestTrimAuditKeepsTheNewest(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	for i := 0; i < 10; i++ {
		if err := s.RecordAudit(ctx, AuditEntry{Event: "e", FileID: string(rune('a' + i)), At: t0}); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := s.TrimAudit(ctx, 20); err != nil || n != 0 {
		t.Errorf("under the cap: dropped %d, err %v", n, err)
	}
	if n, err := s.TrimAudit(ctx, 4); err != nil || n != 6 {
		t.Errorf("over the cap: dropped %d, err %v", n, err)
	}
	got, _ := s.RecentAudit(ctx, 100)
	if len(got) != 4 || got[0].FileID != "j" || got[3].FileID != "g" {
		t.Errorf("kept %+v", got)
	}
}

func TestQuotaIsAtomic(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	f := sample("x")
	charge := Charge(f.SizeBytes, len(f.MetaCiphertext))
	quota := 5 * charge

	var wg sync.WaitGroup
	var mu sync.Mutex
	created := 0
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			g := sample(fmt.Sprintf("file-%d", i))
			ok, err := s.CreateFile(ctx, g, quota)
			if err != nil {
				t.Error(err)
				return
			}
			if ok {
				mu.Lock()
				created++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if created != 5 {
		t.Errorf("%d created under a quota for 5", created)
	}
	if used, _ := s.Usage(ctx); used != quota {
		t.Errorf("usage %d, want %d", used, quota)
	}
}

func TestUsageFollowsEveryDeletePath(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	mustCreate(t, s, sample("deleted"), true)
	mustCreate(t, s, sample("pending"), false)
	burned := sample("burned")
	burned.DownloadsLeft = 1
	mustCreate(t, s, burned, true)
	mustCreate(t, s, sample("kept"), true)

	if err := s.DeleteFile(ctx, "deleted"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.DeleteIfPending(ctx, "pending"); !ok {
		t.Fatal("pending not deleted")
	}
	if _, ok, _ := s.ConsumeDownload(ctx, "burned", t0); !ok {
		t.Fatal("download not granted")
	}
	if ok, _ := s.DeleteIfBurned(ctx, "burned", t0); !ok {
		t.Fatal("burned not deleted")
	}
	var sum int64
	if err := s.db.QueryRow(`SELECT COALESCE(SUM(charge), 0) FROM files`).Scan(&sum); err != nil {
		t.Fatal(err)
	}
	f := sample("kept")
	if used, _ := s.Usage(ctx); used != sum || used != Charge(f.SizeBytes, len(f.MetaCiphertext)) {
		t.Errorf("usage %d, sum of charges %d", used, sum)
	}
}

func TestQuotaMigrationChargesExistingRecords(t *testing.T) {
	all, err := fs.Sub(migrations, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	before := fstest.MapFS{}
	for _, name := range []string{"0001_files.sql", "0002_audit.sql"} {
		data, err := fs.ReadFile(all, name)
		if err != nil {
			t.Fatal(err)
		}
		before[name] = &fstest.MapFile{Data: data}
	}
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "old.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := migrate(ctx, db, before); err != nil {
		t.Fatal(err)
	}
	for i, size := range []int64{1000, 2000} {
		_, err := db.Exec(`INSERT INTO files (id, size_bytes, meta_ciphertext, auth_key, owner_token_hash,
			downloads_left, expires_at, created_at) VALUES (?, ?, ?, x'00', x'00', 1, 0, 0)`,
			fmt.Sprintf("old-%d", i), size, make([]byte, 100))
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := migrate(ctx, db, all); err != nil {
		t.Fatal(err)
	}
	var used int64
	if err := db.QueryRow(`SELECT charged FROM usage WHERE id = 1`).Scan(&used); err != nil {
		t.Fatal(err)
	}
	if want := Charge(1000, 100) + Charge(2000, 100); used != want {
		t.Errorf("usage after migration %d, want %d", used, want)
	}
}
