package audit

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sHyanorn/vault-share/server/internal/store"
)

func newRecorder(t *testing.T, dir string) (*Recorder, *store.Store) {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(dir, "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	r, err := New(dir, st, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	return r, st
}

func TestRecordsHashedIdentifiers(t *testing.T) {
	dir := t.TempDir()
	r, st := newRecorder(t, dir)
	ctx := context.Background()
	r.Record(ctx, DownloadGranted, "file-a", Client{IP: "203.0.113.7", UserAgent: "Mozilla/5.0"})
	r.Record(ctx, FilePurged, "file-b", Client{})

	entries, err := st.RecentAudit(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("%d entries", len(entries))
	}
	granted := entries[1]
	if granted.Event != DownloadGranted || granted.FileID != "file-a" {
		t.Errorf("entry %+v", granted)
	}
	if len(granted.IPHash) != 16 || len(granted.UAHash) != 16 {
		t.Errorf("hash lengths %d %d", len(granted.IPHash), len(granted.UAHash))
	}
	if bytes.Contains(granted.IPHash, []byte("203")) || bytes.Equal(granted.IPHash, granted.UAHash) {
		t.Error("identifiers are not hashed independently")
	}
	if entries[0].IPHash != nil || entries[0].UAHash != nil {
		t.Error("empty identifiers must stay empty")
	}

	info, err := os.Stat(filepath.Join(dir, keyFile))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("key file: %v %v", info, err)
	}
}

func TestKeyIsStableAndPrivatePerDeployment(t *testing.T) {
	dir := t.TempDir()
	a, _ := newRecorder(t, dir)
	b, _ := newRecorder(t, dir)
	c, _ := newRecorder(t, t.TempDir())
	if !bytes.Equal(a.hash("203.0.113.7"), b.hash("203.0.113.7")) {
		t.Error("the same deployment must hash consistently across restarts")
	}
	if bytes.Equal(a.hash("203.0.113.7"), c.hash("203.0.113.7")) {
		t.Error("two deployments must not share hashes")
	}
}

func TestPurgeKeepsRecentEntries(t *testing.T) {
	r, st := newRecorder(t, t.TempDir())
	ctx := context.Background()
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	r.Now = func() time.Time { return now.Add(-Retention - time.Hour) }
	r.Record(ctx, FileCreated, "old", Client{})
	r.Now = func() time.Time { return now }
	r.Record(ctx, FileCreated, "new", Client{})
	if err := r.Purge(ctx); err != nil {
		t.Fatal(err)
	}
	entries, _ := st.RecentAudit(ctx, 10)
	if len(entries) != 1 || entries[0].FileID != "new" {
		t.Errorf("after purge: %+v", entries)
	}
}

func TestFailureEventsShareABudget(t *testing.T) {
	r, st := newRecorder(t, t.TempDir())
	var logs bytes.Buffer
	r.log = slog.New(slog.NewJSONHandler(&logs, nil))
	ctx := context.Background()
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	r.Now = func() time.Time { return now }

	for i := 0; i < failureBurst+40; i++ {
		r.Record(ctx, DownloadDenied, "file", Client{IP: "203.0.113.1"})
	}
	r.Record(ctx, ClientLocked, "file", Client{IP: "203.0.113.1"})
	r.Record(ctx, FileCreated, "file", Client{IP: "203.0.113.1"})

	entries, _ := st.RecentAudit(ctx, 1000)
	counts := map[string]int{}
	for _, e := range entries {
		counts[e.Event]++
	}
	if counts[DownloadDenied] != failureBurst || counts[ClientLocked] != 0 || counts[FileCreated] != 1 {
		t.Errorf("counts %v", counts)
	}
	if err := r.Purge(ctx); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), `"count":41`) || strings.Contains(logs.String(), "203.0.113.1") {
		t.Errorf("skip log %s", logs.String())
	}
	now = now.Add(10 * time.Second)
	for i := 0; i < 20; i++ {
		r.Record(ctx, DownloadDenied, "file", Client{})
	}
	entries, _ = st.RecentAudit(ctx, 1000)
	if got := len(entries); got != failureBurst+1+10 {
		t.Errorf("%d entries after the budget refilled for 10s, want %d", got, failureBurst+1+10)
	}
}

func TestPurgeTrimsToTheCap(t *testing.T) {
	r, st := newRecorder(t, t.TempDir())
	var logs bytes.Buffer
	r.log = slog.New(slog.NewJSONHandler(&logs, nil))
	r.max = 5
	ctx := context.Background()
	for i := 0; i < 8; i++ {
		r.Record(ctx, FileCreated, "f", Client{})
	}
	if err := r.Purge(ctx); err != nil {
		t.Fatal(err)
	}
	if entries, _ := st.RecentAudit(ctx, 100); len(entries) != 5 {
		t.Errorf("%d entries, cap 5", len(entries))
	}
	if !strings.Contains(logs.String(), "over capacity") || !strings.Contains(logs.String(), `"count":3`) {
		t.Errorf("trim log %s", logs.String())
	}
}
