package main

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sHyanorn/vault-share/server/internal/blob"
	"github.com/sHyanorn/vault-share/server/internal/store"
)

const storedID = "AAAAAAAAAAAAAAAAAAAAAA"

func TestNewDatabaseOverStoredContentIsRefused(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "vault.db")
	blobs, err := blob.NewDisk(filepath.Join(dir, "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	if err := refuseNewDatabaseOverContent(ctx, dbPath, blobs); err != nil {
		t.Fatalf("a first start on empty storage was refused: %v", err)
	}
	if err := blobs.Put(ctx, storedID, 3, strings.NewReader("abc")); err != nil {
		t.Fatal(err)
	}

	err = refuseNewDatabaseOverContent(ctx, dbPath, blobs)
	if err == nil || !strings.Contains(err.Error(), storedID) || !strings.Contains(err.Error(), "Restore the database") {
		t.Errorf("no database, stored content: %v, want a refusal that names the content and the remedy", err)
	}
	if _, statErr := os.Stat(dbPath); !errors.Is(statErr, fs.ErrNotExist) {
		t.Errorf("the refusal left a database behind, so a second start would pass: %v", statErr)
	}

	// An empty file is what an interrupted first start leaves.
	if err := os.WriteFile(dbPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := refuseNewDatabaseOverContent(ctx, dbPath, blobs); err == nil {
		t.Error("an empty database file over stored content was accepted")
	}

	st, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	if err := refuseNewDatabaseOverContent(ctx, dbPath, blobs); err != nil {
		t.Errorf("an existing database was refused: %v", err)
	}
}
