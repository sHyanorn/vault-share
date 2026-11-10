package main

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

	_, err = openDatabase(ctx, dbPath, blobs)
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
	st, err = openDatabase(ctx, dbPath, blobs)
	if err != nil {
		t.Fatalf("an existing database was refused: %v", err)
	}
	st.Close()
}

func TestMissingAccountKeyBesideAccountsIsRefused(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, accountKeyFile)
	st, err := store.Open(ctx, filepath.Join(dir, "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	first, err := loadAccountKey(ctx, dir, st)
	if err != nil {
		t.Fatalf("a first start without accounts was refused: %v", err)
	}
	// Lost before anyone signed up: nothing depends on it yet.
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAccountKey(ctx, dir, st); err != nil {
		t.Fatalf("no key, no accounts: %v", err)
	}

	u := store.User{Username: "alice", Salt: []byte("salt"), AuthHash: "hash", SealedKey: []byte("sealed"), CreatedAt: time.Unix(1, 0)}
	if _, err := st.CreateUser(ctx, u, 1); err != nil {
		t.Fatal(err)
	}
	key, err := loadAccountKey(ctx, dir, st)
	if err != nil || bytes.Equal(key, first) {
		t.Fatalf("existing key beside accounts: %v, the removed key came back: %t", err, bytes.Equal(key, first))
	}

	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	_, err = loadAccountKey(ctx, dir, st)
	if err == nil || !strings.Contains(err.Error(), keyPath) || !strings.Contains(err.Error(), "docs/OPERATIONS.md") {
		t.Errorf("no key beside accounts: %v, want a refusal that names the file and the manual", err)
	}
	if _, statErr := os.Stat(keyPath); !errors.Is(statErr, fs.ErrNotExist) {
		t.Errorf("the refusal left a key behind, so a second start would pass: %v", statErr)
	}

	// The documented way out: a key the operator creates on purpose.
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{7}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if key, err := loadAccountKey(ctx, dir, st); err != nil || key[0] != 7 {
		t.Errorf("an operator-made key was not used: %v", err)
	}
}
