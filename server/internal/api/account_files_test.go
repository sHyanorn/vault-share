package api

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func (b *browser) keep(sh share, owner string, entry []byte) (int, []byte) {
	b.e.t.Helper()
	if b.headers == nil {
		b.headers = map[string]string{}
	}
	b.headers["Authorization"] = "Bearer " + owner
	defer delete(b.headers, "Authorization")
	return b.send(http.MethodPut, "/api/v1/account/files/"+sh.id, keepRequest{Entry: encoding.EncodeToString(entry)}, nil)
}

func (b *browser) kept() (int, keptFilesResponse) {
	var resp keptFilesResponse
	status, _ := b.send(http.MethodGet, "/api/v1/account/files", nil, &resp)
	return status, resp
}

func TestKeepFilesInAnAccount(t *testing.T) {
	e := newAccountEnv(t)
	alice := newCreds("alice")
	b := e.browser()
	b.signup(alice)
	sh := e.shared(100, 3, 3600)
	pending := e.create(100, 1, 3600)
	entry := randomBytes(200)

	if status, _ := e.browser().keep(sh, sh.owner, entry); status != http.StatusUnauthorized {
		t.Errorf("without a session: %d", status)
	}
	if status, _ := b.keep(sh, encoding.EncodeToString(randomBytes(32)), entry); status != http.StatusNotFound {
		t.Errorf("without the owner token: %d", status)
	}
	if status, _ := b.keep(sh, sh.owner, randomBytes(20)); status != http.StatusBadRequest {
		t.Errorf("short entry: %d", status)
	}
	if status, _ := b.keep(sh, sh.owner, randomBytes(maxEntryBytes+1)); status != http.StatusBadRequest {
		t.Errorf("long entry: %d", status)
	}
	if status, body := b.keep(sh, sh.owner, entry); status != http.StatusNoContent {
		t.Fatalf("keep: %d %s", status, body)
	}
	if status, _ := b.keep(pending, pending.owner, entry); status != http.StatusNoContent {
		t.Fatalf("keep a pending file: %d", status)
	}

	status, list := b.kept()
	if status != http.StatusOK || len(list.Files) != 2 || list.More || b.last.Get("Cache-Control") != "no-store" {
		t.Fatalf("list: %d %+v", status, list)
	}
	byID := map[string]keptFile{}
	for _, f := range list.Files {
		byID[f.ID] = f
	}
	got := byID[sh.id]
	if got.Entry != encoding.EncodeToString(entry) || got.Meta != encoding.EncodeToString(sh.meta) || !got.Uploaded ||
		got.DownloadsLeft != 3 || got.ExpiresAt != e.clock().Add(time.Hour).Unix() || byID[pending.id].Uploaded {
		t.Errorf("listed %+v", list.Files)
	}

	// Another account sees none of it and cannot take the file over.
	bob := newCreds("bob")
	other := e.browser()
	other.signup(bob)
	if _, list := other.kept(); len(list.Files) != 0 {
		t.Errorf("bob sees %+v", list.Files)
	}
	if status, _ := other.keep(sh, sh.owner, entry); status != http.StatusNotFound {
		t.Errorf("bob kept alice's file: %d", status)
	}

	// A file that is used up or deleted leaves the list.
	e.token(sh)
	e.remove(pending.id, pending.owner)
	if _, list := b.kept(); len(list.Files) != 1 || list.Files[0].DownloadsLeft != 2 {
		t.Errorf("after a download and a deletion: %+v", list.Files)
	}
	if status, _ := e.browser().send(http.MethodGet, "/api/v1/account/files", nil, nil); status != http.StatusUnauthorized {
		t.Errorf("list without a session: %d", status)
	}
}

func TestDeletingAnAccountDeletesItsFiles(t *testing.T) {
	e := newAccountEnv(t)
	alice := newCreds("alice")
	b := e.browser()
	b.signup(alice)
	hers := e.shared(100, 3, 3600)
	b.keep(hers, hers.owner, randomBytes(100))
	anonymous := e.shared(100, 3, 3600)
	if status, _ := b.send(http.MethodDelete, "/api/v1/account", confirmRequest{Auth: encoding.EncodeToString(alice.auth)}, nil); status != http.StatusNoContent {
		t.Fatalf("delete: %d", status)
	}
	if _, status := e.meta(hers.id); status != http.StatusNotFound {
		t.Errorf("the account's file still opens: %d", status)
	}
	if _, status := e.meta(anonymous.id); status != http.StatusOK {
		t.Errorf("another file was affected: %d", status)
	}
	if err := e.job.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ok, _ := e.store.FileExists(context.Background(), hers.id); ok {
		t.Error("cleanup kept the record")
	}
	if _, err := e.blobs.Open(context.Background(), hers.id); err == nil {
		t.Error("cleanup kept the content")
	}
}
