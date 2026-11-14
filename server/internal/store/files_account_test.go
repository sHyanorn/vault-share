package store

import (
	"context"
	"testing"
	"time"
)

func TestKeptFiles(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	alice, _ := s.CreateUser(ctx, user("alice"), 10)
	bob, _ := s.CreateUser(ctx, user("bob"), 10)
	for i, id := range []string{"old", "new", "expired", "burned", "bobs"} {
		f := sample(id)
		f.CreatedAt = t0.Add(time.Duration(i) * time.Minute)
		switch id {
		case "expired":
			f.ExpiresAt = t0.Add(time.Hour)
		case "burned":
			f.DownloadsLeft = 0
		}
		if _, err := s.CreateFile(ctx, f, noQuota); err != nil {
			t.Fatal(err)
		}
	}
	s.MarkUploaded(ctx, "new", t0)
	for _, id := range []string{"old", "new", "expired", "burned"} {
		if ok, err := s.KeepFile(ctx, id, alice, []byte("entry-"+id), t0); !ok || err != nil {
			t.Fatalf("keep %s: %v %v", id, ok, err)
		}
	}
	if ok, _ := s.KeepFile(ctx, "bobs", bob, []byte("entry"), t0); !ok {
		t.Fatal("keep bobs")
	}
	// Another account cannot take a kept file; its own account may re-key it.
	if ok, _ := s.KeepFile(ctx, "new", bob, []byte("stolen"), t0); ok {
		t.Error("bob took alice's file")
	}
	if ok, _ := s.KeepFile(ctx, "new", alice, []byte("entry-new"), t0); !ok {
		t.Error("alice could not keep her file again")
	}
	if ok, _ := s.KeepFile(ctx, "missing", alice, []byte("entry"), t0); ok {
		t.Error("kept a file that does not exist")
	}

	kept, err := s.KeptFiles(ctx, alice, t0.Add(2*time.Hour), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(kept) != 2 || kept[0].ID != "new" || kept[1].ID != "old" || !kept[0].Uploaded || kept[1].Uploaded ||
		string(kept[0].Entry) != "entry-new" || string(kept[1].MetaCiphertext) != "meta" {
		t.Errorf("kept %+v", kept)
	}
	if kept, _ := s.KeptFiles(ctx, alice, t0.Add(2*time.Hour), 1); len(kept) != 1 {
		t.Errorf("limit 1 gave %d", len(kept))
	}
	if ok, _ := s.KeepFile(ctx, "old", alice, []byte("late"), t0.Add(25*time.Hour)); ok {
		t.Error("kept an expired file")
	}
}

func TestDeleteUserExpiresItsFiles(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	alice, _ := s.CreateUser(ctx, user("alice"), 10)
	for _, id := range []string{"hers", "anonymous"} {
		s.CreateFile(ctx, sample(id), noQuota)
		s.MarkUploaded(ctx, id, t0)
	}
	s.KeepFile(ctx, "hers", alice, []byte("entry"), t0)
	now := t0.Add(time.Hour)
	if err := s.DeleteUser(ctx, alice, now, nil); err != nil {
		t.Fatal(err)
	}
	hers, _ := s.GetFile(ctx, "hers")
	other, _ := s.GetFile(ctx, "anonymous")
	if hers.Live(now) || !other.Live(now) {
		t.Errorf("after deletion: hers live %v, anonymous live %v", hers.Live(now), other.Live(now))
	}
	purges, _ := s.Purgeable(ctx, now)
	if len(purges) != 1 || purges[0].ID != "hers" {
		t.Errorf("purgeable %+v", purges)
	}
	var entry []byte
	s.db.QueryRow(`SELECT entry FROM files WHERE id = 'hers'`).Scan(&entry)
	if entry != nil {
		t.Error("the entry outlived its account")
	}
}
