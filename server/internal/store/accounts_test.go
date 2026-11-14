package store

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// renewal stands in for the session a change to how an account signs in
// opens.
var renewal = Renewal{SessionHash: []byte("renewed"), Now: t0}

func user(name string) User {
	return User{Username: name, Salt: []byte("salt-16-bytes!!!"), AuthHash: "$argon2id$hash",
		SealedKey: []byte("sealed"), CreatedAt: t0}
}

func TestCreateUser(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	if any, err := s.HasUsers(ctx); err != nil || any {
		t.Fatalf("new database has users: %t %v", any, err)
	}
	id, err := s.CreateUser(ctx, user("alice"), 2)
	if err != nil || id == 0 {
		t.Fatalf("create: %d %v", id, err)
	}
	if any, err := s.HasUsers(ctx); err != nil || !any {
		t.Errorf("after a sign-up, has users: %t %v", any, err)
	}
	if _, err := s.CreateUser(ctx, user("alice"), 2); !errors.Is(err, ErrUsernameTaken) {
		t.Errorf("taken: %v", err)
	}
	if _, err := s.CreateUser(ctx, user("bob"), 2); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser(ctx, user("carol"), 2); !errors.Is(err, ErrCapacity) {
		t.Errorf("past the cap: %v", err)
	}
	got, err := s.UserByName(ctx, "alice")
	want := user("alice")
	want.ID = id
	if err != nil || fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("got %+v %v, want %+v", got, err, want)
	}
	if _, err := s.UserByName(ctx, "nobody"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown: %v", err)
	}
}

// Audit entries outlive their account, so no id is given out twice (F60).
func TestAccountIDsAreNeverReused(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	if _, err := s.CreateUser(ctx, user("first"), 10); err != nil {
		t.Fatal(err)
	}
	gone, err := s.CreateUser(ctx, user("gone"), 10)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteUser(ctx, gone, t0); err != nil {
		t.Fatal(err)
	}
	if id, err := s.CreateUser(ctx, user("next"), 10); err != nil || id <= gone {
		t.Errorf("after account %d was deleted, the next got id %d (%v)", gone, id, err)
	}
}

func TestAccountCapHoldsUnderConcurrency(t *testing.T) {
	s := openTest(t)
	var created atomic.Int32
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Go(func() {
			if _, err := s.CreateUser(context.Background(), user(fmt.Sprintf("user-%d", i)), 5); err == nil {
				created.Add(1)
			} else if !errors.Is(err, ErrCapacity) {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if created.Load() != 5 {
		t.Errorf("%d accounts under a cap of 5", created.Load())
	}
}

func TestSessionLifetimes(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	id, _ := s.CreateUser(ctx, user("alice"), 10)
	if err := s.CreateSession(ctx, []byte("token"), id, t0, 10); err != nil {
		t.Fatal(err)
	}
	valid := func(at time.Time) bool {
		t.Helper()
		u, ok, err := s.SessionUser(ctx, []byte("token"), at)
		if err != nil {
			t.Fatal(err)
		}
		if ok && u.Username != "alice" {
			t.Errorf("session of %q", u.Username)
		}
		return ok
	}
	if !valid(t0.Add(SessionIdle - time.Second)) {
		t.Fatal("ended before the idle timeout")
	}
	// That use moved the idle timeout on.
	if !valid(t0.Add(2*SessionIdle - 2*time.Second)) {
		t.Error("use did not keep the session alive")
	}
	if valid(t0.Add(3*SessionIdle - time.Second)) {
		t.Error("idle session still valid")
	}
	if _, ok, _ := s.SessionUser(ctx, []byte("other"), t0); ok {
		t.Error("unknown token accepted")
	}
}

func TestSessionsKeepTheNewest(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	alice, _ := s.CreateUser(ctx, user("alice"), 10)
	bob, _ := s.CreateUser(ctx, user("bob"), 10)
	s.CreateSession(ctx, []byte("bob"), bob, t0, 2)
	for i := range 4 {
		if err := s.CreateSession(ctx, []byte{byte(i)}, alice, t0.Add(time.Duration(i)*time.Second), 2); err != nil {
			t.Fatal(err)
		}
	}
	for token, want := range map[string]bool{"\x00": false, "\x01": false, "\x02": true, "\x03": true, "bob": true} {
		if _, ok, _ := s.SessionUser(ctx, []byte(token), t0.Add(time.Minute)); ok != want {
			t.Errorf("session %q valid %v, want %v", token, ok, want)
		}
	}
}

func TestExpireSessions(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	id, _ := s.CreateUser(ctx, user("alice"), 10)
	s.CreateSession(ctx, []byte("idle"), id, t0, 10)
	s.CreateSession(ctx, []byte("busy"), id, t0, 10)
	for at := t0.Add(30 * time.Minute); at.Before(t0.Add(SessionLifetime)); at = at.Add(30 * time.Minute) {
		s.SessionUser(ctx, []byte("busy"), at)
		if err := s.ExpireSessions(ctx, at); err != nil {
			t.Fatal(err)
		}
	}
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&n)
	if n != 1 {
		t.Errorf("%d sessions left before the day is over, want the busy one", n)
	}
	s.ExpireSessions(ctx, t0.Add(SessionLifetime))
	s.db.QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&n)
	if n != 0 {
		t.Errorf("%d sessions outlived their day", n)
	}
}

func TestDeleteUserEndsItsSessions(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	id, _ := s.CreateUser(ctx, user("alice"), 10)
	s.CreateSession(ctx, []byte("token"), id, t0, 10)
	if err := s.DeleteUser(ctx, id, t0); err != nil {
		t.Fatal(err)
	}
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&n)
	if n != 0 {
		t.Errorf("%d sessions outlived their account", n)
	}
}

func TestSetPassword(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	id, _ := s.CreateUser(ctx, user("alice"), 10)
	if err := s.SetPassword(ctx, id, []byte("new-salt"), "$argon2id$new", []byte("new-sealed"), renewal); err != nil {
		t.Fatal(err)
	}
	u, _ := s.UserByName(ctx, "alice")
	if string(u.Salt) != "new-salt" || u.AuthHash != "$argon2id$new" || string(u.SealedKey) != "new-sealed" {
		t.Errorf("after the change: %+v", u)
	}
}
