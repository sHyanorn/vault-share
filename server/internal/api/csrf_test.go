package api

import (
	"maps"
	"net/http"
	"testing"
)

// Sessions ride on a cookie, so every request that uses one must come from
// the vault-share page itself (D028). The checks of D022 refuse requests that
// browsers mark as coming from another site, and writes whose Origin is
// another site; the SameSite=Strict cookie is the second line.
func TestCrossSiteRequestsCannotUseTheSession(t *testing.T) {
	e := newAccountEnv(t)
	alice := newCreds("alice")
	victim := e.browser()
	victim.signup(alice)
	mallory := newCreds("mallory")
	e.browser().signup(mallory)
	held := maps.Clone(victim.cookies)

	next := newCreds("alice")
	requests := []struct {
		name, method, path string
		body               any
	}{
		{"sign-up", http.MethodPost, "/api/v1/account", signupRequest{Username: "planted",
			Salt: encoding.EncodeToString(next.salt), Auth: encoding.EncodeToString(next.auth), SealedKey: encoding.EncodeToString(next.sealed)}},
		{"salt lookup", http.MethodPost, "/api/v1/account/salt", usernameRequest{Username: "alice"}},
		// Login CSRF: signing the victim in to the attacker's account.
		{"sign-in", http.MethodPost, "/api/v1/session", loginRequest{Username: "mallory", Auth: encoding.EncodeToString(mallory.auth)}},
		{"session read", http.MethodGet, "/api/v1/session", nil},
		{"sign-out", http.MethodDelete, "/api/v1/session", nil},
		{"password change", http.MethodPost, "/api/v1/account/password", passwordRequest{
			Auth: encoding.EncodeToString(alice.auth), Salt: encoding.EncodeToString(next.salt),
			NewAuth: encoding.EncodeToString(next.auth), SealedKey: encoding.EncodeToString(next.sealed)}},
		{"account deletion", http.MethodDelete, "/api/v1/account", confirmRequest{Auth: encoding.EncodeToString(alice.auth)}},
		{"two-factor setup", http.MethodPost, "/api/v1/account/totp/setup", nil},
		{"two-factor change", http.MethodPost, "/api/v1/account/totp", totpRequest{Auth: encoding.EncodeToString(alice.auth), Code: "123456"}},
		{"second step", http.MethodPost, "/api/v1/session/totp", secondStepRequest{Ticket: encoding.EncodeToString(randomBytes(32)), Code: "123456"}},
		{"file list", http.MethodGet, "/api/v1/account/files", nil},
		{"keeping a file", http.MethodPut, "/api/v1/account/files/" + encoding.EncodeToString(randomBytes(16)), keepRequest{Entry: encoding.EncodeToString(randomBytes(100))}},
	}
	attacks := []map[string]string{
		{"Sec-Fetch-Site": "cross-site"},
		{"Sec-Fetch-Site": "same-site"},
		// A browser without Fetch Metadata still sends Origin on writes.
		{"Origin": "https://attacker.example"},
	}
	for _, req := range requests {
		for _, headers := range attacks {
			if headers["Origin"] != "" && req.method == http.MethodGet {
				continue // a read reveals nothing without CORS, and only Fetch Metadata marks it
			}
			victim.headers = headers
			status, body := victim.send(req.method, req.path, req.body, nil)
			if status != http.StatusForbidden || errorCode(body) != "cross_origin" {
				t.Errorf("%s with %v: %d %s", req.name, headers, status, body)
			}
			if victim.last.Get("Set-Cookie") != "" {
				t.Errorf("%s with %v set a cookie", req.name, headers)
			}
		}
	}
	victim.headers = nil
	if !maps.Equal(victim.cookies, held) {
		t.Error("the victim's cookies changed")
	}

	// Nothing happened: the session is alive and still alice's, the
	// password is unchanged and no account was planted.
	if status, s := victim.current(); status != http.StatusOK || s.Username != "alice" {
		t.Errorf("the victim's session: %d %+v", status, s)
	}
	if status, _ := e.browser().login("alice", alice.auth); status != http.StatusOK {
		t.Errorf("the victim's password: %d", status)
	}
	if status, _ := e.browser().signup(newCreds("planted")); status != http.StatusCreated {
		t.Errorf("the planted name is taken: %d", status)
	}

	// The same requests from the page itself go through.
	victim.headers = map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": e.srv.URL}
	if status, _ := victim.current(); status != http.StatusOK {
		t.Errorf("same-origin session read: %d", status)
	}
	if vary := victim.last.Get("Vary"); vary != "Sec-Fetch-Site, Origin" {
		t.Errorf("Vary: %q", vary)
	}
	if status, _ := victim.send(http.MethodDelete, "/api/v1/session", nil, nil); status != http.StatusNoContent {
		t.Errorf("same-origin sign-out: %d", status)
	}
}
