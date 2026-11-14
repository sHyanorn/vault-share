package api

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strings"
	"testing"
)

// TestLogsNeverContainSecrets drives the whole lifecycle, including failures,
// with every log line captured, then checks that nothing a client sent or
// received as a secret appears in them. CLAUDE.md: logs must never contain
// keys, tokens, passwords or file contents.
func TestLogsNeverContainSecrets(t *testing.T) {
	var logs bytes.Buffer
	e := newEnvWith(t, func(o *Options) {
		o.Logger = slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	})
	// Printable content, so a copy of it in a log line is found as text too.
	sh := e.create(500, 2, 3600)
	sh.content = []byte(strings.Repeat("file contents ", 36)[:500])
	if status := e.upload(sh, sh.owner, sh.content); status != http.StatusNoContent {
		t.Fatalf("upload: %d", status)
	}
	m, _ := e.meta(sh.id)
	dl, _ := e.download(sh.id, m.Challenge, sign(sh.authKey, m.Challenge))
	e.content(sh.id, dl.Token)
	e.download(sh.id, m.Challenge, sign(randomBytes(32), m.Challenge)) // denied
	e.upload(sh, "Bearer-looking-garbage", sh.content)                 // bad owner token
	e.content(sh.id, "garbage-token")
	e.remove(sh.id, sh.owner)

	out := logs.String()
	if !strings.Contains(out, `"path":"/api/v1/files/`+sh.id) {
		t.Fatalf("request log missing: %s", out)
	}
	decode := func(s string) []byte {
		b, err := encoding.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	// A secret reaches a log as it was sent, or as bytes, which slog writes
	// in standard base64 and %x in hex; whole base64 groups of its start
	// are a prefix of any of its encodings.
	for name, secret := range map[string][]byte{
		"owner token":    decode(sh.owner),
		"download token": decode(dl.Token),
		"challenge":      decode(m.Challenge),
		"auth key":       sh.authKey,
		"metadata":       sh.meta,
		"signature":      decode(sign(sh.authKey, m.Challenge)),
		"content":        sh.content,
	} {
		head := secret[:min(len(secret), 63)]
		head = head[:len(head)-len(head)%3]
		for _, form := range []string{
			encoding.EncodeToString(head), base64.StdEncoding.EncodeToString(head),
			hex.EncodeToString(head), string(head),
		} {
			if strings.Contains(out, form) {
				t.Errorf("%s appears in the logs as %q", name, form)
			}
		}
	}
	for name, text := range map[string]string{
		"user agent":    "Go-http-client",
		"query":         "token=",
		"authorization": "Bearer",
	} {
		if strings.Contains(out, text) {
			t.Errorf("%s appears in the logs", name)
		}
	}
}
