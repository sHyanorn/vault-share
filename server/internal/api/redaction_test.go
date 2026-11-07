package api

import (
	"bytes"
	"log/slog"
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
	sh := e.shared(500, 2, 3600)
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
	for name, secret := range map[string]string{
		"owner token":    sh.owner,
		"download token": dl.Token,
		"challenge":      m.Challenge,
		"auth key":       encoding.EncodeToString(sh.authKey),
		"metadata":       encoding.EncodeToString(sh.meta),
		"signature":      sign(sh.authKey, m.Challenge),
		"content":        encoding.EncodeToString(sh.content[:64]),
		"user agent":     "Go-http-client",
		"query":          "token=",
		"authorization":  "Bearer",
	} {
		if strings.Contains(out, secret) {
			t.Errorf("%s appears in the logs", name)
		}
	}
}
