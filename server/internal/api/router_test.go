package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newTestRouter(t *testing.T, webDir string) http.Handler {
	t.Helper()
	h, err := NewRouter(Options{Logger: slog.New(slog.DiscardHandler), WebDir: webDir})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func do(h http.Handler, method, target string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, target, nil))
	return rec
}

func TestHealthz(t *testing.T) {
	rec := do(newTestRouter(t, ""), http.MethodGet, "/healthz")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil || body["status"] != "ok" {
		t.Fatalf("body %q err %v", rec.Body.String(), err)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q", rec.Header().Get("Cache-Control"))
	}
}

func TestHealthzReportsAFailedCheck(t *testing.T) {
	var failure error
	h, err := NewRouter(Options{Logger: slog.New(slog.DiscardHandler), Health: func(context.Context) error { return failure }})
	if err != nil {
		t.Fatal(err)
	}
	if rec := do(h, http.MethodGet, "/healthz"); rec.Code != http.StatusOK {
		t.Fatalf("passing check: status %d", rec.Code)
	}
	failure = errors.New("database: disk I/O error at /data/vault.db")
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		rec := do(h, method, "/healthz")
		if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s with a failing check: status %d, Cache-Control %q", method, rec.Code, rec.Header().Get("Cache-Control"))
		}
		// The probe is public; the reason belongs in the log only.
		if body := rec.Body.String(); strings.Contains(body, "database") || strings.Contains(body, "/data") {
			t.Errorf("%s: the answer tells what failed: %s", method, body)
		}
	}
	var body map[string]string
	if err := json.NewDecoder(do(h, http.MethodGet, "/healthz").Body).Decode(&body); err != nil || body["status"] != "unavailable" {
		t.Errorf("body %v err %v", body, err)
	}
}

func TestHealthzMethods(t *testing.T) {
	for _, webDir := range []string{"", t.TempDir()} {
		if webDir != "" {
			writeFile(t, filepath.Join(webDir, "index.html"), "INDEX")
		}
		h := newTestRouter(t, webDir)
		if rec := do(h, http.MethodHead, "/healthz"); rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/json" {
			t.Errorf("webDir=%q HEAD: status %d type %q", webDir, rec.Code, rec.Header().Get("Content-Type"))
		}
		if rec := do(h, http.MethodPost, "/healthz"); rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("webDir=%q POST: status %d", webDir, rec.Code)
		}
	}
}

func TestRequestLogOmitsQueryString(t *testing.T) {
	var buf bytes.Buffer
	h, err := NewRouter(Options{Logger: slog.New(slog.NewJSONHandler(&buf, nil))})
	if err != nil {
		t.Fatal(err)
	}
	do(h, http.MethodGet, "/healthz?token=secret")
	line := buf.String()
	if !strings.Contains(line, `"path":"/healthz"`) || !strings.Contains(line, `"status":200`) {
		t.Errorf("unexpected log line %q", line)
	}
	if strings.Contains(line, "token") || strings.Contains(line, "secret") {
		t.Errorf("query string leaked into the log: %q", line)
	}
}

func TestPanicIsLoggedAndAnswered(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	h := requestLog(log)(recoverer(log)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	})))
	rec := do(h, http.MethodGet, "/boom")
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), `"internal"`) {
		t.Errorf("status %d body %q", rec.Code, rec.Body.String())
	}
	out := buf.String()
	if !strings.Contains(out, `"msg":"panic"`) || !strings.Contains(out, `"value":"boom"`) || !strings.Contains(out, `"status":500`) {
		t.Errorf("log output %q", out)
	}
}

func TestUnknownAPIRouteIsJSON404(t *testing.T) {
	h := newTestRouter(t, "")
	for _, target := range []string{"/api/v1", "/api/v1/", "/api/v1/files/x/content"} {
		rec := do(h, http.MethodGet, target)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: status %d", target, rec.Code)
		}
		var body errorBody
		if err := json.NewDecoder(rec.Body).Decode(&body); err != nil || body.Error.Code != "not_found" {
			t.Errorf("%s: body %q err %v", target, rec.Body.String(), err)
		}
	}
}

func TestNoWebDirMeans404ForPages(t *testing.T) {
	if rec := do(newTestRouter(t, ""), http.MethodGet, "/f/abc"); rec.Code != http.StatusNotFound {
		t.Errorf("status %d", rec.Code)
	}
}

func TestWebDirMustContainIndex(t *testing.T) {
	if _, err := NewRouter(Options{Logger: slog.New(slog.DiscardHandler), WebDir: t.TempDir()}); err == nil {
		t.Fatal("want error for web dir without index.html")
	}
}

func writeFile(t *testing.T, name, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestSPA(t *testing.T) {
	root := t.TempDir()
	web := filepath.Join(root, "dist")
	writeFile(t, filepath.Join(web, "index.html"), "INDEX")
	writeFile(t, filepath.Join(web, "assets", "app-abc123.js"), "console.log(1)")
	writeFile(t, filepath.Join(web, "favicon.svg"), "<svg/>")
	writeFile(t, filepath.Join(root, "secret.txt"), "SECRET")
	if err := os.Symlink(filepath.Join(root, "secret.txt"), filepath.Join(web, "link.txt")); err != nil {
		t.Fatal(err)
	}
	h := newTestRouter(t, web)

	cases := []struct {
		name, target string
		status       int
		body         string
		cache        string
	}{
		{"root", "/", http.StatusOK, "INDEX", "no-cache"},
		{"client route", "/f/abc", http.StatusOK, "INDEX", "no-cache"},
		{"asset", "/assets/app-abc123.js", http.StatusOK, "console.log(1)", "public, max-age=31536000, immutable"},
		{"unhashed file", "/favicon.svg", http.StatusOK, "<svg/>", "no-cache"},
		{"missing asset", "/assets/nope.js", http.StatusOK, "INDEX", "no-cache"},
		{"directory is not listed", "/assets/", http.StatusOK, "INDEX", "no-cache"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := do(h, http.MethodGet, tc.target)
			if rec.Code != tc.status {
				t.Fatalf("status %d", rec.Code)
			}
			if got, _ := io.ReadAll(rec.Body); strings.TrimSpace(string(got)) != tc.body {
				t.Errorf("body %q", got)
			}
			if got := rec.Header().Get("Cache-Control"); got != tc.cache {
				t.Errorf("Cache-Control %q", got)
			}
		})
	}

	t.Run("api paths never fall back to index", func(t *testing.T) {
		rec := do(h, http.MethodGet, "/api/v1/nope")
		if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "not_found") {
			t.Errorf("status %d body %q", rec.Code, rec.Body.String())
		}
		rec = do(h, http.MethodGet, "/api/v1/files/x")
		if rec.Code != http.StatusMethodNotAllowed || !strings.Contains(rec.Body.String(), "method_not_allowed") ||
			rec.Header().Get("Allow") != "DELETE" {
			t.Errorf("status %d allow %q body %q", rec.Code, rec.Header().Get("Allow"), rec.Body.String())
		}
	})

	t.Run("traversal cannot leave the web dir", func(t *testing.T) {
		for _, target := range []string{"/../secret.txt", "/assets/../../secret.txt", "/%2e%2e/secret.txt", "/link.txt"} {
			rec := do(h, http.MethodGet, target)
			if strings.Contains(rec.Body.String(), "SECRET") {
				t.Errorf("%s: served a file outside the web dir", target)
			}
		}
	})

	t.Run("only GET and HEAD", func(t *testing.T) {
		if rec := do(h, http.MethodHead, "/f/abc"); rec.Code != http.StatusOK || rec.Body.Len() != 0 {
			t.Errorf("HEAD: status %d body %q", rec.Code, rec.Body.String())
		}
		if rec := do(h, http.MethodPost, "/f/abc"); rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("POST: status %d", rec.Code)
		}
	})
}
