package api

import (
	"encoding/json"
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
	writeFile(t, filepath.Join(root, "secret.txt"), "SECRET")
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
		rec := do(h, http.MethodGet, "/api/v1/files/x")
		if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "not_found") {
			t.Errorf("status %d body %q", rec.Code, rec.Body.String())
		}
	})

	t.Run("traversal cannot leave the web dir", func(t *testing.T) {
		for _, target := range []string{"/../secret.txt", "/assets/../../secret.txt", "/%2e%2e/secret.txt"} {
			rec := do(h, http.MethodGet, target)
			if strings.Contains(rec.Body.String(), "SECRET") {
				t.Errorf("%s: served a file outside the web dir", target)
			}
		}
	})

	t.Run("only GET and HEAD", func(t *testing.T) {
		rec := do(h, http.MethodPost, "/f/abc")
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("status %d", rec.Code)
		}
	})
}
