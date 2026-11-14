package main

import (
	"bytes"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testCSP = "default-src 'self'"

// client writes a small built client and its manifest.
func client(t *testing.T) (dir, manifest string) {
	t.Helper()
	dir = t.TempDir()
	write(t, filepath.Join(dir, "index.html"), `<script src="/assets/app.js"></script>`)
	write(t, filepath.Join(dir, "assets", "app.js"), "console.log('vault-share')")
	var out, errs bytes.Buffer
	if code := run([]string{"manifest", "-dir", dir, "-csp", testCSP, "-version", "v0"}, &out, &errs); code != 0 {
		t.Fatalf("manifest: exit %d: %s", code, errs.String())
	}
	manifest = filepath.Join(t.TempDir(), "manifest.json")
	write(t, manifest, out.String())
	return dir, manifest
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// changeByte flips one bit of the file at path.
func changeByte(t *testing.T, path string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)/2] ^= 1
	write(t, path, string(b))
}

// site serves dir the way vaultd does: the CSP on every response, the
// index at / and at any path that names no file.
func site(t *testing.T, dir string, csp string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(siteHandler(dir, csp))
	t.Cleanup(srv.Close)
	return srv
}

func siteHandler(dir, csp string) http.Handler {
	files := http.FileServer(http.Dir(dir))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", csp)
		if info, err := os.Stat(filepath.Join(dir, filepath.FromSlash(r.URL.Path))); err == nil && !info.IsDir() {
			files.ServeHTTP(w, r)
			return
		}
		http.ServeFile(w, r, filepath.Join(dir, "index.html"))
	})
}

func verifyCode(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var out, errs bytes.Buffer
	code := run(append([]string{"verify"}, args...), &out, &errs)
	return code, out.String() + errs.String()
}

func TestVerifySite(t *testing.T) {
	dir, manifest := client(t)
	code, out := verifyCode(t, "-manifest", manifest, site(t, dir, testCSP).URL)
	if code != 0 || !strings.Contains(out, "all 2 files match") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	for _, path := range []string{"/assets/app.js", "/f/AAAAAAAAAAAAAAAAAAAAAA", "/ "} {
		if !strings.Contains(out, "ok       "+path) {
			t.Errorf("%s not checked:\n%s", path, out)
		}
	}
}

func TestVerifySiteFindsAChangedByte(t *testing.T) {
	dir, manifest := client(t)
	changeByte(t, filepath.Join(dir, "assets", "app.js"))
	code, out := verifyCode(t, "-manifest", manifest, site(t, dir, testCSP).URL)
	if code != 1 || !strings.Contains(out, "changed  /assets/app.js") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
}

func TestVerifySiteFindsAChangedIndex(t *testing.T) {
	dir, manifest := client(t)
	changeByte(t, filepath.Join(dir, "index.html"))
	code, out := verifyCode(t, "-manifest", manifest, site(t, dir, testCSP).URL)
	if code != 1 || !strings.Contains(out, "changed  / ") || !strings.Contains(out, "changed  /f/") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
}

func TestVerifySiteFindsAnotherCSP(t *testing.T) {
	dir, manifest := client(t)
	code, out := verifyCode(t, "-manifest", manifest, site(t, dir, testCSP+"; script-src *").URL)
	if code != 1 || !strings.Contains(out, "csp      /assets/app.js") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
}

func TestVerifySiteFindsALongerFile(t *testing.T) {
	dir, manifest := client(t)
	write(t, filepath.Join(dir, "assets", "app.js"), "console.log('vault-share');alert(1)")
	code, out := verifyCode(t, "-manifest", manifest, site(t, dir, testCSP).URL)
	if code != 1 || !strings.Contains(out, "changed  /assets/app.js  want 26 bytes, got more") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
}

func TestVerifySiteDoesNotFollowRedirects(t *testing.T) {
	dir, manifest := client(t)
	good := site(t, dir, testCSP)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", testCSP)
		if r.URL.Path == "/assets/app.js" {
			http.Redirect(w, r, good.URL+r.URL.Path, http.StatusFound)
			return
		}
		http.ServeFile(w, r, filepath.Join(dir, "index.html"))
	}))
	defer srv.Close()
	code, out := verifyCode(t, "-manifest", manifest, srv.URL)
	if code != 1 || !strings.Contains(out, "status   /assets/app.js  302 Found") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
}

func TestVerifySiteUnreachable(t *testing.T) {
	_, manifest := client(t)
	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close()
	if code, out := verifyCode(t, "-manifest", manifest, srv.URL); code != 2 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
}

func TestVerifyDir(t *testing.T) {
	dir, manifest := client(t)
	if code, out := verifyCode(t, "-manifest", manifest, "-dir", dir); code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	changeByte(t, filepath.Join(dir, "index.html"))
	write(t, filepath.Join(dir, "assets", "extra.js"), "alert(1)")
	code, out := verifyCode(t, "-manifest", manifest, "-dir", dir)
	if code != 1 || !strings.Contains(out, "changed  index.html") || !strings.Contains(out, "extra    assets/extra.js") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
}

func TestManifestNeedsAnIndex(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "app.js"), "x")
	var out, errs bytes.Buffer
	if code := run([]string{"manifest", "-dir", dir, "-csp", testCSP}, &out, &errs); code != 2 {
		t.Fatalf("exit %d", code)
	}
}

func TestVerifySiteChecksTLS(t *testing.T) {
	dir, manifest := client(t)
	srv := httptest.NewTLSServer(siteHandler(dir, testCSP))
	defer srv.Close()
	if code, out := verifyCode(t, "-manifest", manifest, srv.URL); code != 2 || !strings.Contains(out, "certificate") {
		t.Fatalf("an unknown certificate: exit %d:\n%s", code, out)
	}
	ca := filepath.Join(t.TempDir(), "ca.pem")
	write(t, ca, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})))
	if code, out := verifyCode(t, "-manifest", manifest, "-cafile", ca, srv.URL); code != 0 {
		t.Fatalf("with -cafile: exit %d:\n%s", code, out)
	}
}

func TestVerifyDirFindsAMissingFile(t *testing.T) {
	dir, manifest := client(t)
	if err := os.Remove(filepath.Join(dir, "assets", "app.js")); err != nil {
		t.Fatal(err)
	}
	code, out := verifyCode(t, "-manifest", manifest, "-dir", dir)
	if code != 1 || !strings.Contains(out, "missing  assets/app.js") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
}
