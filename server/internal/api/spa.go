package api

import (
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path"
	"strings"
)

// spaHandler serves the built frontend. Paths that do not name a file fall
// back to index.html so the client-side router can handle them, for example
// /f/{id}. Directories are never listed.
type spaHandler struct {
	fsys  fs.FS
	files http.Handler
}

func newSPAHandler(dir string) (*spaHandler, error) {
	fsys := os.DirFS(dir)
	if _, err := fs.Stat(fsys, "index.html"); err != nil {
		return nil, fmt.Errorf("web dir: %w", err)
	}
	return &spaHandler{fsys: fsys, files: http.FileServerFS(fsys)}, nil
}

func (h *spaHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// os.DirFS rejects any name that could escape dir, so a traversal attempt
	// simply fails the Stat and falls through to index.html.
	name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	if name != "" && name != "index.html" {
		if info, err := fs.Stat(h.fsys, name); err == nil && !info.IsDir() {
			if strings.HasPrefix(name, "assets/") {
				// Vite names bundled assets by content hash.
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			}
			h.files.ServeHTTP(w, r)
			return
		}
	}

	w.Header().Set("Cache-Control", "no-cache")
	http.ServeFileFS(w, r, h.fsys, "index.html")
}
