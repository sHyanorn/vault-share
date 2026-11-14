// Command webcheck compares the web client a deployment serves, or a build
// directory, with a manifest of the released client: each file's size and
// SHA-256, and the Content-Security-Policy the server sends.
//
//	webcheck manifest -dir DIR -csp POLICY [-version V -repository URL -commit SHA]
//	webcheck verify -manifest FILE [-cafile PEM] URL
//	webcheck verify -manifest FILE -dir DIR
//
// verify prints one line per check and exits 0 when everything matches, 1
// when something differs and 2 when it could not check. It finds a changed
// client only in the responses it receives itself.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"
)

// Manifest describes a released client.
type Manifest struct {
	Version string `json:"version"`
	Source  Source `json:"source"`
	// CSP is the Content-Security-Policy every response carries.
	CSP string `json:"csp"`
	// Index is the page served at / and at the client's routes.
	Index string `json:"index"`
	Files []File `json:"files"`
}

type Source struct {
	Repository string `json:"repository"`
	Commit     string `json:"commit"`
}

type File struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// clientRoute is a share link's path, which the server answers with the index.
const clientRoute = "/f/AAAAAAAAAAAAAAAAAAAAAA"

const usage = `usage:
  webcheck manifest -dir DIR -csp POLICY [-version V -repository URL -commit SHA]
  webcheck verify -manifest FILE [-cafile PEM] URL
  webcheck verify -manifest FILE -dir DIR`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	var err error
	code := 0
	switch args[0] {
	case "manifest":
		err = writeManifest(args[1:], stdout)
	case "verify":
		code, err = verify(args[1:], stdout)
	default:
		err = errors.New(usage)
	}
	if err != nil {
		fmt.Fprintln(stderr, "webcheck:", err)
		return 2
	}
	return code
}

func writeManifest(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("manifest", flag.ContinueOnError)
	dir := flags.String("dir", "", "built client directory")
	m := Manifest{Index: "index.html"}
	flags.StringVar(&m.CSP, "csp", "", "Content-Security-Policy the server sends")
	flags.StringVar(&m.Version, "version", "", "release version")
	flags.StringVar(&m.Source.Repository, "repository", "", "source repository URL")
	flags.StringVar(&m.Source.Commit, "commit", "", "source commit")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *dir == "" || m.CSP == "" || flags.NArg() != 0 {
		return errors.New(usage)
	}
	files, err := hashDir(*dir)
	if err != nil {
		return err
	}
	if !slices.ContainsFunc(files, func(f File) bool { return f.Path == m.Index }) {
		return fmt.Errorf("%s has no %s", *dir, m.Index)
	}
	m.Files = files
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "%s\n", out)
	return err
}

// hashDir lists every regular file under dir, sorted by path.
func hashDir(dir string) ([]File, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	fsys := root.FS()
	var files []File
	err = fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("%s is not a regular file", path)
		}
		f, err := fsys.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		size, sum, err := digest(f, -1)
		files = append(files, File{Path: path, Size: size, SHA256: sum})
		return err
	})
	return files, err
}

// digest reads r, at most limit+1 bytes when limit is not negative, and
// returns the length read and its SHA-256.
func digest(r io.Reader, limit int64) (int64, string, error) {
	if limit >= 0 {
		r = io.LimitReader(r, limit+1)
	}
	h := sha256.New()
	n, err := io.Copy(h, r)
	return n, hex.EncodeToString(h.Sum(nil)), err
}

func verify(args []string, stdout io.Writer) (int, error) {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	manifestPath := flags.String("manifest", "", "manifest file")
	dir := flags.String("dir", "", "build directory to check instead of a URL")
	caFile := flags.String("cafile", "", "PEM file of a CA to trust besides the system's")
	if err := flags.Parse(args); err != nil {
		return 0, err
	}
	if *manifestPath == "" || (*dir == "") == (flags.NArg() != 1) {
		return 0, errors.New(usage)
	}
	raw, err := os.ReadFile(*manifestPath) // #nosec G304 -- a path the user names
	if err != nil {
		return 0, err
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return 0, fmt.Errorf("manifest: %w", err)
	}
	if m.Index == "" || len(m.Files) == 0 {
		return 0, errors.New("manifest lists no files")
	}
	r := report{out: stdout}
	if *dir != "" {
		err = r.checkDir(m, *dir)
	} else {
		var c *checker
		if c, err = newChecker(flags.Arg(0), *caFile); err == nil {
			err = r.checkSite(m, c)
		}
	}
	if err != nil {
		return 0, err
	}
	if r.differences > 0 {
		fmt.Fprintf(stdout, "%d difference(s) from the manifest\n", r.differences)
		return 1, nil
	}
	fmt.Fprintf(stdout, "all %d files match the manifest\n", len(m.Files))
	return 0, nil
}

type report struct {
	out         io.Writer
	differences int
}

func (r *report) line(status, path, detail string) {
	if status != "ok" {
		r.differences++
	}
	fmt.Fprintf(r.out, "%-8s %s  %s\n", status, path, detail)
}

// compare reports whether size and sum are the manifest's for f.
func (r *report) compare(f File, size int64, sum string) {
	if size == f.Size && sum == f.SHA256 {
		r.line("ok", f.Path, sum)
		return
	}
	r.line("changed", f.Path, fmt.Sprintf("want %d bytes %s, got %d bytes %s", f.Size, f.SHA256, size, sum))
}

func (r *report) checkDir(m Manifest, dir string) error {
	files, err := hashDir(dir)
	if err != nil {
		return err
	}
	found := map[string]File{}
	for _, f := range files {
		found[f.Path] = f
	}
	for _, want := range m.Files {
		got, ok := found[want.Path]
		delete(found, want.Path)
		if !ok {
			r.line("missing", want.Path, "")
			continue
		}
		r.compare(want, got.Size, got.SHA256)
	}
	for _, f := range files {
		if _, extra := found[f.Path]; extra {
			r.line("extra", f.Path, f.SHA256)
		}
	}
	return nil
}

type checker struct {
	base   *url.URL
	client *http.Client
}

func newChecker(base, caFile string) (*checker, error) {
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || strings.Trim(u.Path, "/") != "" {
		return nil, fmt.Errorf("%q is not an http or https origin", base)
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pool, err := x509.SystemCertPool()
		if err != nil {
			return nil, err
		}
		pem, err := os.ReadFile(caFile) // #nosec G304 -- a path the user names
		if err != nil {
			return nil, err
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s holds no certificate", caFile)
		}
		tlsConfig.RootCAs = pool
	}
	return &checker{
		base: &url.URL{Scheme: u.Scheme, Host: u.Host},
		client: &http.Client{
			Timeout:   time.Minute,
			Transport: &http.Transport{TLSClientConfig: tlsConfig, Proxy: http.ProxyFromEnvironment},
			// A redirect is itself a difference: the manifest's files are served in place.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func (r *report) checkSite(m Manifest, c *checker) error {
	paths := map[string]File{}
	var index File
	for _, f := range m.Files {
		if f.Path == m.Index {
			index = f
			continue
		}
		paths["/"+f.Path] = f
	}
	if index.Path == "" {
		return fmt.Errorf("manifest lists no %s", m.Index)
	}
	// The index is served at / and at the client's routes; its own name
	// redirects to /.
	for _, p := range []string{"/", clientRoute} {
		paths[p] = File{Path: p, Size: index.Size, SHA256: index.SHA256}
	}
	for _, p := range slices.Sorted(maps.Keys(paths)) {
		if err := r.checkURL(c, paths[p], p, m.CSP); err != nil {
			return err
		}
	}
	return nil
}

func (r *report) checkURL(c *checker, want File, path, csp string) error {
	u := *c.base
	u.Path = path
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		r.line("status", path, resp.Status)
		return nil
	}
	if got := resp.Header.Get("Content-Security-Policy"); got != csp {
		r.line("csp", path, fmt.Sprintf("got %q", got))
	}
	size, sum, err := digest(resp.Body, want.Size)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if size > want.Size {
		r.line("changed", path, fmt.Sprintf("want %d bytes, got more", want.Size))
		return nil
	}
	r.compare(File{Path: path, Size: want.Size, SHA256: want.SHA256}, size, sum)
	return nil
}
