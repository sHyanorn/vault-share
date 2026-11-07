package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sHyanorn/vault-share/server/internal/audit"
	"github.com/sHyanorn/vault-share/server/internal/blob"
	"github.com/sHyanorn/vault-share/server/internal/cleanup"
	"github.com/sHyanorn/vault-share/server/internal/store"
)

const maxTestFileBytes = 1 << 20

type env struct {
	t     *testing.T
	srv   *httptest.Server
	store *store.Store
	blobs *blob.Disk
	job   *cleanup.Job
	mu    sync.Mutex
	now   time.Time
}

func newEnv(t *testing.T) *env {
	return newEnvWith(t, nil)
}

// newEnvWith builds the server; mutate adjusts the router options first.
func newEnvWith(t *testing.T, mutate func(*Options)) *env {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(context.Background(), filepath.Join(dir, "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	blobs, err := blob.NewDisk(filepath.Join(dir, "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, store: st, blobs: blobs, now: time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)}
	logger := slog.New(slog.DiscardHandler)
	auditor, err := audit.New(dir, st, logger)
	if err != nil {
		t.Fatal(err)
	}
	auditor.Now = e.clock
	e.job = &cleanup.Job{Store: st, Blobs: blobs, Audit: auditor, Log: logger, Now: e.clock}
	// Rate limits are exercised by their own test; elsewhere they stay out of the way.
	unlimited := Limits{General: Budget{1e9, 1e9}, Create: Budget{1e9, 1e9}, Download: Budget{1e9, 1e9}, Storage: Budget{1e12, 1 << 40}}
	opts := Options{Logger: logger, Store: st, Blobs: blobs, Audit: auditor, MaxFileBytes: maxTestFileBytes, Limits: &unlimited, Now: e.clock}
	if mutate != nil {
		mutate(&opts)
	}
	h, err := NewRouter(opts)
	if err != nil {
		t.Fatal(err)
	}
	e.srv = httptest.NewUnstartedServer(h)
	e.srv.Config.WriteTimeout = time.Second // the upload handler must outlive this
	e.srv.Start()
	t.Cleanup(e.srv.Close)
	return e
}

func (e *env) clock() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.now
}

func (e *env) advance(d time.Duration) {
	e.mu.Lock()
	e.now = e.now.Add(d)
	e.mu.Unlock()
}

// request sends body (JSON-encoded unless it is already []byte or a reader)
// and decodes a 2xx JSON response into out.
func (e *env) request(method, path string, body any, headers map[string]string, out any) (int, []byte) {
	e.t.Helper()
	var reader io.Reader
	switch b := body.(type) {
	case nil:
	case []byte:
		reader = bytes.NewReader(b)
	case io.Reader:
		reader = b
	default:
		data, err := json.Marshal(b)
		if err != nil {
			e.t.Fatal(err)
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, e.srv.URL+path, reader)
	if err != nil {
		e.t.Fatal(err)
	}
	for k, v := range headers {
		if k == "Host" {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if out != nil && resp.StatusCode < 300 {
		if err := json.Unmarshal(data, out); err != nil {
			e.t.Fatalf("decode %s %s: %v (%q)", method, path, err, data)
		}
	}
	return resp.StatusCode, data
}

type share struct {
	id, owner string
	authKey   []byte
	meta      []byte
	content   []byte
}

func randomContent(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func (e *env) create(size, maxDownloads int, expiresIn int64) share {
	e.t.Helper()
	sh := share{authKey: randomContent(32), meta: randomContent(64), content: randomContent(size)}
	var resp createResponse
	status, body := e.request(http.MethodPost, "/api/v1/files", createRequest{
		Size:         int64(size),
		Meta:         encoding.EncodeToString(sh.meta),
		AuthKey:      encoding.EncodeToString(sh.authKey),
		ExpiresIn:    expiresIn,
		MaxDownloads: int64(maxDownloads),
	}, nil, &resp)
	if status != http.StatusCreated {
		e.t.Fatalf("create: %d %s", status, body)
	}
	if resp.UploadURL != "/api/v1/files/"+resp.ID+"/content" || resp.ExpiresAt != e.clock().Unix()+expiresIn {
		e.t.Fatalf("create response %+v", resp)
	}
	sh.id, sh.owner = resp.ID, resp.OwnerToken
	return sh
}

func (e *env) upload(sh share, owner string, body any) int {
	e.t.Helper()
	status, _ := e.request(http.MethodPut, "/api/v1/files/"+sh.id+"/content", body,
		map[string]string{"Authorization": "Bearer " + owner}, nil)
	return status
}

func (e *env) shared(size, maxDownloads int, expiresIn int64) share {
	e.t.Helper()
	sh := e.create(size, maxDownloads, expiresIn)
	if status := e.upload(sh, sh.owner, sh.content); status != http.StatusNoContent {
		e.t.Fatalf("upload: %d", status)
	}
	return sh
}

func (e *env) meta(id string) (metaResponse, int) {
	e.t.Helper()
	var resp metaResponse
	status, _ := e.request(http.MethodGet, "/api/v1/files/"+id+"/meta", nil, nil, &resp)
	return resp, status
}

func sign(authKey []byte, challenge string) string {
	nonce, _ := encoding.DecodeString(challenge)
	mac := hmac.New(sha256.New, authKey)
	mac.Write(nonce)
	return encoding.EncodeToString(mac.Sum(nil))
}

func (e *env) download(id, challenge, signature string) (downloadResponse, int) {
	e.t.Helper()
	var resp downloadResponse
	status, _ := e.request(http.MethodPost, "/api/v1/files/"+id+"/download",
		downloadRequest{Challenge: challenge, Signature: signature}, nil, &resp)
	return resp, status
}

// token walks the challenge flow and returns a download token.
func (e *env) token(sh share) (downloadResponse, int) {
	e.t.Helper()
	m, status := e.meta(sh.id)
	if status != http.StatusOK {
		return downloadResponse{}, status
	}
	return e.download(sh.id, m.Challenge, sign(sh.authKey, m.Challenge))
}

func (e *env) content(id, token string) (int, []byte, http.Header) {
	e.t.Helper()
	resp, err := e.srv.Client().Get(e.srv.URL + "/api/v1/files/" + id + "/content?token=" + token)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data, resp.Header
}

func (e *env) remove(id, owner string) int {
	e.t.Helper()
	status, _ := e.request(http.MethodDelete, "/api/v1/files/"+id, nil,
		map[string]string{"Authorization": "Bearer " + owner}, nil)
	return status
}

func (e *env) blobExists(id string) bool {
	e.t.Helper()
	rc, err := e.blobs.Open(context.Background(), id)
	if errors.Is(err, blob.ErrNotFound) {
		return false
	}
	if err != nil {
		e.t.Fatal(err)
	}
	rc.Close()
	return true
}

func TestShareLifecycle(t *testing.T) {
	e := newEnv(t)
	sh := e.shared(1000, 2, 86400)

	m, status := e.meta(sh.id)
	if status != http.StatusOK || m.Size != 1000 || m.DownloadsLeft != 2 || m.Meta != encoding.EncodeToString(sh.meta) {
		t.Fatalf("meta: %d %+v", status, m)
	}
	dl, status := e.download(sh.id, m.Challenge, sign(sh.authKey, m.Challenge))
	if status != http.StatusOK || dl.DownloadsLeft != 1 || dl.Token == "" {
		t.Fatalf("download: %d %+v", status, dl)
	}
	status, body, headers := e.content(sh.id, dl.Token)
	if status != http.StatusOK || !bytes.Equal(body, sh.content) {
		t.Fatalf("content: %d, %d bytes", status, len(body))
	}
	for key, want := range map[string]string{
		"Content-Type": "application/octet-stream", "Content-Length": "1000",
		"Content-Disposition": "attachment", "Cache-Control": "no-store",
	} {
		if got := headers.Get(key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	if !e.blobExists(sh.id) {
		t.Fatal("content deleted while a download remained")
	}

	dl, status = e.token(sh)
	if status != http.StatusOK || dl.DownloadsLeft != 0 {
		t.Fatalf("second download: %d %+v", status, dl)
	}
	if _, status := e.meta(sh.id); status != http.StatusNotFound {
		t.Errorf("meta with no downloads left: %d", status)
	}
	if status, body, _ := e.content(sh.id, dl.Token); status != http.StatusOK || !bytes.Equal(body, sh.content) {
		t.Fatalf("last content: %d", status)
	}
	if e.blobExists(sh.id) {
		t.Error("content survived the last download")
	}
	if _, err := e.store.GetFile(context.Background(), sh.id); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("record survived the last download: %v", err)
	}
}

type chunkedBody struct{ io.Reader }

func TestUploadRules(t *testing.T) {
	e := newEnv(t)
	sh := e.create(1000, 1, 3600)

	if _, status := e.meta(sh.id); status != http.StatusNotFound {
		t.Errorf("meta before upload: %d", status)
	}
	other := e.create(1000, 1, 3600)
	for name, owner := range map[string]string{"other owner": other.owner, "garbage": "nope", "empty": ""} {
		if status := e.upload(sh, owner, sh.content); status != http.StatusNotFound {
			t.Errorf("%s: %d", name, status)
		}
	}
	cases := map[string]any{
		"short":         sh.content[:999],
		"long":          append(append([]byte{}, sh.content...), 1),
		"chunked short": chunkedBody{bytes.NewReader(sh.content[:999])},
		"chunked long":  chunkedBody{bytes.NewReader(append(append([]byte{}, sh.content...), 1))},
	}
	for name, body := range cases {
		if status := e.upload(sh, sh.owner, body); status != http.StatusBadRequest {
			t.Errorf("%s: %d", name, status)
		}
		if e.blobExists(sh.id) {
			t.Errorf("%s: partial content kept", name)
		}
	}
	if status := e.upload(sh, sh.owner, sh.content); status != http.StatusNoContent {
		t.Fatalf("upload: %d", status)
	}
	if status := e.upload(sh, sh.owner, sh.content); status != http.StatusConflict {
		t.Errorf("second upload: %d", status)
	}

	late := e.create(1000, 1, 3600)
	e.advance(2 * time.Hour)
	if status := e.upload(late, late.owner, late.content); status != http.StatusNotFound {
		t.Errorf("upload after expiry: %d", status)
	}
}

func TestCreateValidation(t *testing.T) {
	e := newEnv(t)
	valid := func() createRequest {
		return createRequest{Size: 1000, Meta: encoding.EncodeToString(randomContent(64)),
			AuthKey: encoding.EncodeToString(randomContent(32)), ExpiresIn: 3600, MaxDownloads: 1}
	}
	cases := []struct {
		name   string
		mutate func(*createRequest)
		status int
	}{
		{"expiry not offered", func(r *createRequest) { r.ExpiresIn = 7200 }, http.StatusBadRequest},
		{"zero downloads", func(r *createRequest) { r.MaxDownloads = 0 }, http.StatusBadRequest},
		{"too many downloads", func(r *createRequest) { r.MaxDownloads = 101 }, http.StatusBadRequest},
		{"size below minimum", func(r *createRequest) { r.Size = 37 }, http.StatusBadRequest},
		{"size above limit", func(r *createRequest) { r.Size = maxTestFileBytes + 1 }, http.StatusBadRequest},
		{"short auth key", func(r *createRequest) { r.AuthKey = encoding.EncodeToString(randomContent(31)) }, http.StatusBadRequest},
		{"standard base64", func(r *createRequest) { r.AuthKey = strings.ReplaceAll(r.AuthKey, "-", "+") + "==" }, http.StatusBadRequest},
		{"meta too short", func(r *createRequest) { r.Meta = encoding.EncodeToString(randomContent(27)) }, http.StatusBadRequest},
		{"meta too long", func(r *createRequest) { r.Meta = encoding.EncodeToString(randomContent(4097)) }, http.StatusBadRequest},
	}
	for _, tc := range cases {
		req := valid()
		tc.mutate(&req)
		if status, _ := e.request(http.MethodPost, "/api/v1/files", req, nil, nil); status != tc.status {
			t.Errorf("%s: %d, want %d", tc.name, status, tc.status)
		}
	}
	if status, _ := e.request(http.MethodPost, "/api/v1/files", []byte(`{"size":1000,"extra":1}`), nil, nil); status != http.StatusBadRequest {
		t.Errorf("unknown field: %d", status)
	}
	if status, _ := e.request(http.MethodPost, "/api/v1/files", []byte(`{"size":`), nil, nil); status != http.StatusBadRequest {
		t.Errorf("malformed JSON: %d", status)
	}
	if status, _ := e.request(http.MethodPost, "/api/v1/files", valid(), nil, nil); status != http.StatusCreated {
		t.Errorf("valid request: %d", status)
	}
}

func TestChallengeRules(t *testing.T) {
	e := newEnv(t)
	sh := e.shared(100, 10, 3600)
	other := e.shared(100, 10, 3600)

	m, _ := e.meta(sh.id)
	if _, status := e.download(sh.id, m.Challenge, sign(other.authKey, m.Challenge)); status != http.StatusNotFound {
		t.Errorf("wrong key: %d", status)
	}
	if _, status := e.download(other.id, m.Challenge, sign(other.authKey, m.Challenge)); status != http.StatusNotFound {
		t.Errorf("challenge of another file: %d", status)
	}
	tampered, _ := encoding.DecodeString(m.Challenge)
	tampered[20] ^= 1
	forged := encoding.EncodeToString(tampered)
	if _, status := e.download(sh.id, forged, sign(sh.authKey, forged)); status != http.StatusNotFound {
		t.Errorf("tampered challenge: %d", status)
	}
	dl, status := e.download(sh.id, m.Challenge, sign(sh.authKey, m.Challenge))
	if status != http.StatusOK || dl.DownloadsLeft != 9 {
		t.Errorf("valid challenge: %d %+v", status, dl)
	}
	// A replay only spends the holder's own download count.
	if dl, status := e.download(sh.id, m.Challenge, sign(sh.authKey, m.Challenge)); status != http.StatusOK || dl.DownloadsLeft != 8 {
		t.Errorf("replayed challenge: %d %+v", status, dl)
	}
	e.advance(3 * time.Minute)
	if _, status := e.download(sh.id, m.Challenge, sign(sh.authKey, m.Challenge)); status != http.StatusNotFound {
		t.Errorf("expired challenge: %d", status)
	}
	if _, status := e.download(sh.id, "short", sign(sh.authKey, m.Challenge)); status != http.StatusBadRequest {
		t.Errorf("malformed challenge: %d", status)
	}
	// A bad request body gets the same answer whether or not the file exists.
	missing := encoding.EncodeToString(randomContent(16))
	for _, id := range []string{missing, sh.id} {
		for name, body := range map[string]any{"malformed": []byte("{"), "empty fields": downloadRequest{}} {
			if status, _ := e.request(http.MethodPost, "/api/v1/files/"+id+"/download", body, nil, nil); status != http.StatusBadRequest {
				t.Errorf("%s body on %s: %d", name, id, status)
			}
		}
	}
}

func TestDownloadTokenRules(t *testing.T) {
	e := newEnv(t)
	sh := e.shared(100, 10, 3600)
	other := e.shared(100, 10, 3600)

	dl, status := e.token(sh)
	if status != http.StatusOK {
		t.Fatalf("token: %d", status)
	}
	if status, _, _ := e.content(other.id, dl.Token); status != http.StatusNotFound {
		t.Errorf("token on another file: %d", status)
	}
	if status, _, _ := e.content(sh.id, "garbage"); status != http.StatusNotFound {
		t.Errorf("garbage token: %d", status)
	}
	if status, _, _ := e.content(sh.id, dl.Token); status != http.StatusOK {
		t.Errorf("valid token: %d", status)
	}
	if status, _, _ := e.content(sh.id, dl.Token); status != http.StatusNotFound {
		t.Errorf("token reused: %d", status)
	}
	dl, _ = e.token(sh)
	e.advance(6 * time.Minute)
	if status, _, _ := e.content(sh.id, dl.Token); status != http.StatusNotFound {
		t.Errorf("expired token: %d", status)
	}
	dl, _ = e.token(sh)
	if status, _ := e.request(http.MethodHead, "/api/v1/files/"+sh.id+"/content?token="+dl.Token, nil, nil, nil); status != http.StatusMethodNotAllowed {
		t.Errorf("HEAD must not consume a token: %d", status)
	}
	if status, _, _ := e.content(sh.id, dl.Token); status != http.StatusOK {
		t.Errorf("token after HEAD: %d", status)
	}
}

type countingBlobs struct {
	blob.Store
	opens atomic.Int32
}

func (c *countingBlobs) Open(ctx context.Context, id string) (io.ReadCloser, error) {
	c.opens.Add(1)
	return c.Store.Open(ctx, id)
}

func TestInvalidTokensOpenNoContent(t *testing.T) {
	counting := &countingBlobs{}
	e := newEnvWith(t, func(o *Options) {
		counting.Store = o.Blobs
		o.Blobs = counting
	})
	sh := e.shared(100, 1, 3600)
	if status, _, _ := e.content(sh.id, encoding.EncodeToString(randomContent(tokenBytes))); status != http.StatusNotFound {
		t.Errorf("invalid token: %d", status)
	}
	if n := counting.opens.Load(); n != 0 {
		t.Errorf("an invalid token opened the content %d times", n)
	}
	dl, _ := e.token(sh)
	if status, body, _ := e.content(sh.id, dl.Token); status != http.StatusOK || !bytes.Equal(body, sh.content) {
		t.Errorf("valid token: %d", status)
	}
}

func TestExpiryAndCleanup(t *testing.T) {
	e := newEnv(t)
	sh := e.shared(100, 5, 3600)
	pending := e.create(100, 5, 3600)

	e.advance(61 * time.Minute)
	if _, status := e.meta(sh.id); status != http.StatusNotFound {
		t.Errorf("meta after expiry: %d", status)
	}
	if err := e.job.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e.blobExists(sh.id) {
		t.Error("expired content not purged")
	}
	for _, id := range []string{sh.id, pending.id} {
		if _, err := e.store.GetFile(context.Background(), id); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("%s not purged: %v", id, err)
		}
	}
}

func TestCleanupDeletesOrphanedContent(t *testing.T) {
	e := newEnv(t)
	sh := e.shared(100, 5, 86400)
	pending := e.create(100, 5, 86400)
	orphan := encoding.EncodeToString(randomContent(idBytes))
	ctx := context.Background()
	for _, id := range []string{orphan, pending.id} {
		if err := e.blobs.Put(ctx, id, 3, strings.NewReader("abc")); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.job.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if e.blobExists(orphan) {
		t.Error("content without a record survived cleanup")
	}
	// A record waiting for its upload marks the content as wanted.
	if !e.blobExists(sh.id) || !e.blobExists(pending.id) {
		t.Error("cleanup deleted content that has a record")
	}
	// The sweep lists the whole store, so it runs once an hour.
	late := encoding.EncodeToString(randomContent(idBytes))
	if err := e.blobs.Put(ctx, late, 3, strings.NewReader("abc")); err != nil {
		t.Fatal(err)
	}
	if err := e.job.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if !e.blobExists(late) {
		t.Error("a second sweep ran within the hour")
	}
	e.advance(61 * time.Minute)
	if err := e.job.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if e.blobExists(late) {
		t.Error("the hourly sweep left content without a record")
	}
}

func TestDelete(t *testing.T) {
	e := newEnv(t)
	sh := e.shared(100, 5, 3600)
	other := e.shared(100, 5, 3600)
	if status := e.remove(sh.id, other.owner); status != http.StatusNotFound {
		t.Errorf("wrong owner: %d", status)
	}
	if status := e.remove(sh.id, sh.owner); status != http.StatusNoContent {
		t.Errorf("delete: %d", status)
	}
	if _, status := e.meta(sh.id); status != http.StatusNotFound {
		t.Errorf("meta after delete: %d", status)
	}
	if e.blobExists(sh.id) {
		t.Error("content survived delete")
	}
	if status := e.remove(sh.id, sh.owner); status != http.StatusNotFound {
		t.Errorf("second delete: %d", status)
	}
	if _, status := e.meta(other.id); status != http.StatusOK {
		t.Errorf("other file affected: %d", status)
	}
}

func TestConcurrentDownloadsRespectTheLimit(t *testing.T) {
	e := newEnv(t)
	sh := e.shared(100, 3, 3600)

	const attempts = 40
	var wg sync.WaitGroup
	results := make(chan int, attempts)
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, status := e.token(sh)
			results <- status
		}()
	}
	wg.Wait()
	close(results)
	granted := 0
	for status := range results {
		switch status {
		case http.StatusOK:
			granted++
		case http.StatusNotFound:
		default:
			t.Errorf("unexpected status %d", status)
		}
	}
	if granted != 3 {
		t.Errorf("%d downloads granted, want 3", granted)
	}
}

func TestInvalidIDs(t *testing.T) {
	e := newEnv(t)
	for _, id := range []string{"not-an-id", "AAAAAAAAAAAAAAAAAAAAA", "AAAAAAAAAAAAAAAAAAAAAAA"} {
		if _, status := e.meta(id); status != http.StatusNotFound {
			t.Errorf("meta %q: %d", id, status)
		}
		if status := e.remove(id, encoding.EncodeToString(randomContent(32))); status != http.StatusNotFound {
			t.Errorf("delete %q: %d", id, status)
		}
	}
}

// pipeBody is a chunked request body the test feeds piece by piece.
func pipeBody(t *testing.T, e *env, sh share, owner string) (*io.PipeWriter, <-chan int) {
	t.Helper()
	pr, pw := io.Pipe()
	done := make(chan int, 1)
	go func() { done <- e.upload(sh, owner, chunkedBody{pr}) }()
	return pw, done
}

// heldBlobs holds the first Put until release is closed.
type heldBlobs struct {
	blob.Store
	once    sync.Once
	held    chan struct{}
	release chan struct{}
}

func (b *heldBlobs) Put(ctx context.Context, id string, size int64, r io.Reader) error {
	first := false
	b.once.Do(func() { first = true; close(b.held) })
	if first {
		<-b.release
	}
	return b.Store.Put(ctx, id, size, r)
}

func TestOneUploadAtATimePerFile(t *testing.T) {
	held := &heldBlobs{held: make(chan struct{}), release: make(chan struct{})}
	e := newEnvWith(t, func(o *Options) {
		held.Store = o.Blobs
		o.Blobs = held
	})
	sh := e.create(1000, 1, 3600)
	first := make(chan int, 1)
	go func() { first <- e.upload(sh, sh.owner, sh.content) }()
	<-held.held
	if status := e.upload(sh, sh.owner, randomContent(1000)); status != http.StatusConflict {
		t.Errorf("upload while another is in flight: %d", status)
	}
	close(held.release)
	if status := <-first; status != http.StatusNoContent {
		t.Fatalf("first upload: %d", status)
	}
	dl, _ := e.token(sh)
	if _, body, _ := e.content(sh.id, dl.Token); !bytes.Equal(body, sh.content) {
		t.Error("stored content is not the first upload")
	}
}

func TestNoDeleteDuringUpload(t *testing.T) {
	held := &heldBlobs{held: make(chan struct{}), release: make(chan struct{})}
	e := newEnvWith(t, func(o *Options) {
		held.Store = o.Blobs
		o.Blobs = held
	})
	sh := e.create(1000, 1, 3600)
	done := make(chan int, 1)
	go func() { done <- e.upload(sh, sh.owner, sh.content) }()
	<-held.held
	if status := e.remove(sh.id, sh.owner); status != http.StatusConflict {
		t.Errorf("delete during the upload: %d", status)
	}
	close(held.release)
	if status := <-done; status != http.StatusNoContent {
		t.Fatalf("upload: %d", status)
	}
	if status := e.remove(sh.id, sh.owner); status != http.StatusNoContent {
		t.Errorf("delete after the upload: %d", status)
	}
	if e.blobExists(sh.id) {
		t.Error("content survived the delete")
	}
}

func TestCleanupWaitsForARunningUpload(t *testing.T) {
	held := &heldBlobs{held: make(chan struct{}), release: make(chan struct{})}
	e := newEnvWith(t, func(o *Options) {
		held.Store = o.Blobs
		o.Blobs = held
	})
	sh := e.create(1000, 1, 86400)
	first := make(chan int, 1)
	go func() { first <- e.upload(sh, sh.owner, sh.content) }()
	<-held.held
	// Past the upload grace, but the upload still runs.
	e.advance(2 * time.Hour)
	if err := e.job.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	close(held.release)
	if status := <-first; status != http.StatusNoContent {
		t.Fatalf("upload: %d", status)
	}
	if _, status := e.meta(sh.id); status != http.StatusOK {
		t.Errorf("file purged during its upload: %d", status)
	}
}

func TestSlowUploadStillGetsItsResponse(t *testing.T) {
	e := newEnv(t)
	sh := e.create(1000, 1, 3600)
	pw, done := pipeBody(t, e, sh, sh.owner)
	if _, err := pw.Write(sh.content[:999]); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1500 * time.Millisecond) // past the server's WriteTimeout
	pw.Write(sh.content[999:])
	pw.Close()
	if status := <-done; status != http.StatusNoContent {
		t.Errorf("slow upload: %d", status)
	}
}

func TestGrantedDownloadSurvivesCleanup(t *testing.T) {
	e := newEnv(t)
	sh := e.shared(100, 2, 3600)
	first, _ := e.token(sh)
	second, _ := e.token(sh)
	if err := e.job.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if status, body, _ := e.content(sh.id, first.Token); status != http.StatusOK || !bytes.Equal(body, sh.content) {
		t.Errorf("first download after cleanup: %d", status)
	}
	if !e.blobExists(sh.id) {
		t.Fatal("content purged while a token was pending")
	}
	if status, body, _ := e.content(sh.id, second.Token); status != http.StatusOK || !bytes.Equal(body, sh.content) {
		t.Errorf("second download: %d", status)
	}
	if e.blobExists(sh.id) {
		t.Error("content survived the last download")
	}
}

type failingBlobs struct{ blob.Store }

func (failingBlobs) Put(context.Context, string, int64, io.Reader) error {
	return errors.New("disk full")
}

func TestStorageFailureIsNotTheClientsFault(t *testing.T) {
	var logs bytes.Buffer
	e := newEnvWith(t, func(o *Options) {
		o.Blobs = failingBlobs{o.Blobs}
		o.Logger = slog.New(slog.NewJSONHandler(&logs, nil))
	})
	sh := e.create(100, 1, 3600)
	if status := e.upload(sh, sh.owner, sh.content); status != http.StatusInternalServerError {
		t.Errorf("storage failure: %d", status)
	}
	if !strings.Contains(logs.String(), "disk full") {
		t.Errorf("storage failure not logged: %s", logs.String())
	}
}

func TestJSONBodiesAreBounded(t *testing.T) {
	e := newEnv(t)
	huge := []byte(`{"size":1000,"meta":"` + strings.Repeat("A", 20_000) + `"}`)
	if status, _ := e.request(http.MethodPost, "/api/v1/files", huge, nil, nil); status != http.StatusBadRequest {
		t.Errorf("oversized JSON: %d", status)
	}
}
