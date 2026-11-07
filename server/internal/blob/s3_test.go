package blob

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// The S3 tests need an S3-compatible service, named by VAULT_TEST_S3_ENDPOINT,
// VAULT_TEST_S3_BUCKET, VAULT_TEST_S3_ACCESS_KEY_ID and
// VAULT_TEST_S3_SECRET_ACCESS_KEY; CI starts one. Without them they skip.
func newS3(t *testing.T) *S3 {
	t.Helper()
	endpoint := os.Getenv("VAULT_TEST_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("VAULT_TEST_S3_ENDPOINT is not set")
	}
	cfg := S3Config{
		Endpoint:        endpoint,
		Region:          "us-east-1",
		Bucket:          os.Getenv("VAULT_TEST_S3_BUCKET"),
		AccessKeyID:     os.Getenv("VAULT_TEST_S3_ACCESS_KEY_ID"),
		SecretAccessKey: os.Getenv("VAULT_TEST_S3_SECRET_ACCESS_KEY"),
		PathStyle:       true,
	}
	ctx := context.Background()
	_, err := newS3Client(cfg).CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &cfg.Bucket})
	var owned *types.BucketAlreadyOwnedByYou
	var exists *types.BucketAlreadyExists
	if err != nil && !errors.As(err, &owned) && !errors.As(err, &exists) {
		t.Fatalf("create bucket: %v", err)
	}
	s, err := NewS3(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestS3Contract(t *testing.T) {
	testStore(t, newS3(t))
}

func TestS3RequestsTimeOut(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// The service accepts every connection and never answers.
	var mu sync.Mutex
	var conns []net.Conn
	t.Cleanup(func() {
		ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range conns {
			conn.Close()
		}
	})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
		}
	}()
	defer func(saved time.Duration) { responseTimeout = saved }(responseTimeout)
	responseTimeout = 200 * time.Millisecond
	c := newS3Client(S3Config{Endpoint: "http://" + ln.Addr().String(), Region: "us-east-1", AccessKeyID: "k", SecretAccessKey: "s", PathStyle: true})
	// Only a backstop, so a missing timeout fails the test instead of hanging it.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	start := time.Now()
	_, err = c.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String("vault")},
		func(o *s3.Options) { o.RetryMaxAttempts = 1 })
	if elapsed := time.Since(start); err == nil || elapsed > 2*time.Second {
		t.Errorf("a silent service held the request for %v: %v", elapsed, err)
	}
}

// fakeS3 answers just enough of the S3 API for the checks of NewS3.
type fakeS3 struct {
	versioning  string // a versioning status, or "unsupported"
	conditional bool   // whether If-None-Match is honoured

	mu   sync.Mutex
	keys map[string]bool
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.Method == http.MethodGet && r.URL.Query().Has("versioning"):
		if f.versioning == "unsupported" {
			w.WriteHeader(http.StatusNotImplemented)
			io.WriteString(w, `<Error><Code>NotImplemented</Code><Message>not here</Message></Error>`)
			return
		}
		fmt.Fprintf(w, `<VersioningConfiguration><Status>%s</Status></VersioningConfiguration>`, f.versioning)
	case r.Method == http.MethodPut:
		io.Copy(io.Discard, r.Body)
		if f.conditional && f.keys[r.URL.Path] && r.Header.Get("If-None-Match") == "*" {
			w.WriteHeader(http.StatusPreconditionFailed)
			io.WriteString(w, `<Error><Code>PreconditionFailed</Code><Message>exists</Message></Error>`)
			return
		}
		f.keys[r.URL.Path] = true
		w.Header().Set("ETag", `"etag"`)
	case r.Method == http.MethodDelete:
		delete(f.keys, r.URL.Path)
		w.WriteHeader(http.StatusNoContent)
	}
}

func TestNewS3ChecksTheBucket(t *testing.T) {
	cases := []struct {
		versioning  string
		conditional bool
		refusal     string
	}{
		{"", true, ""},
		{"unsupported", true, ""},
		{"Enabled", true, "versioning is Enabled"},
		{"Suspended", true, "versioning is Suspended"},
		{"", false, "If-None-Match"},
	}
	for _, c := range cases {
		fake := &fakeS3{versioning: c.versioning, conditional: c.conditional, keys: map[string]bool{}}
		srv := httptest.NewServer(fake)
		_, err := NewS3(context.Background(), S3Config{Endpoint: srv.URL, Region: "us-east-1", Bucket: "vault", AccessKeyID: "k", SecretAccessKey: "s", PathStyle: true})
		srv.Close()
		switch {
		case c.refusal == "" && err != nil:
			t.Errorf("versioning %q, conditional %v: %v", c.versioning, c.conditional, err)
		case c.refusal != "" && (err == nil || !strings.Contains(err.Error(), c.refusal)):
			t.Errorf("versioning %q, conditional %v: want %q, got %v", c.versioning, c.conditional, c.refusal, err)
		case len(fake.keys) != 0:
			t.Errorf("versioning %q, conditional %v: probe left behind", c.versioning, c.conditional)
		}
	}
}

func TestS3MissingBucketIsAnError(t *testing.T) {
	s := newS3(t)
	gone := &S3{client: s.client, bucket: fmt.Sprintf("vault-missing-%x", randomBytes(6))}
	ctx := context.Background()
	if _, err := gone.Open(ctx, newID()); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("Open: %v", err)
	}
	if err := gone.Delete(ctx, newID()); err == nil {
		t.Error("Delete reported success")
	}
}
