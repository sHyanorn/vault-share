package blob

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
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
	c := newS3Client(S3Config{Endpoint: "http://" + ln.Addr().String(), Region: "us-east-1", AccessKeyID: "k", SecretAccessKey: "s"})
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
