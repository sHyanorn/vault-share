package blob

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"

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
