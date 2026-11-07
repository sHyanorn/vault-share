package blob

import (
	"context"
	"errors"
	"os"
	"slices"
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
		PartSize:        5 << 20, // the S3 minimum, so multipart uploads stay small
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
	testStore(t, newS3(t), 11<<20)
}

func TestS3SweepAbortsOnlyOldUploadsOfIDs(t *testing.T) {
	s := newS3(t)
	ctx := context.Background()
	start := func(key string) string {
		up, err := s.client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{Bucket: &s.bucket, Key: &key})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, _ = s.client.AbortMultipartUpload(context.Background(), &s3.AbortMultipartUploadInput{
				Bucket: &s.bucket, Key: &key, UploadId: up.UploadId,
			})
		})
		return aws.ToString(up.UploadId)
	}
	pending := func() []string {
		out, err := s.client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{Bucket: &s.bucket})
		if err != nil {
			t.Fatal(err)
		}
		var ids []string
		for _, up := range out.Uploads {
			ids = append(ids, aws.ToString(up.UploadId))
		}
		return ids
	}

	fresh := start(newID())
	if err := s.Sweep(ctx, time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(pending(), fresh) {
		t.Error("a fresh upload was aborted")
	}

	foreign := start("other/" + newID())
	// A cutoff in the future makes every upload old.
	if err := s.Sweep(ctx, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	left := pending()
	if slices.Contains(left, fresh) {
		t.Error("an abandoned upload survived the sweep")
	}
	if !slices.Contains(left, foreign) {
		t.Error("an upload under a name vaultd never uses was aborted")
	}
}
