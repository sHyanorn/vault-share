package blob

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// S3Config names a bucket on an S3-compatible service. The bucket belongs to
// vaultd alone: Sweep aborts any abandoned upload in it.
type S3Config struct {
	// Endpoint is the service URL; empty means AWS. A custom endpoint is
	// addressed path-style, which every S3-compatible service accepts.
	Endpoint        string
	Region          string
	Bucket          string
	AccessKeyID     string
	SecretAccessKey string
	// PartSize is the size of upload parts and the largest object sent in
	// one request; zero means 8 MiB. S3 needs at least 5 MiB.
	PartSize int64
}

const (
	defaultPartSize = 8 << 20
	maxParts        = 10_000
)

// S3 stores each blob as an object named by its id. An upload becomes visible
// only through its final request, which S3 carries out only if no object of
// that name exists, so a reader never sees a partial object and an object is
// never replaced.
type S3 struct {
	client *s3.Client
	bucket string
	part   int64

	mu sync.Mutex
	// open counts the readers of each object, so a Delete while one reads
	// waits for the last to close, as removing an open file does on disk.
	open map[string]*readers
}

type readers struct {
	n       int
	deleted bool
}

// NewS3 connects to the bucket and checks that it is reachable.
func NewS3(ctx context.Context, cfg S3Config) (*S3, error) {
	part := cfg.PartSize
	if part == 0 {
		part = defaultPartSize
	}
	s := &S3{client: newS3Client(cfg), bucket: cfg.Bucket, part: part, open: map[string]*readers{}}
	if _, err := s.client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: &s.bucket}); err != nil {
		return nil, fmt.Errorf("bucket %s: %w", cfg.Bucket, err)
	}
	return s, nil
}

func newS3Client(cfg S3Config) *s3.Client {
	key, secret := cfg.AccessKeyID, cfg.SecretAccessKey
	opts := s3.Options{
		Region: cfg.Region,
		Credentials: aws.NewCredentialsCache(aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: key, SecretAccessKey: secret, Source: "vaultd configuration"}, nil
		})),
		// Checksums only where S3 requires them; many compatible services
		// reject the newer default ones.
		RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired,
		ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired,
	}
	if cfg.Endpoint != "" {
		opts.BaseEndpoint = aws.String(cfg.Endpoint)
		opts.UsePathStyle = true
	}
	return s3.New(opts)
}

func (s *S3) Put(ctx context.Context, id string, size int64, r io.Reader) error {
	if !ValidID(id) {
		return ErrInvalidID
	}
	if size < 0 {
		return ErrSize
	}
	if size <= s.part {
		// One more byte than declared shows a body that is too long.
		buf := make([]byte, size+1)
		n, err := io.ReadFull(r, buf)
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			return err
		}
		if int64(n) != size {
			return ErrSize
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		_, err = s.client.PutObject(ctx, &s3.PutObjectInput{
			Bucket:        &s.bucket,
			Key:           &id,
			Body:          bytes.NewReader(buf[:n]),
			ContentLength: aws.Int64(size),
			ContentType:   aws.String("application/octet-stream"),
			IfNoneMatch:   aws.String("*"),
		})
		return putError(err)
	}
	return s.putParts(ctx, id, size, r)
}

// putParts uploads a large body in parts and publishes it only once every
// byte has arrived and the count matches; otherwise the upload is aborted.
func (s *S3) putParts(ctx context.Context, id string, size int64, r io.Reader) (err error) {
	up, err := s.client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket:      &s.bucket,
		Key:         &id,
		ContentType: aws.String("application/octet-stream"),
	})
	if err != nil {
		return err
	}
	defer func() {
		if err == nil {
			return
		}
		// The request's own context may be what ended the upload.
		actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		_, _ = s.client.AbortMultipartUpload(actx, &s3.AbortMultipartUploadInput{
			Bucket: &s.bucket, Key: &id, UploadId: up.UploadId,
		})
	}()

	part := max(s.part, (size+maxParts-1)/maxParts)
	buf := make([]byte, part)
	var parts []types.CompletedPart
	var total int64
	for number := int32(1); ; number++ {
		n, rerr := io.ReadFull(r, buf)
		if n > 0 {
			if total += int64(n); total > size {
				return ErrSize
			}
			out, err := s.client.UploadPart(ctx, &s3.UploadPartInput{
				Bucket:        &s.bucket,
				Key:           &id,
				UploadId:      up.UploadId,
				PartNumber:    aws.Int32(number),
				Body:          bytes.NewReader(buf[:n]),
				ContentLength: aws.Int64(int64(n)),
			})
			if err != nil {
				return err
			}
			parts = append(parts, types.CompletedPart{ETag: out.ETag, PartNumber: aws.Int32(number)})
		}
		if errors.Is(rerr, io.EOF) || errors.Is(rerr, io.ErrUnexpectedEOF) {
			break
		}
		if rerr != nil {
			return rerr
		}
	}
	if total != size {
		return ErrSize
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	_, err = s.client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket:          &s.bucket,
		Key:             &id,
		UploadId:        up.UploadId,
		MultipartUpload: &types.CompletedMultipartUpload{Parts: parts},
		IfNoneMatch:     aws.String("*"),
	})
	return putError(err)
}

// putError maps a refused conditional write to ErrExists. A 409 means a
// conflicting request was in flight; it is returned as is, because the upload
// has to start over and its body cannot be read again.
func putError(err error) error {
	var resp *smithyhttp.ResponseError
	if errors.As(err, &resp) && resp.HTTPStatusCode() == http.StatusPreconditionFailed {
		return ErrExists
	}
	return err
}

func (s *S3) Open(ctx context.Context, id string) (io.ReadCloser, error) {
	if !ValidID(id) {
		return nil, ErrInvalidID
	}
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &s.bucket, Key: &id})
	if notFound(err) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	st := s.open[id]
	if st == nil {
		st = &readers{}
		s.open[id] = st
	}
	st.n++
	s.mu.Unlock()
	return &s3Reader{ReadCloser: out.Body, store: s, id: id}, nil
}

type s3Reader struct {
	io.ReadCloser
	store *S3
	id    string
	once  sync.Once
}

func (r *s3Reader) Close() error {
	err := r.ReadCloser.Close()
	r.once.Do(func() { r.store.release(r.id) })
	return err
}

// release drops one reader and carries out a Delete that waited for it.
func (s *S3) release(id string) {
	s.mu.Lock()
	st := s.open[id]
	st.n--
	remove := st.n == 0 && st.deleted
	if st.n == 0 {
		delete(s.open, id)
	}
	s.mu.Unlock()
	if remove {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = s.deleteObject(ctx, id)
	}
}

// Delete removes the object. While it is open for reading, the last reader
// to close removes it instead.
func (s *S3) Delete(ctx context.Context, id string) error {
	if !ValidID(id) {
		return ErrInvalidID
	}
	s.mu.Lock()
	if st := s.open[id]; st != nil {
		st.deleted = true
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()
	return s.deleteObject(ctx, id)
}

// deleteObject treats a missing object as deleted; S3 itself does, some
// compatible services answer 404.
func (s *S3) deleteObject(ctx context.Context, id string) error {
	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &s.bucket, Key: &id})
	if notFound(err) {
		return nil
	}
	return err
}

func notFound(err error) bool {
	var missing *types.NoSuchKey
	var resp *smithyhttp.ResponseError
	return errors.As(err, &missing) || errors.As(err, &resp) && resp.HTTPStatusCode() == http.StatusNotFound
}

// Sweep aborts multipart uploads started before the given time, which a
// crash or a lost connection left behind.
func (s *S3) Sweep(ctx context.Context, before time.Time) error {
	pages := s3.NewListMultipartUploadsPaginator(s.client, &s3.ListMultipartUploadsInput{Bucket: &s.bucket})
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, up := range page.Uploads {
			if !ValidID(aws.ToString(up.Key)) || up.Initiated == nil || !up.Initiated.Before(before) {
				continue
			}
			_, err := s.client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
				Bucket: &s.bucket, Key: up.Key, UploadId: up.UploadId,
			})
			var gone *types.NoSuchUpload
			if err != nil && !errors.As(err, &gone) {
				return fmt.Errorf("abort upload of %s: %w", aws.ToString(up.Key), err)
			}
		}
	}
	return nil
}
