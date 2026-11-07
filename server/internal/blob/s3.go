package blob

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// MaxS3ObjectBytes is the largest object S3 accepts in one request, and so
// the largest blob the S3 store holds.
const MaxS3ObjectBytes = 5 << 30

// S3Config names a bucket on an S3-compatible service. The bucket belongs to
// vaultd alone.
type S3Config struct {
	// Endpoint is the service URL; empty means AWS. A custom endpoint is
	// addressed path-style, which every S3-compatible service accepts.
	Endpoint        string
	Region          string
	Bucket          string
	AccessKeyID     string
	SecretAccessKey string
}

// S3 stores each blob as an object named by its id. The body streams into a
// single request that S3 carries out only if no object of that name exists,
// so a reader never sees a partial object and an object is never replaced.
type S3 struct {
	client *s3.Client
	bucket string

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
	s := &S3{client: newS3Client(cfg), bucket: cfg.Bucket, open: map[string]*readers{}}
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

// Put streams r into one request, so an upload holds no more memory than the
// transport's buffers.
func (s *S3) Put(ctx context.Context, id string, size int64, r io.Reader) error {
	if !ValidID(id) {
		return ErrInvalidID
	}
	if size < 0 || size > MaxS3ObjectBytes {
		return ErrSize
	}
	body := &exactReader{ctx: ctx, r: r, left: size}
	defer body.stop()
	if size == 0 {
		// The SDK sends no body for an empty object, so nothing else reads r.
		if err := body.end(); err != nil {
			return err
		}
	}
	_, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        &s.bucket,
		Key:           &id,
		Body:          body,
		ContentLength: aws.Int64(size),
		ContentType:   aws.String("application/octet-stream"),
		IfNoneMatch:   aws.String("*"),
	}, streamed)
	// A 409 means a conflicting conditional request was in flight; it is
	// returned as is, because the body cannot be read again.
	var resp *smithyhttp.ResponseError
	switch {
	case errors.As(err, &resp) && resp.HTTPStatusCode() == http.StatusPreconditionFailed:
		return ErrExists
	case errors.Is(err, ErrSize):
		return ErrSize
	}
	return err
}

// streamed sends a body as it arrives. Its hash is only known at the end, so
// the payload goes unsigned: TLS or the local network carries it, and the
// browser's authenticated encryption detects any change. It cannot be read
// twice, so the request is never retried.
func streamed(o *s3.Options) {
	o.RetryMaxAttempts = 1
	o.APIOptions = append(o.APIOptions, v4.SwapComputePayloadSHA256ForUnsignedPayloadMiddleware)
}

var errStopped = errors.New("upload finished")

// exactReader passes on exactly the declared number of bytes of r. It holds
// back the last of them until r has ended and the request is still wanted,
// so a body that is too long or a cancelled upload fails before the request
// completes and S3 stores nothing. Once stopped it reads no more, so Put
// never touches the caller's reader after it returns.
type exactReader struct {
	mu      sync.Mutex
	ctx     context.Context
	r       io.Reader
	left    int64
	stopped bool
}

func (e *exactReader) Read(p []byte) (int, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	switch {
	case e.stopped:
		return 0, errStopped
	case e.left == 0:
		return 0, io.EOF
	}
	n, err := e.r.Read(p[:min(int64(len(p)), e.left)])
	e.left -= int64(n)
	switch {
	case err != nil && err != io.EOF:
		return 0, err
	case e.left > 0 && err == io.EOF:
		return 0, ErrSize
	case e.left > 0:
		return n, nil
	}
	if err == nil {
		if err := e.end(); err != nil {
			return 0, err
		}
	}
	if err := e.ctx.Err(); err != nil {
		return 0, err
	}
	return n, nil
}

// end checks that r has nothing beyond the declared size.
func (e *exactReader) end() error {
	var extra [1]byte
	n, err := io.ReadFull(e.r, extra[:])
	switch {
	case n > 0:
		return ErrSize
	case err == io.EOF:
		return nil
	}
	return err
}

// stop waits for a read in progress and makes every later one fail.
func (e *exactReader) stop() {
	e.mu.Lock()
	e.stopped = true
	e.mu.Unlock()
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

// Sweep has nothing to do: an upload that fails leaves nothing behind.
func (s *S3) Sweep(context.Context, time.Time) error {
	return nil
}
