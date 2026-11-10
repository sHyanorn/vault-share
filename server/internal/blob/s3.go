package blob

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"iter"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// MaxS3ObjectBytes is the largest object S3 accepts in one request, and so
// the largest blob the S3 store holds.
const MaxS3ObjectBytes = 5 << 30

// S3Config names a bucket on an S3-compatible service. The bucket belongs to
// vaultd alone.
type S3Config struct {
	// Endpoint is the service URL; empty means AWS.
	Endpoint        string
	Region          string
	Bucket          string
	AccessKeyID     string
	SecretAccessKey string
	// PathStyle names the bucket in the path, as most self-hosted services
	// need, instead of in the host name.
	PathStyle bool
}

// S3 stores each blob as an object named by its id. The body streams into a
// single request that S3 carries out only if no object of that name exists,
// so a reader never sees a partial object and an object is never replaced.
type S3 struct {
	client *s3.Client
	bucket string
}

// NewS3 connects to the bucket and checks what the store relies on: deleted
// objects leave no old versions, and no write replaces an existing object.
func NewS3(ctx context.Context, cfg S3Config) (*S3, error) {
	s := &S3{client: newS3Client(cfg, responseTimeout, writeTimeout), bucket: cfg.Bucket}
	if _, err := s.client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: &s.bucket}); err != nil {
		return nil, fmt.Errorf("bucket %s: %w", cfg.Bucket, err)
	}
	if err := s.checkVersioning(ctx); err != nil {
		return nil, fmt.Errorf("bucket %s: %w", cfg.Bucket, err)
	}
	if err := s.checkConditionalWrites(ctx); err != nil {
		return nil, fmt.Errorf("bucket %s: %w", cfg.Bucket, err)
	}
	return s, nil
}

// checkVersioning refuses a bucket that has ever kept versions, where a
// deleted file would stay readable as an old version.
func (s *S3) checkVersioning(ctx context.Context) error {
	out, err := s.client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: &s.bucket})
	var api smithy.APIError
	switch {
	case errors.As(err, &api) && api.ErrorCode() == "NotImplemented":
		return nil // a service without versioning at all
	case err != nil:
		return fmt.Errorf("versioning: %w", err)
	case out.Status != "":
		return fmt.Errorf("versioning is %s, so deleted files would stay as old versions", out.Status)
	}
	return nil
}

// checkConditionalWrites writes a probe twice: a service that ignores
// If-None-Match would let stored content be replaced. A probe that a failed
// delete leaves behind has no record, so cleanup removes it.
func (s *S3) checkConditionalWrites(ctx context.Context) error {
	b := make([]byte, 16)
	_, _ = rand.Read(b) // crypto/rand never fails on supported platforms
	id := base64.RawURLEncoding.EncodeToString(b)
	if err := s.Put(ctx, id, 1, strings.NewReader("1")); err != nil {
		return fmt.Errorf("probe write: %w", err)
	}
	defer func() { _ = s.Delete(ctx, id) }()
	switch err := s.Put(ctx, id, 1, strings.NewReader("2")); {
	case errors.Is(err, ErrExists):
		return nil
	case err == nil:
		return errors.New("the service replaced an object despite If-None-Match, so stored content could change")
	default:
		return fmt.Errorf("probe write: %w", err)
	}
}

// responseTimeout bounds the wait for a response once a request is sent, and
// writeTimeout each write to the service, so a service that stops reading an
// upload cannot hold it. Reads keep no deadline: a download waits on its
// client, and a client that goes away cancels the request.
const (
	responseTimeout = time.Minute
	writeTimeout    = time.Minute
)

type writeTimeoutConn struct {
	net.Conn
	timeout time.Duration
}

func (c writeTimeoutConn) Write(p []byte) (int, error) {
	if err := c.SetWriteDeadline(time.Now().Add(c.timeout)); err != nil {
		return 0, err
	}
	return c.Conn.Write(p)
}

func newS3Client(cfg S3Config, responseTimeout, writeTimeout time.Duration) *s3.Client {
	key, secret := cfg.AccessKeyID, cfg.SecretAccessKey
	opts := s3.Options{
		Region: cfg.Region,
		HTTPClient: awshttp.NewBuildableClient().WithTransportOptions(func(t *http.Transport) {
			t.ResponseHeaderTimeout = responseTimeout
			dial := t.DialContext
			t.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				conn, err := dial(ctx, network, addr)
				if err != nil {
					return nil, err
				}
				return writeTimeoutConn{conn, writeTimeout}, nil
			}
		}),
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
	}
	opts.UsePathStyle = cfg.PathStyle
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
	// The caller's ctx governs only the body, which body checks before its
	// last bytes go out. Past that point the service may store the object at
	// any moment, so a cancellation then would report failure for a stored
	// object; the request runs to its answer instead.
	_, err := s.client.PutObject(context.WithoutCancel(ctx), &s3.PutObjectInput{
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
	return out.Body, nil
}

// Delete removes the object at once. A download already streaming still
// gets every byte: S3 updates a key atomically, and the store contract
// checks it on each service tested.
func (s *S3) Delete(ctx context.Context, id string) error {
	if !ValidID(id) {
		return ErrInvalidID
	}
	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &s.bucket, Key: &id})
	// S3 answers success for a missing key, some compatible services 404.
	if notFound(err) {
		return nil
	}
	return err
}

// notFound reports a missing object. A missing bucket is an error: it means
// the configuration is wrong, not that the file is gone.
func notFound(err error) bool {
	var api smithy.APIError
	return errors.As(err, &api) && api.ErrorCode() == "NoSuchKey"
}

func (s *S3) IDs(ctx context.Context) iter.Seq2[string, error] {
	return func(yield func(string, error) bool) {
		pages := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{Bucket: &s.bucket})
		for pages.HasMorePages() {
			page, err := pages.NextPage(ctx)
			if err != nil {
				yield("", err)
				return
			}
			for _, obj := range page.Contents {
				if id := aws.ToString(obj.Key); ValidID(id) && !yield(id, nil) {
					return
				}
			}
		}
	}
}

// Check asks the service for the bucket, which also proves the credentials.
func (s *S3) Check(ctx context.Context) error {
	_, err := s.client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: &s.bucket})
	return err
}

// Sweep has nothing to do: an upload that fails leaves nothing behind.
func (s *S3) Sweep(context.Context, time.Time) error {
	return nil
}
