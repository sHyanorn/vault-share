package api

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/sHyanorn/vault-share/server/internal/blob"
	"github.com/sHyanorn/vault-share/server/internal/store"
)

const (
	maxJSONBody  = 16 << 10
	maxMetaBytes = 4096
	minMetaBytes = 12 + 16 // IV and tag of an empty AES-GCM message
	// A ciphertext is at least the 21-byte header and a 17-byte empty last
	// record, see web/src/crypto/ece.ts.
	minCiphertextBytes = 38
	maxDownloads       = 100
	idBytes            = 16
	tokenBytes         = 32
	challengeTTL       = 2 * time.Minute
	downloadTokenTTL   = 5 * time.Minute
	// A transfer slower than this rate hits its deadline and is cut off.
	minTransferRate = 512 << 10 // bytes per second
	transferGrace   = time.Minute
)

var expiryOptions = map[int64]bool{3600: true, 86400: true, 604800: true}

var encoding = base64.RawURLEncoding.Strict()

type files struct {
	store        *store.Store
	blobs        blob.Store
	maxFileBytes int64
	now          func() time.Time
	sweep        func(context.Context) error
	log          *slog.Logger
}

type createRequest struct {
	Size         int64  `json:"size"`
	Meta         string `json:"meta"`
	AuthKey      string `json:"auth_key"`
	ExpiresIn    int64  `json:"expires_in"`
	MaxDownloads int64  `json:"max_downloads"`
}

type createResponse struct {
	ID         string `json:"id"`
	OwnerToken string `json:"owner_token"`
	UploadURL  string `json:"upload_url"`
	ExpiresAt  int64  `json:"expires_at"`
}

// create registers an upload: the ciphertext size, the encrypted metadata and
// the key that will verify download challenges. The owner token it returns
// authorizes the content upload and early deletion.
func (h *files) create(w http.ResponseWriter, r *http.Request) {
	var req createRequest
	if !h.decodeJSON(w, r, &req) {
		return
	}
	meta, err := encoding.DecodeString(req.Meta)
	switch {
	case err != nil || len(meta) < minMetaBytes || len(meta) > maxMetaBytes:
		writeError(w, http.StatusBadRequest, "invalid_request", "meta must be base64url of 28 to 4096 bytes")
		return
	case req.Size > h.maxFileBytes:
		writeError(w, http.StatusRequestEntityTooLarge, "too_large", "file exceeds the size limit")
		return
	case req.Size < minCiphertextBytes:
		writeError(w, http.StatusBadRequest, "invalid_request", "size is below the minimum ciphertext size")
		return
	case !expiryOptions[req.ExpiresIn]:
		writeError(w, http.StatusBadRequest, "invalid_request", "expires_in must be 3600, 86400 or 604800")
		return
	case req.MaxDownloads < 1 || req.MaxDownloads > maxDownloads:
		writeError(w, http.StatusBadRequest, "invalid_request", "max_downloads must be between 1 and 100")
		return
	}
	authKey, ok := decodeFixed(req.AuthKey, tokenBytes)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_request", "auth_key must be base64url of 32 bytes")
		return
	}

	now := h.now()
	id := encoding.EncodeToString(randomBytes(idBytes))
	owner := randomBytes(tokenBytes)
	f := store.File{
		ID:             id,
		SizeBytes:      req.Size,
		MetaCiphertext: meta,
		AuthKey:        authKey,
		OwnerTokenHash: hashToken(owner),
		DownloadsLeft:  req.MaxDownloads,
		ExpiresAt:      now.Add(time.Duration(req.ExpiresIn) * time.Second),
		CreatedAt:      now,
	}
	if err := h.store.CreateFile(r.Context(), f); err != nil {
		h.internalError(w, "create file", err)
		return
	}
	writeJSON(w, http.StatusCreated, createResponse{
		ID:         id,
		OwnerToken: encoding.EncodeToString(owner),
		UploadURL:  "/api/v1/files/" + id + "/content",
		ExpiresAt:  f.ExpiresAt.Unix(),
	})
}

// upload streams the ciphertext to blob storage. The body must be exactly the
// size declared at creation; anything else is discarded.
func (h *files) upload(w http.ResponseWriter, r *http.Request) {
	f, ok := h.ownerFile(w, r)
	if !ok {
		return
	}
	if f.Uploaded {
		writeError(w, http.StatusConflict, "conflict", "content already uploaded")
		return
	}
	if r.ContentLength >= 0 && r.ContentLength != f.SizeBytes {
		writeError(w, http.StatusBadRequest, "invalid_request", "body size differs from the declared size")
		return
	}
	ctx := r.Context()
	_ = http.NewResponseController(w).SetReadDeadline(h.now().Add(transferDeadline(f.SizeBytes)))
	n, err := h.blobs.Put(ctx, f.ID, http.MaxBytesReader(w, r.Body, f.SizeBytes))
	if err != nil || n != f.SizeBytes {
		if deleteErr := h.blobs.Delete(ctx, f.ID); deleteErr != nil {
			h.log.Error("discard partial upload", "err", deleteErr)
		}
		var tooLarge *http.MaxBytesError
		if err == nil || errors.As(err, &tooLarge) {
			writeError(w, http.StatusBadRequest, "invalid_request", "body size differs from the declared size")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid_request", "upload interrupted")
		return
	}
	marked, err := h.store.MarkUploaded(ctx, f.ID, h.now())
	if err != nil {
		h.internalError(w, "mark uploaded", err)
		return
	}
	if !marked {
		writeError(w, http.StatusConflict, "conflict", "content already uploaded")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type metaResponse struct {
	Meta          string `json:"meta"`
	Size          int64  `json:"size"`
	DownloadsLeft int64  `json:"downloads_left"`
	ExpiresAt     int64  `json:"expires_at"`
	Challenge     string `json:"challenge"`
}

// meta returns the encrypted metadata and a one-time challenge for download.
func (h *files) meta(w http.ResponseWriter, r *http.Request) {
	f, ok := h.liveFile(w, r)
	if !ok {
		return
	}
	nonce := randomBytes(tokenBytes)
	if err := h.store.CreateChallenge(r.Context(), f.ID, nonce, h.now().Add(challengeTTL)); err != nil {
		h.internalError(w, "create challenge", err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, metaResponse{
		Meta:          encoding.EncodeToString(f.MetaCiphertext),
		Size:          f.SizeBytes,
		DownloadsLeft: f.DownloadsLeft,
		ExpiresAt:     f.ExpiresAt.Unix(),
		Challenge:     encoding.EncodeToString(nonce),
	})
}

type downloadRequest struct {
	Challenge string `json:"challenge"`
	Signature string `json:"signature"`
}

type downloadResponse struct {
	Token         string `json:"token"`
	DownloadsLeft int64  `json:"downloads_left"`
}

// download verifies the signed challenge, takes one download from the count
// and issues a one-time token for the content. The count is taken here, not
// when the stream finishes, so an interrupted download cannot be repeated.
func (h *files) download(w http.ResponseWriter, r *http.Request) {
	f, ok := h.liveFile(w, r)
	if !ok {
		return
	}
	var req downloadRequest
	if !h.decodeJSON(w, r, &req) {
		return
	}
	nonce, okNonce := decodeFixed(req.Challenge, tokenBytes)
	signature, okSig := decodeFixed(req.Signature, sha256.Size)
	if !okNonce || !okSig {
		writeError(w, http.StatusBadRequest, "invalid_request", "challenge and signature must be base64url of 32 bytes")
		return
	}
	ctx := r.Context()
	now := h.now()
	valid, err := h.store.ConsumeChallenge(ctx, f.ID, nonce, now)
	if err != nil {
		h.internalError(w, "consume challenge", err)
		return
	}
	mac := hmac.New(sha256.New, f.AuthKey)
	mac.Write(nonce)
	if !valid || !hmac.Equal(mac.Sum(nil), signature) {
		notFound(w, r)
		return
	}
	left, granted, err := h.store.ConsumeDownload(ctx, f.ID, now)
	if err != nil {
		h.internalError(w, "consume download", err)
		return
	}
	if !granted {
		notFound(w, r)
		return
	}
	token := randomBytes(tokenBytes)
	if err := h.store.CreateDownloadToken(ctx, f.ID, hashToken(token), now.Add(downloadTokenTTL)); err != nil {
		h.internalError(w, "create download token", err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, downloadResponse{
		Token:         encoding.EncodeToString(token),
		DownloadsLeft: left,
	})
}

// content streams the ciphertext for a one-time download token. On the last
// permitted download the file is purged before the stream starts: the open
// descriptor keeps the bytes readable, and nothing is left for a retry.
func (h *files) content(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	token, ok := decodeFixed(r.URL.Query().Get("token"), tokenBytes)
	if !blob.ValidID(id) || !ok {
		notFound(w, r)
		return
	}
	ctx := r.Context()
	now := h.now()
	valid, err := h.store.ConsumeDownloadToken(ctx, id, hashToken(token), now)
	if err != nil {
		h.internalError(w, "consume download token", err)
		return
	}
	if !valid {
		notFound(w, r)
		return
	}
	f, err := h.store.GetFile(ctx, id)
	if err != nil {
		h.lookupError(w, r, "load file", err)
		return
	}
	rc, err := h.blobs.Open(ctx, id)
	if errors.Is(err, blob.ErrNotFound) {
		h.log.Warn("download token for missing content", "id", id)
		notFound(w, r)
		return
	}
	if err != nil {
		h.internalError(w, "open content", err)
		return
	}
	defer rc.Close()

	if f.DownloadsLeft == 0 {
		sweepCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		if err := h.sweep(sweepCtx); err != nil {
			h.log.Error("purge on last download", "err", err)
		}
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment")
	w.Header().Set("Content-Length", strconvInt(f.SizeBytes))
	w.Header().Set("Cache-Control", "no-store")
	_ = http.NewResponseController(w).SetWriteDeadline(now.Add(transferDeadline(f.SizeBytes)))
	if _, err := io.Copy(w, rc); err != nil {
		h.log.Debug("download interrupted", "id", id, "err", err)
	}
}

// remove deletes the file early with the owner token.
func (h *files) remove(w http.ResponseWriter, r *http.Request) {
	f, ok := h.ownerFile(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	if err := h.blobs.Delete(ctx, f.ID); err != nil {
		h.internalError(w, "delete content", err)
		return
	}
	if err := h.store.DeleteFile(ctx, f.ID); err != nil {
		h.internalError(w, "delete file", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// liveFile loads the file named in the path if it can be downloaded now.
func (h *files) liveFile(w http.ResponseWriter, r *http.Request) (store.File, bool) {
	id := chi.URLParam(r, "id")
	if !blob.ValidID(id) {
		notFound(w, r)
		return store.File{}, false
	}
	f, err := h.store.GetFile(r.Context(), id)
	if err != nil {
		h.lookupError(w, r, "load file", err)
		return store.File{}, false
	}
	if !f.Live(h.now()) {
		notFound(w, r)
		return store.File{}, false
	}
	return f, true
}

// ownerFile loads the unexpired file named in the path if the bearer token is
// its owner token. Every failure is a 404, so nothing reveals whether an id exists.
func (h *files) ownerFile(w http.ResponseWriter, r *http.Request) (store.File, bool) {
	id := chi.URLParam(r, "id")
	bearer, hasBearer := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	token, okToken := decodeFixed(bearer, tokenBytes)
	if !blob.ValidID(id) || !hasBearer || !okToken {
		notFound(w, r)
		return store.File{}, false
	}
	f, err := h.store.GetFile(r.Context(), id)
	if err != nil {
		h.lookupError(w, r, "load file", err)
		return store.File{}, false
	}
	if !hmac.Equal(hashToken(token), f.OwnerTokenHash) || !h.now().Before(f.ExpiresAt) {
		notFound(w, r)
		return store.File{}, false
	}
	return f, true
}

func (h *files) decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxJSONBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return false
	}
	return true
}

func (h *files) lookupError(w http.ResponseWriter, r *http.Request, what string, err error) {
	if errors.Is(err, store.ErrNotFound) {
		notFound(w, r)
		return
	}
	h.internalError(w, what, err)
}

func (h *files) internalError(w http.ResponseWriter, what string, err error) {
	h.log.Error(what, "err", err)
	writeError(w, http.StatusInternalServerError, "internal", "internal error")
}

func transferDeadline(size int64) time.Duration {
	return transferGrace + time.Duration(size/minTransferRate)*time.Second
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return b
}

func hashToken(token []byte) []byte {
	sum := sha256.Sum256(token)
	return sum[:]
}

func decodeFixed(s string, n int) ([]byte, bool) {
	b, err := encoding.DecodeString(s)
	return b, err == nil && len(b) == n
}
