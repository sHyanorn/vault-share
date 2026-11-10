package api

import (
	"net/http"
)

// My files (D030). The server keeps, for each file of an account, the entry
// the browser sealed under the account key (D026): only the browser can open
// it, and only it can then open the file's metadata.

const (
	minEntryBytes = 12 + 16 // IV and tag of an empty AES-GCM message
	maxEntryBytes = 1024
	// maxKeptFiles caps one listing; the newest come first.
	maxKeptFiles = 1000
)

type keepRequest struct {
	Entry string `json:"entry"`
}

// keepFile adds a file to the signed-in account. The owner token proves the
// file is the caller's, so no one can claim another's file or plant one.
func (h *files) keepFile(w http.ResponseWriter, r *http.Request) {
	f, ok := h.ownerFile(w, r)
	if !ok {
		return
	}
	var req keepRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	entry, err := encoding.DecodeString(req.Entry)
	if err != nil || len(entry) < minEntryBytes || len(entry) > maxEntryBytes {
		writeError(w, http.StatusBadRequest, "invalid_request", "entry must be base64url of 28 to 1024 bytes")
		return
	}
	ctx := r.Context()
	kept, err := h.store.KeepFile(ctx, f.ID, sessionFrom(ctx).user.ID, entry, h.now())
	if err != nil {
		internalError(w, h.log, "keep file", err)
		return
	}
	if !kept {
		notFound(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type keptFile struct {
	ID            string `json:"id"`
	Size          int64  `json:"size"`
	Meta          string `json:"meta"`
	Entry         string `json:"entry"`
	DownloadsLeft int64  `json:"downloads_left"`
	ExpiresAt     int64  `json:"expires_at"`
	CreatedAt     int64  `json:"created_at"`
	Uploaded      bool   `json:"uploaded"`
}

type keptFilesResponse struct {
	Files []keptFile `json:"files"`
	// More tells that older files exist beyond the listing.
	More bool `json:"more"`
}

// keptFiles lists the account's files that are still live or uploading.
func (h *files) keptFiles(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	kept, err := h.store.KeptFiles(ctx, sessionFrom(ctx).user.ID, h.now(), maxKeptFiles+1)
	if err != nil {
		internalError(w, h.log, "list files", err)
		return
	}
	resp := keptFilesResponse{Files: []keptFile{}, More: len(kept) > maxKeptFiles}
	for _, f := range kept[:min(len(kept), maxKeptFiles)] {
		resp.Files = append(resp.Files, keptFile{
			ID:            f.ID,
			Size:          f.SizeBytes,
			Meta:          encoding.EncodeToString(f.MetaCiphertext),
			Entry:         encoding.EncodeToString(f.Entry),
			DownloadsLeft: f.DownloadsLeft,
			ExpiresAt:     f.ExpiresAt.Unix(),
			CreatedAt:     f.CreatedAt.Unix(),
			Uploaded:      f.Uploaded,
		})
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, resp)
}
