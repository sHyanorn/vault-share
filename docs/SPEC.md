# vault-share Specification

## 1. Summary

A zero-knowledge, end-to-end encrypted file sharing service: files are encrypted in the browser before upload, the share link carries the key, and the server stores only ciphertext. Supports expiry, download limits and burn-after-reading.

## 2. Skills Demonstrated

| Skill | Where it shows |
|---|---|
| Applied cryptography | Chunked AES-GCM, HKDF key derivation, password protection, key delivery via URL fragment |
| Backend development | Go service, streaming upload and download, database, scheduled cleanup, Docker deployment |
| Security engineering | Threat model, security response headers, rate limiting, audit logging, dependency scanning |
| Security testing | Self-assessment against the OWASP Top 10 with a written report |

## 3. Scope

### Must have

- Anonymous upload: choose a file, encrypt it in the browser, upload the ciphertext, get a share link
- Share link format: `https://host/f/{fileId}#{key}`; the browser never sends the key after `#` to the server
- Set an expiry time (1 hour, 1 day, 7 days) and a maximum download count (1 to 100)
- Burn after reading: the ciphertext is deleted as soon as the download count is used up
- Optional password protection: the password derives a wrapping key in the browser, so the server never sees it either
- Delete token: the uploader receives a delete link to remove the file early
- File name and type are encrypted too; the server knows only the ciphertext size
- Scheduled background cleanup of expired files
- Per-file size limit of 1 GB (configurable); large files are processed as streamed chunks and never loaded into memory all at once

### Nice to have

- User accounts: Argon2id password hashing, HttpOnly session cookies, CSRF protection, TOTP two-factor authentication
- Logged-in users can view and manage their own uploads
- Share multiple files at once

### Out of scope

- File preview
- Native mobile apps

## 4. Encryption Scheme

Based on the public Firefox Send design. When implementing it, work through each step against that design and make sure it is understood.

### Upload

1. The browser generates a 16-byte random master key `secret`
2. HKDF-SHA256 derives three keys from `secret`:
   - `fileKey`: encrypts the file content
   - `metaKey`: encrypts metadata such as file name and type
   - `authKey`: proves possession of the link at download time (the server stores only its verifier)
3. The file is split into 64 KB chunks, each encrypted with AES-256-GCM; the nonce is a random base value combined with the chunk index; the last chunk carries an end marker to prevent truncation attacks
4. The metadata JSON is encrypted with `metaKey`
5. Upload the ciphertext, the encrypted metadata and the `authKey` verifier
6. The link is `/f/{id}#{base64url(secret)}`

### Password protection (optional)

- Argon2id (browser-side WebAssembly implementation) derives a wrapping key from the password and a random salt
- The wrapping key encrypts `secret`; the link no longer carries `secret` directly
- The recipient enters the password to recover `secret`

### Download

1. The browser reads `secret` from the URL fragment and derives the three keys
2. It signs a random challenge from the server with `authKey` to prove possession of the link
3. Once verification succeeds, the server streams the ciphertext and atomically decrements the download count
4. The browser decrypts while downloading and saves directly via the Streams API, without accumulating data in memory

### Known limitations (to be documented in the threat model and README)

- The web client's encryption code is served by the server; if the server is compromised, an attacker can serve malicious code. Mitigations: Subresource Integrity, strict CSP, reproducible builds, and candid documentation of the risk
- A leaked link means a leaked file; this is inherent to link-based sharing

## 5. Architecture

```
Browser (React)                  Server (Go)                                                 Storage
┌──────────────┐      HTTPS      ┌──────────────────────────────────────────────────────┐
│ crypto/      │────────────────▶│ Middleware: rate limiting, security headers, logging │
│  Web Crypto  │ ciphertext only │ Handlers: upload, download, delete                   │──▶ SQLite or PostgreSQL (metadata)
│  Streams API │◀────────────────│ Cleanup job (scheduled)                              │──▶ Local disk or S3-compatible storage (ciphertext)
└──────────────┘                 └──────────────────────────────────────────────────────┘
```

Server stack: Go standard library `net/http` with the `chi` router, `sqlc` or hand-written parameterized SQL, and `slog` structured logging. The storage layer is defined as an interface, implemented first for local disk and then for S3-compatible storage (tested with MinIO).

## 6. Data Model

```
files
  id               TEXT PRIMARY KEY  -- 128-bit random, base64url
  size_bytes       INTEGER
  meta_ciphertext  BLOB
  auth_verifier    BLOB
  owner_token_hash BLOB              -- hash of the delete token
  has_password     BOOLEAN
  password_salt    BLOB NULL
  downloads_left   INTEGER
  expires_at       TIMESTAMP
  created_at       TIMESTAMP

audit_log
  id, event_type, file_id, ip_hash, user_agent_hash, created_at
```

The audit log stores IPs only as salted hashes, balancing traceability and privacy.

## 7. API

| Method | Path | Description |
|---|---|---|
| POST | `/api/v1/files` | Create an upload; returns the id and upload URL |
| PUT | `/api/v1/files/{id}/content` | Stream the ciphertext upload |
| GET | `/api/v1/files/{id}/meta` | Return the encrypted metadata and an auth challenge |
| POST | `/api/v1/files/{id}/download` | Submit the challenge signature; returns a one-time download token |
| GET | `/api/v1/files/{id}/content?token=` | Stream the ciphertext download |
| DELETE | `/api/v1/files/{id}` | Delete using the delete token |
| GET | `/healthz` | Health check |

All errors use the format `{"error":{"code":"...","message":"..."}}`. Nonexistent files, expired files and wrong tokens all return the same 404, so file existence is not revealed.

## 8. Security Controls

- HTTPS (locally via Caddy automatic certificates or a self-signed certificate)
- Security response headers: strict CSP (no inline scripts), HSTS, X-Content-Type-Options, Referrer-Policy: no-referrer, Permissions-Policy
- Rate limiting: per-client token bucket (one IPv4 address or one IPv6 /64, D017), with separate limits for uploads and download authentication
- Lock a file for a period of time after repeated failed download authentication attempts
- Request body size limits and timeouts
- Total storage quota and a per-client daily storage budget
- File ids and tokens use cryptographically secure random numbers
- CI runs gosec, govulncheck, npm audit, Semgrep, and an OWASP ZAP baseline scan
- Containers run as a non-root user, with a read-only filesystem and a minimal image

## 9. Security Documentation (key deliverable)

- `docs/security/THREAT_MODEL.md`: STRIDE analysis listing assets, trust boundaries, threats, mitigations and residual risks
- `docs/security/TEST_REPORT.md`: item-by-item self-assessment against the latest OWASP Top 10, covering test method, results, screenshot evidence and remediation status
- `docs/security/FINDINGS.md`: issues found during development and how they were fixed
- `SECURITY.md`: how to report vulnerabilities

## 10. Testing Strategy

- Go unit and integration tests (including expiry, exhausted download counts, and race tests for concurrent download decrements)
- Frontend crypto module unit tests: encrypting then decrypting yields the original plaintext; tampering with any byte makes decryption fail; truncated ciphertext makes decryption fail
- End-to-end tests (Playwright): the full upload, share, download and burn-after-reading flow
- Known test vectors: verify HKDF and AES-GCM against standard test vectors

## 11. Deliverables

- One-command startup with Docker Compose
- Public demo site (with file size and retention limits)
- English README: summary, encryption flow diagram, demo GIF, threat model summary, known limitations
- All security documents listed in Section 9
