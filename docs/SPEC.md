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
- Per-file size limit of 1 GiB (configurable); large files are processed as streamed chunks and never loaded into memory all at once

### Nice to have

- User accounts (M7): Argon2id password hashing, HttpOnly session cookies, CSRF protection, TOTP two-factor authentication
- Logged-in users can view and manage their own uploads (M7, "My files")
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
   - `authKey`: proves possession of the link at download time; the server keeps it to verify signatures, and it decrypts nothing
3. The file is encrypted with AES-256-GCM in 64 KiB records (65,536 bytes of ciphertext, 65,519 bytes of file data each); the nonce is a random base value combined with the record index; the last record carries an end marker to prevent truncation attacks
4. The metadata JSON is encrypted with `metaKey`
5. Upload the ciphertext, the encrypted metadata and the `authKey`
6. The link is `/f/{id}#{base64url(secret)}`

### Password protection (optional)

- Argon2id (browser-side WebAssembly implementation) derives a wrapping key from the password and a random salt
- The wrapping key encrypts `secret`; the link no longer carries `secret` directly
- The recipient enters the password to recover `secret`

### Download

1. The browser reads `secret` from the URL fragment and derives the three keys
2. It signs a random challenge from the server with `authKey` to prove possession of the link
3. Once verification succeeds, the server takes one download from the count and issues a one-time download token, in one transaction (D014); the token then fetches the ciphertext
4. The browser decrypts while downloading. Chromium-based browsers write straight to the file the user picks (File System Access API); other browsers collect the decrypted file in a Blob, which the browser holds until it is saved

### Parameters

The exact formats are in D012 and D019.

- Keys: `HKDF-SHA256(secret, salt = "", info, 32 bytes)` with info `vault-share/file`, `vault-share/meta` and `vault-share/auth`
- Content: the record format of RFC 8188 with a 256-bit key. Header `salt(16) | rs(4, always 65536) | idlen(1, always 0)`; each record is AES-256-GCM over `data | delimiter | padding`, the delimiter `0x01`, or `0x02` in the last record
- Nonces: per file, a content key and a 12-byte nonce base come from HKDF over `fileKey` and the random header salt; record `i` uses the nonce base XOR `i`, so no nonce repeats under a key
- Metadata: `iv(12) | AES-256-GCM(JSON {name, type, size})` under `metaKey`, with a random IV
- Password: the link carries `salt(16) | iv(12) | AES-256-GCM(secret)`, 60 bytes, in place of `secret`; the key is `Argon2id(password, salt, 64 MiB, 2 passes, 1 lane, 32 bytes)`, the IV is random, and there is no associated data

### Accounts (optional, D026)

1. The browser derives `master = Argon2id(password, salt)` with a random salt per account, then with HKDF-SHA256 the `authSecret` it sends at sign-in and the `wrappingKey` it keeps
2. A random 256-bit account key, sealed with AES-256-GCM under `wrappingKey`, is stored on the server; the server stores only an Argon2id hash of `authSecret` besides it, so neither the password nor anything that opens the account key reaches it
3. For each file shared while signed in, the browser seals an entry under the account key, bound to the file id: the share secret, the link key and the delete token. "My files" lists the entries and their encrypted metadata; only the browser opens them
4. Between page loads the browser keeps the account key sealed under a device key that the server derives from the session token, so it opens only while the session lasts
5. Optional TOTP (RFC 6238) adds a second step at sign-in, with recovery codes (D029)

### Known limitations (to be documented in the threat model and README)

- The web client's encryption code is served by the server; if the server is compromised, an attacker can serve malicious code. Mitigations: a strict CSP and candid documentation of the risk. Dependencies and images are pinned, but builds are not verified to be reproducible and no hashes of the client are published, so a user cannot check the code a server sent. Subresource Integrity does not help, because the same server serves the page that carries the hashes (D023)
- A leaked link means a leaked file; this is inherent to link-based sharing
- There is no password reset: the server cannot open an account key, so a forgotten password loses the account; shared links keep working

## 5. Architecture

```
Browser (React)                  Server (Go)                                                 Storage
┌──────────────┐      HTTPS      ┌──────────────────────────────────────────────────────┐
│ crypto/      │────────────────▶│ Middleware: rate limiting, security headers, logging │
│  Web Crypto  │ ciphertext only │ Handlers: upload, download, delete, accounts         │──▶ SQLite (metadata)
│  Streams API │◀────────────────│ Cleanup job (scheduled)                              │──▶ Local disk or S3-compatible storage (ciphertext)
└──────────────┘                 └──────────────────────────────────────────────────────┘
```

Server stack: Go standard library `net/http` with the `chi` router, hand-written parameterized SQL, and `slog` structured logging. The storage layer is defined as an interface, implemented for local disk and for S3-compatible storage (tested with Versity S3 Gateway, D025). The bucket must belong to vaultd alone, keep no old versions and honour conditional writes; vaultd checks the last two at startup, and files on S3 are capped at 5 GiB.

## 6. Data Model

```
files
  id               TEXT PRIMARY KEY  -- 128-bit random, base64url
  size_bytes       INTEGER
  meta_ciphertext  BLOB
  auth_key         BLOB              -- HMAC key that verifies download signatures
  owner_token_hash BLOB              -- SHA-256 of the delete token
  downloads_left   INTEGER
  expires_at       INTEGER           -- Unix seconds, like every time column
  created_at       INTEGER
  uploaded_at      INTEGER NULL      -- set once the ciphertext is stored
  charge           INTEGER           -- bytes counted against the storage quota
  user_id          INTEGER NULL      -- the account that keeps the file (D030)
  entry            BLOB NULL         -- sealed by the browser under the account key

usage                                -- one row, kept by triggers on files
  id, charged                        -- the sum of files.charge, checked against the quota

download_tokens
  token_hash, file_id, expires_at

users                                -- D026, D027, D029
  id, username UNIQUE
  salt                               -- the browser's Argon2id salt
  auth_hash                          -- Argon2id of the auth secret, PHC string
  sealed_key                         -- the account key under the password
  totp_secret, totp_pending          -- sealed under a server key; NULL when off
  totp_step, totp_failures, created_at

account_ids                          -- one row: the next account id, above every id used before (D037)
  id, next

sessions
  token_hash, user_id, created_at, seen_at

login_tickets                        -- a right password waiting for its code
  token_hash, user_id, expires_at, attempts

recovery_codes
  user_id, code_hash

audit_log
  id, event, file_id, user_id, ip_hash, ua_hash, created_at
```

The server never sees a file's password (D019); the threat model lists how it can still tell that one exists. The audit log stores the client address and user agent only as keyed hashes, balancing traceability and privacy (D018). Tokens, tickets and recovery codes are kept as SHA-256 hashes; the account password never reaches the server (D026).

## 7. API

| Method | Path | Description |
|---|---|---|
| POST | `/api/v1/files` | Create an upload; returns the id and upload URL |
| PUT | `/api/v1/files/{id}/content` | Stream the ciphertext upload |
| GET | `/api/v1/files/{id}/meta` | Return the encrypted metadata and an auth challenge |
| POST | `/api/v1/files/{id}/download` | Submit the challenge signature; returns a one-time download token |
| GET | `/api/v1/files/{id}/content?token=` | Stream the ciphertext download |
| DELETE | `/api/v1/files/{id}` | Delete using the delete token |
| POST | `/api/v1/account` | Sign up with a username, the browser's salt, the auth secret and the sealed account key; starts a session |
| POST | `/api/v1/account/salt` | The salt to derive with; a username without an account gets a stable one of its own |
| POST | `/api/v1/session` | Sign in; returns a session, or a ticket when the account has a second step |
| POST | `/api/v1/session/totp` | Complete a sign-in with a TOTP or recovery code |
| GET | `/api/v1/session` | The signed-in account and the device key |
| DELETE | `/api/v1/session` | Sign out |
| POST | `/api/v1/account/password` | Change the password, which ends every other session |
| DELETE | `/api/v1/account` | Delete the account and the files it keeps |
| POST | `/api/v1/account/totp/setup` | Draw a TOTP secret for an authenticator app |
| POST, DELETE | `/api/v1/account/totp` | Turn two-factor sign-in on or off |
| GET | `/api/v1/account/files` | List the account's files with their sealed entries |
| PUT | `/api/v1/account/files/{id}` | Keep a file in the account, with the session and its delete token |
| GET | `/healthz` | Health check: 200 while the database, the blob store and the free space on the data volume pass, 503 otherwise (D033) |

All errors use the format `{"error":{"code":"...","message":"..."}}`. Nonexistent files, expired files and wrong tokens all return the same 404, so file existence is not revealed.

## 8. Security Controls

- HTTPS (locally via Caddy automatic certificates or a self-signed certificate)
- Security response headers: strict CSP (no inline scripts), HSTS, X-Content-Type-Options, Referrer-Policy: no-referrer, Permissions-Policy
- Rate limiting: per-client token bucket (one IPv4 address or one IPv6 /64, D017), with separate limits for uploads and download authentication
- Lock a file for a period of time after repeated failed download authentication attempts
- Requests from other sites are refused, and the API answers only for its own host (D022); session cookies are `__Host-`, HttpOnly and SameSite=Strict (D027, D028)
- Sessions end after an hour without use or a day after sign-in; sign-in failures are counted per client, per account and per known browser (D027); second steps have their own lockout and cannot be replayed (D029)
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
- End-to-end tests (Playwright): the full upload, share, download and burn-after-reading flow, and an account from sign-up through two-factor sign-in to deletion
- Known test vectors for the account key derivation, computed with two independent implementations (D026), and the RFC 4226 and RFC 6238 vectors for TOTP
- Known test vectors: verify HKDF and AES-GCM against standard test vectors

## 11. Deliverables

- One-command startup with Docker Compose
- English README: summary, encryption flow diagram, demo GIF, threat model summary, known limitations
- All security documents listed in Section 9
