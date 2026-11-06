# Task List

## M0 Setup
- [x] Create `web/` with Vite (React + TypeScript); configure oxlint, Prettier, Vitest
- [x] Server directory layout: `internal/{api,store,blob,audit,config}`
- [x] Configuration loading (environment variables) and `.env.example`
- [x] Add frontend tests and dependency scanning to CI
- [x] Docker Compose: service plus Caddy reverse proxy (HTTPS)

## M1 Crypto Module (frontend; first and most important)
- [x] HKDF derivation of fileKey, metaKey, authKey
- [ ] Chunked AES-GCM encryption and decryption (Streams API)
- [ ] Nonce construction and end marker
- [ ] Metadata encryption
- [ ] Tests: round-trip correctness, tampering fails, truncation fails, reordering fails, standard test vectors
- [ ] Document the ciphertext format in DECISIONS.md

## M2 Backend Core
- [ ] Database tables and migrations
- [ ] Storage interface and local disk implementation
- [ ] Create-upload and streaming upload endpoints, with size limits
- [ ] Metadata, challenge, download token and streaming download endpoints
- [ ] Atomic download count decrement, with concurrency tests
- [ ] Delete token
- [ ] Expiry cleanup job

## M3 Frontend Pages
- [ ] Upload page: drag and drop, progress bar, expiry and download-count options, copy link
- [ ] Download page: read the key from the fragment, decryption progress, save file
- [ ] Error states: invalid link, expired, wrong password
- [ ] Clean, Apple-style UI

## M4 Security Hardening
- [ ] Security response headers and strict CSP
- [ ] Rate limiting middleware and lockout after failed authentication
- [ ] Audit logging
- [ ] Log redaction check
- [ ] Optional password protection (Argon2id WebAssembly)
- [ ] Add gosec, govulncheck, Semgrep and ZAP baseline scan to CI
- [ ] Update the status column of the threat model

## M5 Security Testing and Report
- [ ] Self-assess against each OWASP Top 10 item and write `docs/security/TEST_REPORT.md`
- [ ] Fix discovered issues and record them in FINDINGS.md
- [ ] Write SECURITY.md

## M6 Showcase and Deployment
- [ ] S3-compatible storage implementation (tested with MinIO)
- [ ] Playwright end-to-end tests
- [ ] Deploy a public demo site (with size and retention limits)
- [ ] English README: encryption flow diagram, GIF, threat model summary, known limitations

## Optional M7 User Accounts
- [ ] Sign-up and login, Argon2id, session cookies, CSRF
- [ ] TOTP two-factor authentication
- [ ] "My files" list
