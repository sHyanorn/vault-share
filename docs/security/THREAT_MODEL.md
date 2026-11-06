# Threat Model

Method: STRIDE. It is revised with every feature change.

## 1. Assets

| Asset | Sensitivity |
|---|---|
| File plaintext and file names | Highest |
| Master key secret | Highest |
| Delete token | High |
| Ciphertext | Medium (unreadable without the key, but size and timing can be analyzed) |
| Audit log | Medium |

## 2. Trust Boundaries

1. Between the user's browser and the network
2. Between the network and the server
3. Between the server and storage
4. Frontend code delivery (the server serves JS to the browser)
5. Build and CI pipeline (GitHub Actions, npm and Go modules, container base images)

## 3. Attackers

- A1 Network eavesdropper
- A2 Ordinary external attacker holding information other than the share link
- A3 Attacker who has obtained the database and storage
- A4 Attacker in full control of the server
- A5 Malicious uploader (abuses the service to spread malicious files or exhaust resources)

## 4. Threats and Mitigations

| Category | Threat | Mitigation | Status |
|---|---|---|---|
| S Spoofing | Someone without the link tries to download | authKey challenge signature | Done (M2) |
| T Tampering | Modifying or reordering ciphertext chunks | AES-GCM authentication, chunk index in the nonce, end marker | Done (M1, tests for tampering, truncation, reordering, duplication) |
| T Tampering | Compromised dependency, action or base image injects code at build time | Exact versions, commit SHAs and image digests; Dependabot; npm audit, govulncheck, gosec and Semgrep in CI | Done (M4) |
| R Repudiation | Uploader denies having uploaded | Audit log (hashed IPs) | Done (M4: keyed hashes, 30-day retention, D018) |
| I Information disclosure | Key leaks via Referer or logs | Key only in the URL fragment; Referrer-Policy: no-referrer; log filtering | Done (M4: no-referrer header, a test drives the whole flow and checks every log line) |
| I Information disclosure | Probing file existence via 404 vs 403 responses | Always return 404 | Done (M2: every lookup, token and signature failure answers 404) |
| I Information disclosure | A3 reads the database | Only ciphertext and verifiers, no keys | Covered by design (the audit key sits in the same data directory, so A3 can also invert IPv4 audit hashes, D018) |
| D Denial of service | Mass uploads exhaust disk space | Size limits, rate limiting, expiry cleanup, total storage quota | Partial (M4: per-client rate limits on creation; no total quota yet, the disk is the limit) |
| D Denial of service | Metadata requests create server state | Challenges are stateless, see D014 | Done (M2) |
| D Denial of service | Password brute forcing | Browser-side Argon2id plus server-side lockout after failed authentication | Done (M4: Argon2id 64 MiB bounds offline guessing; the lockout bounds signature forgery, a guess never reaches the server, see D019) |
| E Elevation of privilege | Path traversal to read arbitrary files | Strict file id validation; storage paths never built from user input; static files served through `os.Root`, which refuses symlinks and dot segments that leave the web dir, with no directory listing | Done (M2: ids must be 22 base64url characters before any path is built) |
| E Elevation of privilege | XSS stealing the key from the page | Strict CSP, no inline scripts, React default escaping, no rendering of user HTML | Done (M4: CSP without unsafe-inline or unsafe-eval, D016) |

## 5. Residual Risks

- A4 can serve malicious frontend code to steal keys. This limitation is shared by all web-based encryption products and must be stated in the README
- File size and upload time are visible to the server
- Once a link leaks, anyone holding it can download the file; with a password the holder can still guess it offline at Argon2id cost per attempt
- Rate limits and lockouts count one IPv4 address or one IPv6 /64 as one client; an attacker holding many of those is bounded only by the per-file download count and the total disk. Clients behind one address share their limits
- The server is a single instance; its in-memory limiter state resets on restart
