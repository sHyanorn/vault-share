# Threat Model (Draft)

Method: STRIDE. This file is a starting point; Claude Code and Aaron update it together at the end of each milestone.

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
| I Information disclosure | A3 reads the database and the storage, disk or S3 bucket | Ciphertext, token hashes and auth keys; nothing that decrypts | Covered by design (the auth keys pass the download check, so A3 can fetch ciphertext and spend download counts, F20; the audit key sits in the same data directory, so A3 can also invert IPv4 audit hashes, D018) |
| D Denial of service | Mass uploads exhaust disk space | Size limits, rate limiting, expiry cleanup, total storage quota | Done (M4, F17: quota with per-record overhead, per-client daily storage budget, D021) |
| D Denial of service | Metadata requests create server state | Challenges are stateless, see D014 | Done (M2) |
| D Denial of service | Failures from many addresses fill the audit log | Process-wide budget for failure events, 1,000,000-row cap (D018) | Done (M4, F16) |
| S Spoofing | A client names itself in X-Forwarded-For behind a proxy that appends a header line | Only the last entry of the last line counts (D017) | Done (M4, F15) |
| S Spoofing | A page on another site makes its visitors' browsers create files, each visitor counting as a separate client, or drain their budget with reads | Requests marked cross-site or same-site refused for every method, cross-origin writes also judged by Origin (D022) | Done (M5, F18, F24) |
| S Spoofing | A page rebinds its own name to a directly reachable vaultd and acts as same-origin | The API answers only for the host of `VAULT_BASE_URL` (D022) | Done (M5, F25) |
| T Tampering | A link to the content URL spends a download | The URL carries a one-time 256-bit token that only the downloading browser holds | Covered by design |
| D Denial of service | Slow clients hold connections open | Header timeout of 10 s and idle timeout of 2 minutes at Caddy, on both ports, and at vaultd; uploads and downloads get a deadline from their size | Done (M5, F19, F23) |
| D Denial of service | Password brute forcing | Browser-side Argon2id plus server-side lockout after failed authentication | Done (M4: Argon2id 64 MiB bounds offline guessing; the lockout bounds signature forgery, a guess never reaches the server, see D019; M5: passwords need 8 characters, F21) |
| D Denial of service | Many uploads at once, or deletes during uploads, fill vaultd's memory or the disk beyond the quota | One upload at a time per file, and no delete or purge while it runs, so the bytes in flight stay within the quota; S3 uploads stream without buffering (D025) | Done (M6, F26, F33) |
| I Information disclosure | Burned, expired or deleted ciphertext stays in the bucket after a failed delete, a crash or under versioning | Deletes at once and reports errors; cleanup deletes content without a record; a versioned bucket is refused at startup | Done (M6, F27, F29, F31) |
| T Tampering | An S3-compatible service ignores If-None-Match and lets stored content be replaced | One upload at a time per file; a startup probe refuses such a service | Done (M6, F30) |
| D Denial of service | A stalled S3 service holds requests and stops the cleanup job | One-minute timeouts on responses and on each write; each cleanup run has a deadline | Done (M6, F28, F35) |
| D Denial of service | Made-up download tokens make vaultd send requests to S3 | The token is checked before the object is opened | Done (M6, F32) |
| T Tampering | A1 between vaultd and the S3 service reads or alters ciphertext | https except to this machine or a single-label host; the browser's authenticated encryption detects any change to the unsigned payload | Covered by design |
| E Elevation of privilege | Path traversal to read arbitrary files | Strict file id validation; storage paths never built from user input; static files served through `os.Root`, which refuses symlinks and dot segments that leave the web dir, with no directory listing | Done (M2: ids must be 22 base64url characters before any path is built) |
| E Elevation of privilege | XSS stealing the key from the page | Strict CSP, no inline scripts, React default escaping, no rendering of user HTML | Done (M4: CSP without unsafe-inline or unsafe-eval, D016) |

## 5. Residual Risks

- A4 can serve malicious frontend code to steal keys. This limitation is shared by all web-based encryption products and must be stated in the README
- File size and upload time are visible to the server
- Once a link leaks, anyone holding it can download the file; with a password the holder can still guess it offline at Argon2id cost per attempt
- A copy of the database lets its holder fetch every live ciphertext and spend its download count through the API, without being able to decrypt (F20)
- A power loss can roll back the newest download decrement and so grant one extra download (D005)
- Rate limits and lockouts count one IPv4 address or one IPv6 /64 as one client; an attacker holding many of those is bounded only by the per-file download count and the total disk. Clients behind one address share their limits
- The server is a single instance; its in-memory limiter state resets on restart
- The S3 credentials in vaultd's environment can read and delete every object in the bucket, so the bucket must belong to vaultd alone; cleanup also deletes any object named like a file id that has no record
- A group of clients with upload bandwidth can fill the storage quota and keep uploads unavailable until their files expire, up to seven days; their creates also push older audit entries out, at most a few entries per record and quota / 64 KiB records at a time (D021)
- An attacker with many IPv6 /64s can saturate the CPU: a measured flood raised another client's p99 latency from under 1 ms to 37 ms. Per-client limits cannot stop this; it needs protection upstream of the server
