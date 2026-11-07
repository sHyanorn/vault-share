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
| Account password and account key (M7) | Highest: the key opens the entries, and through them every file an account keeps; neither reaches the server (D026) |
| Session token, device key and device cookie | High: a live session releases the device key that opens this browser's copy of the account key |
| TOTP secrets and recovery codes | High: each completes a sign-in whose password is known |
| Users table | Medium: Argon2id hashes of auth secrets and account keys sealed under passwords, guessable offline at Argon2id cost |

## 2. Trust Boundaries

1. Between the user's browser and the network
2. Between the network and the server
3. Between the server and storage
4. Frontend code delivery (the server serves JS to the browser)
5. Build and CI pipeline (GitHub Actions, npm and Go modules, container base images)
6. The browser's storage, which keeps the account key sealed between page loads (M7)

## 3. Attackers

- A1 Network eavesdropper
- A2 Ordinary external attacker holding information other than the share link
- A3 Attacker who has obtained the database and storage
- A4 Attacker in full control of the server
- A5 Malicious uploader (abuses the service to spread malicious files or exhaust resources)
- A6 Account attacker (guesses or reuses passwords, phishes, or steals a session or a device; M7)

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
| D Denial of service | Failures from many addresses fill the audit log | Process-wide budget for failure events, 1,000,000-row cap (D018); failed sign-ins and second steps share it, so their flood hides other failures for its duration (F40) | Done (M4, F16) |
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
| S Spoofing | A6 guesses passwords online or replays leaked ones | Failures counted per client and username, per username for browsers that never signed in, per known browser, with attempts admitted before they are checked (D027, F39); Argon2id in the browser makes every guess cost 64 MiB; 15-character passwords; optional TOTP | Done (M7) |
| D Denial of service | Failed sign-ins lock the owner out | A browser that signed in before carries a signed device cookie and is counted on its own, so a campaign locks only unknown browsers (OWASP device cookies, D027); an attempt refused only because others are in flight is told to retry in seconds (F42) | Done (M7, F42) |
| I Information disclosure | Probing which usernames exist | A username without an account gets a stable salt and fails after the same work with the same answer | Partly: sign-up still tells a taken name, at five tries an hour per client (D027) |
| S Spoofing | Session theft or fixation | `__Host-` cookie, HttpOnly, Secure, SameSite=Strict; a new token at every sign-in and privilege change; an hour idle, a day in all; sign-out and password changes end sessions server-side, a change in its own transaction and a sign-out even when the client hangs up (F46) | Done (M7, D027, F46) |
| S Spoofing | Another site uses or plants a session (CSRF, login CSRF) | The Fetch Metadata and Origin checks of D022 on every account request; SameSite=Strict | Done (M7, D028) |
| S Spoofing | A6 with the password guesses or replays a second-step code | One step either way, each step usable once, five tries per ticket, five failures per account lock the second step, with attempts counted before they are checked so codes sent at once get no more; failures after a right password are reported at the next sign-in, even when the client hangs up (F45); a password or TOTP change ends pending tickets (F43) | Done (M7, D029, F38, F43) |
| E Elevation of privilege | A stolen session turns off the second factor, changes the password or deletes the account | Each asks for the password again, and for a code while TOTP is on | Done (M7, D029) |
| I Information disclosure | A3 reads the users table and the files' entries | Guessing a password costs Argon2id in the browser and again on the server per attempt; entries and names open only with the account key; TOTP secrets are sealed under a server key | Covered by design (the key sits in the data directory, so A3 with all of it can produce codes) |
| I Information disclosure | A copy of the browser's storage | It holds the account key only sealed under a device key that the server derives from the session token and releases while the session lasts | Done (M7, D026) |
| D Denial of service | Sign-ins and sign-ups exhaust CPU, memory or the database | Four server-side Argon2id hashes at once with a bounded wait; five sign-ups an hour and a sign-in budget per client; 10,000 accounts and ten sessions per account | Done (M7, D027) |
| R Repudiation | An owner denies an account change | Sign-ins, failures, TOTP changes, password changes and deletions are audited with the account id and hashed client | Done (M7) |
| E Elevation of privilege | Path traversal to read arbitrary files | Strict file id validation; storage paths never built from user input; static files served through `os.Root`, which refuses symlinks and dot segments that leave the web dir, with no directory listing | Done (M2: ids must be 22 base64url characters before any path is built) |
| E Elevation of privilege | XSS stealing the key from the page | Strict CSP, no inline scripts, React default escaping, no rendering of user HTML | Done (M4: CSP without unsafe-inline or unsafe-eval, D016) |

## 5. Residual Risks

- A4 can serve malicious frontend code to steal keys. This limitation is shared by all web-based encryption products and must be stated in the README. With an account the reach grows: a captured account password opens every file the account keeps
- There is no password reset: a forgotten account password loses the account and its list; shared links keep working (D026)
- The server knows which files belong to which account and when they were shared; anonymous shares stay unlinked (D030)
- Someone who keeps failing for a username locks it for 15 minutes for browsers that never signed in to it, at 20 attempts every 15 minutes; the owner's known browsers keep working (D027)
- TOTP does not stop a phishing page that relays a code within its step
- File size and upload time are visible to the server
- Once a link leaks, anyone holding it can download the file; with a password the holder can still guess it offline at Argon2id cost per attempt
- A copy of the database lets its holder fetch every live ciphertext and spend its download count through the API, without being able to decrypt (F20)
- A power loss can roll back the newest download decrement and so grant one extra download (D005)
- Rate limits and lockouts count one IPv4 address or one IPv6 /64 as one client; an attacker holding many of those is bounded only by the per-file download count and the total disk. Clients behind one address share their limits
- The server is a single instance; its in-memory limiter state resets on restart
- The S3 credentials in vaultd's environment can read and delete every object in the bucket, so the bucket must belong to vaultd alone; cleanup also deletes any object named like a file id that has no record
- A group of clients with upload bandwidth can fill the storage quota and keep uploads unavailable until their files expire, up to seven days; their creates also push older audit entries out, at most a few entries per record and quota / 64 KiB records at a time (D021)
- An attacker with many IPv6 /64s can saturate the CPU: a measured flood raised another client's p99 latency from under 1 ms to 37 ms. Per-client limits cannot stop this; it needs protection upstream of the server
