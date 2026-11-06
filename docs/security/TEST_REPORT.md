# Security Test Report

Self-assessment of vault-share against the [OWASP Top 10:2025](https://top10.owasp.org/2025/), carried out in milestone M5 on 2026-11-06. All tests ran against local instances of this project.

## Summary

| Category | Result | Findings |
|---|---|---|
| A01:2025 Broken Access Control | Pass after fix | F18 |
| A02:2025 Security Misconfiguration | Pass after fix | F19 |
| A03:2025 Software Supply Chain Failures | Pass, one finding accepted | F22 |
| A04:2025 Cryptographic Failures | Pass after documentation fix | F20 |
| A05:2025 Injection | Pass | |
| A06:2025 Insecure Design | Pass with residual risks | F18 |
| A07:2025 Authentication Failures | Pass after fix | F21 |
| A08:2025 Software or Data Integrity Failures | Pass | |
| A09:2025 Security Logging and Alerting Failures | Pass; alerting is left to the operator | |
| A10:2025 Mishandling of Exceptional Conditions | Pass | |

The assessment found five issues, F18 to F22 in [FINDINGS.md](FINDINGS.md): one Medium, three Low and one Info. Four are fixed; F22 waits for an upstream release.

| Run | Before fixes (`f45771e`) | After fixes (`12a5bf2`) |
|---|---|---|
| `scripts/blackbox.py`, Compose stack | 139 passed, 3 failed | 142 passed |
| `scripts/blackbox.py`, vaultd direct | | 137 passed, 2 skipped (TLS checks) |
| `scripts/browser_checks.cjs` | 19 passed; F18 showed in the server log | 19 passed |
| Go tests with `-race` | 71 | 72 |
| Vitest | 82 | 84 |
| gosec, govulncheck, npm audit, Semgrep | 0 issues | 0 issues |
| ZAP baseline in CI | 0 alerts above Informational | 0 alerts above Informational |

## 1. Scope

- **Target**: this repository. The vaultd API and static serving, the web client, the Caddy front, the Compose deployment, the CI pipeline and the dependencies.
- **Instances**: the Compose stack at `https://localhost`, with Caddy's local CA, and vaultd alone at `http://127.0.0.1:8090`. No other host was tested.
- **Out of scope**: hardening of the host and the Docker daemon, the GitHub account, volumetric denial of service (only bounded probes ran), physical access and social engineering.

## 2. Method

Each category was mapped to the [threat model](THREAT_MODEL.md). The code behind its controls was reviewed, and automated checks ran against the running stack. Manual probes covered what a script would not repeat usefully. Test cases come from the [OWASP Web Security Testing Guide v4.2](https://wstg.owasp.org/v4.2/), cited as `WSTG-v42-<category>-<number>`, the versioned form the guide asks for. Every fix was retested with the check that found it.

| Tool | Version | Use |
|---|---|---|
| `scripts/blackbox.py` | Python 3.13, standard library | 142 server-side checks against a running instance |
| `scripts/browser_checks.cjs` | Playwright 1.63, Chromium | 19 checks that need a real browser |
| Go tests, Vitest | Go 1.27.3, Vitest 5.1.0 | Unit and integration tests, race detector |
| gosec, govulncheck | 2.30.0, 1.9.0 | Static analysis; known vulnerabilities in source and in the Caddy binary |
| npm audit, Semgrep | npm 10.9.9, Semgrep 1.184.0 | Dependency advisories; `p/golang`, `p/typescript`, `p/react`, `p/secrets`, `p/python` |
| OWASP ZAP | 2.17.0 | Baseline scan of the Compose stack in CI |
| OpenSSL `s_client` | 3.0.13 | TLS protocol and cipher suite enumeration |
| `docker inspect` | Docker 29.9.2 | Container user, capabilities and filesystem |

The Compose stack ran the committed `compose.yaml` and `Caddyfile`. Build containers in the test environment could not reach the Go module proxy. The local vaultd image was therefore the runtime stage of the `Dockerfile` around a binary built on the host with the same flags. CI builds the `Dockerfile` unchanged and runs the ZAP scan against that stack. Evidence is in [`evidence/`](evidence/).

## 3. Results

Each table names the test cases, what was run and what came back. Unless stated otherwise, the evidence is the after-fix run in [`blackbox-after.txt`](evidence/blackbox-after.txt), under the named check.

### A01:2025 Broken Access Control

There are no accounts. Access rests on three secrets: the 128-bit file id in the link, the auth key derived from the link's secret, and the owner token in the delete link. Every operation must demand the right secret, tell nothing to anyone without it, and refuse requests made through someone else's browser.

- **Controls**:
  - `ownerFile` compares the SHA-256 of the bearer token with `hmac.Equal`.
  - `download` verifies an HMAC over a server challenge, and `content` spends a one-time token bound to the file.
  - Every lookup, token and signature failure gives the same 404 (D004).
  - Ids are validated before any path is built, and static files are served through `os.Root`.
  - The server sends no CORS headers and refuses cross-origin writes (D022).
  - SSRF, which now sits in this category, does not apply: the server makes no outbound requests.

| WSTG | Test | Result | Evidence |
|---|---|---|---|
| ATHZ-02, ATHZ-04 | Upload, delete, download and content with missing, foreign and wrong secrets. A download token used twice, used on another file, or replaced by the owner token | Every one refused with 404; legitimate use works | `access` |
| IDNT-04 | 19 requests with wrong secrets for live, missing, deleted and malformed ids | Byte-identical 404; a malformed download body gives 400 for live and missing ids alike | `not-found` |
| ATHZ-01, CONF-04 | 18 traversal and hidden-file paths (encoded, double-encoded, backslashes, `.git`, `.env`, `vault.db`, `audit.key`, `/proc`) and 3 through the API | The app shell, 400 or 404; no file outside the web root, no directory listing | `traversal` |
| CLNT-07 | Cross-origin reads and a CORS preflight | No `Access-Control-Allow-Origin`; the preflight gets 405 | `cors` |
| SESS-05 | A create sent from a page on another origin, in Chromium and by script | Created a file before the fix (F18); 403 after | [`cross-site.txt`](evidence/cross-site.txt) |
| BUSL-05 | Burn after reading | The last permitted download completes and the file is gone at once | `access`, [`link-after-burn.png`](evidence/link-after-burn.png) |

**Status**: F18 fixed.

### A02:2025 Security Misconfiguration

The scope is response headers, methods and errors on both servers, administrative interfaces, container privileges and timeouts at each layer.

- **Controls**:
  - `securityHeaders` sets the headers of D016 on every response.
  - Caddy runs unprivileged with `admin off`, HTTP/1.1 and HTTP/2 only, and vaultd's timeouts (D020).
  - Both containers run as uid 65532 on a read-only root with no capabilities.

| WSTG | Test | Result | Evidence |
|---|---|---|---|
| CONF-07, CLNT-09 | Headers on the app shell, an asset, an app route, the health check, an API 404, a 405 and an unknown API route | CSP without `unsafe-inline` or `unsafe-eval`, HSTS for two years, `nosniff`, `no-referrer`, COOP, COEP, CORP and `X-Frame-Options` on all seven | `headers` |
| CONF-06, INPV-03 | TRACE, OPTIONS, PATCH, PROPFIND and an unknown method on four paths; method override headers and parameters | 405 everywhere, nothing reflected; overrides ignored | `methods` |
| CLNT-09 | Framing by a page on another origin | Refused; Chromium cites `frame-ancestors 'none'` | [`browser-checks.txt`](evidence/browser-checks.txt), [`framing-refused.png`](evidence/framing-refused.png) |
| INFO-02, ERRH-01 | Server banners; malformed JSON, an unknown route, an 80 KiB header | No version in any banner; client errors without internals | `headers`, `errors` |
| INFO-05 | Inline script, handlers and styles in the shell; source maps | None | `page` |
| CONF-05 | Caddy admin endpoint on port 2019 | Connection refused; vaultd has no administrative routes | [`containers.txt`](evidence/containers.txt) |
| CONF-09 | Permissions in the data volume | `vault.db` and `audit.key` 0600, `blobs` 0700 | [`containers.txt`](evidence/containers.txt) |
| | Container user, filesystem and capabilities | uid 65532, read-only root, effective capabilities 0, `no-new-privileges`, only Caddy publishes ports | [`containers.txt`](evidence/containers.txt) |
| BUSL-07 | Unfinished headers, idle keep-alive, slow body | Caddy held unfinished headers for 60 s and idle connections for 5 minutes (F19). After the fix: 10 s and 120 s, as in vaultd. A slow body ends after 30 s at vaultd and reaches the client after 90 s through Caddy | [`timeouts.txt`](evidence/timeouts.txt) |
| | ZAP baseline | No alert above Informational; the three Informational rules about caching and single-page apps are accepted in `.zap/rules.tsv` | [`zap-baseline.png`](evidence/zap-baseline.png), [`zap-report.html`](evidence/zap-report.html) |

**Status**: F19 fixed.

### A03:2025 Software Supply Chain Failures

The scope is everything that ends up in the build or the running service: Go modules, npm packages, GitHub Actions, base images and the Caddy binary.

- **Controls**:
  - Exact versions with `go.sum` and `package-lock.json`.
  - Actions pinned by commit SHA and images pinned by digest.
  - Weekly Dependabot updates for every ecosystem.
  - A read-only CI token, and scanners in their own module (`server/tools`).
  - Since this milestone, npm installs without running package scripts.

| Test | Result | Evidence |
|---|---|---|
| govulncheck on vaultd's source | No vulnerabilities | [`go-scan.txt`](evidence/go-scan.txt) |
| npm audit | 0 vulnerabilities | [`web-test.txt`](evidence/web-test.txt) |
| govulncheck in binary mode on `caddy` from the pinned image | 4 advisories in modules that no configured handler uses (F22) | [`caddy-govulncheck.txt`](evidence/caddy-govulncheck.txt) |
| Install scripts in `package-lock.json` | Only `fsevents`, which is macOS only and never installed on Linux; `npm ci --ignore-scripts` in CI and the `Dockerfile` | |
| Pinning: every `uses:`, `FROM` and `docker run` image | 40-character SHAs and `sha256` digests throughout | `.github/workflows/ci.yml`, `Dockerfile`, `Dockerfile.caddy` |

**Not covered**:
- The OS packages of the Alpine-based Caddy image are not scanned.
- No SBOM is published.
- Reproducible builds are not verified.

**Status**: F22 accepted.

### A04:2025 Cryptographic Failures

The scope is the encryption scheme of SPEC section 4, key handling in the browser, transport encryption, randomness, and what the server stores.

- **Encryption**:
  - Web Crypto only.
  - AES-256-GCM records in the RFC 8188 format, with nonces derived per record from a random per-file salt (D012).
  - An HKDF-SHA256 key tree and an HMAC-SHA256 challenge.
  - Argon2id at 64 MiB with 2 passes for passwords (D019).
- **Key handling**:
  - The key lives only in the URL fragment (D003), and pages send no Referer.
- **Randomness and storage**:
  - Tokens are 256-bit random and stored as SHA-256; ids are 128-bit random.
  - Randomness comes from `crypto/rand` and `crypto.getRandomValues`.

| WSTG | Test | Result | Evidence |
|---|---|---|---|
| CRYP-04 | Known-answer tests for HKDF (RFC 5869), RFC 8188 and AES-256-GCM (NIST CAVP); pinned Argon2id parameters; tampered, truncated, reordered and duplicated records | All pass; any change to the ciphertext fails decryption | [`web-test.txt`](evidence/web-test.txt) |
| CRYP-03 | Every request Chromium sent during an upload, a download and a password share, searched in four encodings for the fragment, the secret, the file key and the metadata key | None in 16 requests (7 to the API); the auth key appears once, in the create request, by design; no Referer header | [`browser-checks.txt`](evidence/browser-checks.txt) |
| | A wrong password | Rejected in the browser without a request | [`password-wrong.png`](evidence/password-wrong.png) |
| CRYP-01 | TLS protocols and suites, one at a time | TLS 1.0 and 1.1 refused; TLS 1.2 only with ECDHE-ECDSA and AES-GCM or ChaCha20-Poly1305; TLS 1.3; X25519 | [`tls.txt`](evidence/tls.txt), `tls` |
| CRYP-03 | Plain HTTP | Permanent redirect to the same HTTPS URL | `redirect` |
| | What a copy of the database holds (attacker A3) | Ciphertext, token hashes, keyed audit hashes, and the auth keys, which pass the download check (F20) | [`database.txt`](evidence/database.txt) |

**Status**: F20 fixed in the SPEC and the threat model.

### A05:2025 Injection

The scope is SQL, JSON input, file names rendered in the browser, uploaded content served back, the Host header and response headers.

- **Server**:
  - SQL is parameterized only.
  - JSON input rejects unknown fields and is capped at 16 KiB.
  - Base64url decoding is strict, and numbers are range-checked.
- **Browser**:
  - React renders text only; nothing uses `dangerouslySetInnerHTML` or `innerHTML`.
  - `safeFileName` cleans file names, and the CSP blocks inline and remote script.
- **Content and headers**:
  - Downloads are served as `application/octet-stream` attachments with `nosniff`.
  - Response headers never carry user input.

| WSTG | Test | Result | Evidence |
|---|---|---|---|
| INPV-05 | SQL metacharacters in path ids, tokens and JSON fields | 400 or 404 without detail; Semgrep finds no SQL built from strings | `input`, [`semgrep.txt`](evidence/semgrep.txt) |
| BUSL-01 | 19 malformed create bodies: wrong types and ranges, bad encodings, unknown fields, a 20 KiB body | All 400 with a generic code | `input` |
| INPV-02, CLNT-01, CLNT-03 | A file named `<img src=x onerror=alert(document.domain)>.html` | Shown as text, with the characters invalid in file names replaced; no element created, no script run | [`file-name-as-text.png`](evidence/file-name-as-text.png) |
| CLNT-02 | An injected inline handler, inline script, remote script, `javascript:` frame and string timer | None runs; each is reported as a CSP violation | [`browser-checks.txt`](evidence/browser-checks.txt) |
| BUSL-09 | An uploaded script loaded from its content URL inside the app | Refused for its MIME type | [`browser-checks.txt`](evidence/browser-checks.txt) |
| INPV-17 | A foreign `Host` header | Not reflected | `host`, [`probes.txt`](evidence/probes.txt) |

**Status**: pass.

### A06:2025 Insecure Design

The scope is whether the design bounds abuse: download counts, expiry, burn after reading, and the resources one client or all clients together can take.

- **Controls**:
  - A STRIDE threat model.
  - Download accounting in one statement, and stateless challenges (D014).
  - Per-client token buckets and lockout, in bounded tables (D017).
  - A global storage quota with a per-client budget (D021).
  - Expiry cleanup and an audit budget (D018).

| WSTG | Test | Result | Evidence |
|---|---|---|---|
| BUSL-05 | Concurrent downloads against the count; concurrent uploads | `TestConcurrentDownloadsRespectTheLimit`, `TestConcurrentUploadsStoreOneCopy` pass with `-race` | [`go-test.txt`](evidence/go-test.txt) |
| BUSL-07 | Creates with a new forged client address in four forwarding headers each time | 429 with `Retry-After` once the client's bucket is empty; five more forged creates also 429 | `rate-limit` |
| BUSL-07 | Storage quota and per-client budget | `TestQuotaIsAtomic`, `TestStorageQuota`, `TestStorageBudgetPerClient`, `TestStorageRefundWithARealClock` pass | [`go-test.txt`](evidence/go-test.txt) |
| | Per-client limits against requests sent by other sites through visitors' browsers | Each visitor counted as a new client (F18, fixed under A01) | [`cross-site.txt`](evidence/cross-site.txt) |

**Status**: pass. Section 5 lists the residual risks.

### A07:2025 Authentication Failures

There are no user accounts. Authentication here means possession: of the link, shown by an HMAC over a challenge; of the delete link's owner token; of a download token; and optionally of a password.

- **Controls**:
  - Tokens are 256-bit and compared in constant time.
  - Five bad signatures lock that client out of that file for 15 minutes, and download authentication has its own rate limit.
  - Challenges expire after 2 minutes and carry an HMAC tag that binds them to their file.
  - Passwords go through Argon2id and, since F21, need 8 characters.
  - The server sets no cookies and keeps no sessions.

| WSTG | Test | Result | Evidence |
|---|---|---|---|
| ATHN-03 | Five bad signatures, then the right one | Locked with the same 404; another file of the same client still downloads | `lockout` |
| ATHN-04 | A signature made with another file's key; the owner token as a download token | Refused | `access` |
| ATHN-07 | Password length | Any non-empty password before F21; 8 characters required after, and links made with shorter ones still open | [`password-minimum.png`](evidence/password-minimum.png), [`web-test.txt`](evidence/web-test.txt) |
| ATHN-06 | Caching of tokens, challenges and ciphertext | `no-store` on each | `cache` |
| ATHN-01 | Secrets on unencrypted channels | HTTPS only; plain HTTP redirects before any request reaches vaultd | `tls`, `redirect` |

**Status**: F21 fixed.

### A08:2025 Software or Data Integrity Failures

The scope is the integrity of ciphertext and metadata, of uploads, of the code the browser runs and of the build.

- **Controls**:
  - Ciphertext is AES-GCM per record with an end marker, and metadata is AES-GCM.
  - An upload must match its declared size and is stored once.
  - The API decodes JSON into fixed structs only; no input selects a type to deserialize.
  - Scripts come only from the app's own origin.
  - Build inputs are pinned and the CI token is read-only.

| WSTG | Test | Result | Evidence |
|---|---|---|---|
| BUSL-03 | Flipped bytes; records swapped, dropped, duplicated or appended; streams cut at any point | Decryption fails closed | [`web-test.txt`](evidence/web-test.txt) |
| BUSL-03 | Upload bodies shorter, longer or chunked past the declared size; a second upload | 400 for each, 409 for the second; the first complete upload is what downloads | `upload` |
| | Subresource Integrity | Not used. It cannot stop a compromised server, which serves the hashes too (D023) | |

**Status**: pass. Code served by a compromised server remains residual risk A4.

### A09:2025 Security Logging and Alerting Failures

The scope is whether security events are recorded, whether logs stay free of secrets and resist forging and flooding, and whether anyone is alerted.

- **Request log**: one JSON line per request, without the query string (D010). Panics go through the same logger, and Caddy writes no access log.
- **Audit log**: audit events carry keyed client hashes (D018). The audit table is bounded and failure events share a budget (F16).
- **Warnings**: vaultd warns about a misconfigured proxy and about dropped audit entries.

| Test | Result | Evidence |
|---|---|---|
| A full flow with every key, token and password checked against every log line | `TestLogsNeverContainSecrets`, `TestRequestLogOmitsQueryString`, `TestPanicIsLoggedAndAnswered` pass | [`go-test.txt`](evidence/go-test.txt) |
| Logs of the Compose stack after all runs | 261 request lines, none with a query string, token or bearer value; Caddy logged no request | [`logs.txt`](evidence/logs.txt) |
| Audit rows after the runs | Creates, uploads, grants, denials, a lockout and deletes recorded; forged forwarding headers produced no extra client | [`database.txt`](evidence/database.txt) |
| Log forging (CWE-117) | Paths are written through slog's JSON encoder, which escapes control characters | Code review |

**Gap**: nothing alerts. These are the signals an operator should alert on:
- Bursts of 403 `cross_origin`, 429 `rate_limited` and 503 `capacity`.
- The warnings "audit failure events over budget were not recorded" and "audit log over capacity, oldest entries dropped".
- The warning about a trusted proxy that names no client.
- Any `panic` line.

**Status**: pass.

### A10:2025 Mishandling of Exceptional Conditions

The scope is behaviour under bad input, storage failures, races, timeouts and panics, on the server and in the browser.

- **Controls**:
  - Input is validated before the lookup (F6), and storage failures give a logged 500 (F7).
  - A panic is answered with a 500.
  - Body sizes are capped, and every transfer has a deadline (F3).
  - Burns and purges are ordered so that no granted download is lost (F4, F9).
  - A create refused by the quota gives back its budget, and configuration is validated at startup.
  - The browser discards partial output when decryption fails.

| WSTG | Test | Result | Evidence |
|---|---|---|---|
| ERRH-01, ERRH-02 | Error responses across all checks | Generic JSON errors; no stack trace, SQL or path in any body | `errors`, `input` |
| INPV-15 | Conflicting `Content-Length` values, an obfuscated and an unsupported `Transfer-Encoding` | 400 or 501. With both `Content-Length` and chunked, Go uses chunked and answers a hidden request on the sender's own connection. Caddy frames each forwarded request anew, so no desync between the servers is possible | `framing`, [`probes.txt`](evidence/probes.txt) |
| | Failure paths: `TestStorageFailureIsNotTheClientsFault`, `TestGrantedDownloadSurvivesCleanup`, `TestDeleteDuringUploadLeavesNothing`, `TestSlowUploadStillGetsItsResponse`, `TestStorageRefundWithARealClock` | Pass | [`go-test.txt`](evidence/go-test.txt) |
| | A download whose ciphertext fails to decrypt | No partial file is handed over (`share.test.ts`) | [`web-test.txt`](evidence/web-test.txt) |

**Status**: pass.

## 4. Findings

| ID | Severity | Category | Summary | Status |
|---|---|---|---|---|
| [F18](FINDINGS.md#f18-cross-site-creates-through-visitors-browsers-medium) | Medium | A01, A06 | A page on another site could create files through its visitors' browsers | Fixed |
| [F19](FINDINGS.md#f19-slow-connections-held-longer-at-caddy-low) | Low | A02 | Caddy held slow and idle connections longer than vaultd | Fixed |
| [F20](FINDINGS.md#f20-download-keys-in-the-database-low) | Low | A04 | The database holds the keys that pass the download check, which the docs denied | Fixed in documentation |
| [F21](FINDINGS.md#f21-no-minimum-password-length-low) | Low | A07 | Password protection accepted passwords of any length | Fixed |
| [F22](FINDINGS.md#f22-advisories-in-the-pinned-caddy-info) | Info | A03 | The pinned Caddy release carries modules with published advisories | Accepted |

One hardening change came out of the same work: `npm ci` no longer runs package scripts (A03).

## 5. Residual Risks

Section 5 of the threat model holds the full list. The ones a reader of this report most needs:

- A compromised server can serve code that steals keys (A4); no browser mechanism prevents it.
- A leaked link is a leaked file. With a password, the holder can still guess offline at Argon2id cost per attempt.
- A copy of the database lets its holder fetch ciphertexts and spend download counts, without decrypting (F20).
- Limits count one IPv4 address or one IPv6 /64 as one client. An attacker with many of them can fill the quota or saturate the CPU; this needs protection upstream.
- One instance holds its limiter state in memory, and that state resets on restart.
- Not covered by this assessment: OS packages of the Caddy image, an SBOM, reproducible builds and alerting.

## 6. Reproducing

```bash
docker compose up --build --detach --wait
docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt root.crt
python3 scripts/blackbox.py https://localhost --cafile root.crt --http-url http://localhost
NODE_PATH="$(npm root -g)" node scripts/browser_checks.cjs https://localhost shots
```

The black-box script refuses non-local targets unless `--remote` confirms that the instance is yours. It creates and deletes test files, locks one of them, and uses up the client's create budget.

## Evidence

| File | Content |
|---|---|
| [`blackbox-before.txt`](evidence/blackbox-before.txt), [`blackbox-after.txt`](evidence/blackbox-after.txt) | Black-box checks on the Compose stack before and after the fixes |
| [`blackbox-direct.txt`](evidence/blackbox-direct.txt) | Black-box checks on vaultd without Caddy |
| [`browser-checks.txt`](evidence/browser-checks.txt) | Browser checks after the fixes |
| [`cross-site.txt`](evidence/cross-site.txt) | F18 before and after, from the browser and the server log |
| [`timeouts.txt`](evidence/timeouts.txt) | F19 measurements |
| [`tls.txt`](evidence/tls.txt), [`probes.txt`](evidence/probes.txt) | TLS enumeration; raw framing and Host probes |
| [`containers.txt`](evidence/containers.txt), [`database.txt`](evidence/database.txt), [`logs.txt`](evidence/logs.txt) | Container privileges and data permissions; what the database holds; log contents |
| [`go-test.txt`](evidence/go-test.txt), [`go-scan.txt`](evidence/go-scan.txt), [`web-test.txt`](evidence/web-test.txt), [`semgrep.txt`](evidence/semgrep.txt), [`caddy-govulncheck.txt`](evidence/caddy-govulncheck.txt) | Test and scanner output |
| [`zap-baseline.png`](evidence/zap-baseline.png), [`zap-report.html`](evidence/zap-report.html) | ZAP baseline from CI after the fixes |
| [`file-name-as-text.png`](evidence/file-name-as-text.png), [`link-after-burn.png`](evidence/link-after-burn.png), [`password-wrong.png`](evidence/password-wrong.png), [`password-minimum.png`](evidence/password-minimum.png), [`framing-refused.png`](evidence/framing-refused.png) | Screenshots |
