# Security Test Report

Self-assessment of vault-share against the [OWASP Top 10:2025](https://top10.owasp.org/2025/), carried out in milestone M5 on 2026-11-06 and 2026-11-07. Section 7 adds the accounts of M7. All tests ran against instances of this project that the tester operated.

## Summary

| Category | Result | Findings |
|---|---|---|
| A01:2025 Broken Access Control | Pass after fixes | F18, F24, F25 |
| A02:2025 Security Misconfiguration | Pass after fixes | F19, F23 |
| A03:2025 Software Supply Chain Failures | Pass, one finding accepted | F22 |
| A04:2025 Cryptographic Failures | Pass after documentation fix | F20 |
| A05:2025 Injection | Pass | |
| A06:2025 Insecure Design | Pass with residual risks | F18 |
| A07:2025 Authentication Failures | Pass after fix | F21 |
| A08:2025 Software or Data Integrity Failures | Pass | |
| A09:2025 Security Logging and Alerting Failures | Partial: logging passes, nothing alerts | |
| A10:2025 Mishandling of Exceptional Conditions | Pass | |

The assessment found eight issues, F18 to F25 in [FINDINGS.md](FINDINGS.md): one Medium, six Low and one Info.
- **Fixed in code or configuration**: F18, F19, F21, F23, F24 and F25.
- **Fixed in documentation**: F20.
- **Accepted**: F22, until upstream ships a fixed release.

The first test pass found F18 to F22. An independent review of that pass and of its fixes found F23 to F25, and also showed that several checks could pass without proving their claim. Those checks were tightened, and everything below comes from the tightened versions.

| Run on the fixed code (`dc5eb24`) | Result |
|---|---|
| `scripts/blackbox.py`, Compose stack | 146 passed |
| `scripts/blackbox.py`, vaultd direct | 140 passed; 2 skipped, the TLS and redirect checks, which need HTTPS |
| `scripts/browser_checks.cjs` | 23 passed |
| Go tests with `-race` | 74 passed |
| Vitest | 84 passed |
| gosec, govulncheck on the source, npm audit, Semgrep | 0 issues |
| govulncheck on the Caddy binary | 4 advisories (F22) |
| ZAP baseline in CI | no alert above Informational |

Before the fixes, at `1879871`, the black-box run on the Compose stack passed 139 checks and failed 3: two for F18 and one for F19 ([`blackbox-before.txt`](evidence/blackbox-before.txt)).

## 1. Scope

- **Target**: this repository. That covers the vaultd API and static serving, the web client, the Caddy front, the Compose deployment, the CI pipeline and the dependencies.
- **Instances**: the Compose stack at `https://localhost`, with Caddy's local CA, and vaultd alone at `http://127.0.0.1:8090`, both on the test machine. The ZAP scan runs in CI against the stack the runner starts.
- **Out of scope**:
  - hardening of the host and the Docker daemon;
  - the GitHub account;
  - volumetric denial of service (only bounded probes ran);
  - physical access and social engineering.

## 2. Method

Each category was mapped to the [threat model](THREAT_MODEL.md), and the code behind its controls was reviewed. Automated checks ran against the running instances, and manual probes covered what a script would not usefully repeat.

Test cases come from the [OWASP Web Security Testing Guide v4.2](https://wstg.owasp.org/v4.2/). The tables give each ID in its short form (`ATHZ-02` stands for `WSTG-v42-ATHZ-02`); a row without an ID has no matching case in the guide.

Work stopped at each finding until Aaron agreed to a fix, and each fix was retested with the check that found it.

| Tool | Version | Use |
|---|---|---|
| `scripts/blackbox.py` | Python 3.13, standard library | Server-side checks against a running instance |
| `scripts/browser_checks.cjs` | Playwright 1.63, Chromium | Checks that need a real browser |
| Go tests, Vitest | Go 1.27.3, Vitest 5.1.0 | Unit and integration tests, race detector |
| gosec, govulncheck | 2.30.0, 1.9.0 | Static analysis; known vulnerabilities in the source and in the Caddy binary |
| npm audit, Semgrep | npm 10.9.9, Semgrep 1.184.0 | Dependency advisories; rulesets `p/golang`, `p/typescript`, `p/react`, `p/secrets`, `p/python` |
| OWASP ZAP | 2.17.0 | Baseline scan of the Compose stack in CI |
| OpenSSL `s_client` | 3.0.13 | TLS protocol and cipher suite enumeration |
| `docker inspect` | Docker 29.9.2 | Container user, capabilities and filesystem |

The Compose stack ran the committed `compose.yaml` and `Caddyfile`. Build containers in the test environment could not reach the Go module proxy. The local vaultd image was therefore the runtime stage of the `Dockerfile` around a binary built on the host with the same flags. CI builds the `Dockerfile` unchanged and runs the ZAP scan against that stack. Evidence is in [`evidence/`](evidence/).

## 3. Results

Each table names the test cases, what was run and what came back. Unless stated otherwise, the evidence is [`blackbox-after.txt`](evidence/blackbox-after.txt), under the named check.

### A01:2025 Broken Access Control

There are no accounts. Access rests on three secrets:
- the 128-bit file id in the link;
- the auth key derived from the link's secret;
- the owner token in the delete link.

Every operation must demand the right secret and tell nothing to anyone without it. Requests made through someone else's browser must be refused.

**Controls**:
- **Secrets**: `ownerFile` compares the SHA-256 of the bearer token with `hmac.Equal`. `download` verifies an HMAC over a server challenge, and `content` spends a one-time token bound to the file.
- **Uniform 404**: every lookup, token and signature failure gives the same 404 (D004).
- **Paths**: ids are validated before any path is built, and static files are served through `os.Root`.
- **Other origins**: the server sends no CORS headers. API requests that Fetch Metadata marks as cross-site are refused for every method, and the API answers only for its own host (D022).
- **SSRF**: now part of this category, but not applicable here, because the server makes no outbound requests.

| WSTG | Test | Result | Evidence |
|---|---|---|---|
| ATHZ-02, ATHZ-04 | Upload, delete, download and content requests with missing and foreign secrets. A download token used twice, used on another file, or replaced by the owner token | Every one refused with 404; legitimate use works | `access` |
| IDNT-04 | 19 requests for live, missing, deleted and malformed ids, 16 of them with a wrong token or signature | Byte-identical 404s. A malformed download body gets 400 for live and missing ids alike | `not-found` |
| ATHZ-01, CONF-04 | 18 traversal and hidden-file paths (encoded, double-encoded, backslashes, `.git`, `.env`, `vault.db`, `audit.key`, `/proc`), plus 3 through the API | The app shell, 400 or 404. No file outside the web root, no directory listing | `traversal` |
| CLNT-07 | Cross-origin reads and a CORS preflight | No `Access-Control-Allow-Origin`; the preflight gets 405 | `cors` |
| SESS-05 | A create and a read sent from a page on another origin, in Chromium and by script | Before the fix, the create made a file (F18). Now both get 403 `cross_origin`, read from the browser's network log (F24) | [`cross-site.txt`](evidence/cross-site.txt), [`browser-checks.txt`](evidence/browser-checks.txt) |
| INPV-17 | An API request under a foreign Host, as from a rebound name | 421 `misdirected` at vaultd (F25). Through Caddy, the request never reaches vaultd | `host`, [`probes.txt`](evidence/probes.txt) |
| BUSL-05 | Burn after reading | The last permitted download completes and the file is gone at once | `access`, [`link-after-burn.png`](evidence/link-after-burn.png) |

**Status**: F18, F24 and F25 fixed.

### A02:2025 Security Misconfiguration

The scope is response headers, methods and banners on both servers, administrative interfaces, container privileges, and the timeouts at each layer.

**Controls**:
- `securityHeaders` sets the headers of D016 on every response.
- Caddy runs unprivileged, with `admin off`, HTTP/1.1 and HTTP/2 only, and vaultd's header and idle timeouts on both of its ports (D020).
- Both containers run as uid 65532 on a read-only root filesystem with no capabilities.

| WSTG | Test | Result | Evidence |
|---|---|---|---|
| CONF-07 | Headers on seven responses: the app shell, an asset, an app route, the health check, an API 404, a 405 and an unknown API route | All seven carry: a CSP without `unsafe-inline` or `unsafe-eval`; HSTS for two years; `nosniff`; `no-referrer`; COOP, COEP and CORP; `X-Frame-Options` | `headers` |
| | Inline script, event handlers and style attributes in the app shell, which the CSP forbids | None | `page` |
| CONF-06, INPV-03 | TRACE, OPTIONS, PATCH, PROPFIND and an unknown method on four paths; method override headers and parameters | 405 everywhere with nothing reflected; overrides ignored | `methods` |
| CLNT-09 | Framing by a page on another origin | Refused; Chromium cites `frame-ancestors 'none'` | [`browser-checks.txt`](evidence/browser-checks.txt), [`framing-refused.png`](evidence/framing-refused.png) |
| INFO-02 | Server banners | No version in any banner | `headers` |
| INFO-05 | Source maps | None referenced, none served | `page` |
| CONF-05 | Caddy admin endpoint on port 2019 | Connection refused; vaultd has no administrative routes | [`containers.txt`](evidence/containers.txt) |
| CONF-09 | Permissions in the data volume | `vault.db` and `audit.key` 0600, `blobs` 0700 | [`containers.txt`](evidence/containers.txt) |
| | Container user, filesystem and capabilities | uid 65532, read-only root, effective capabilities 0, `no-new-privileges`; only Caddy publishes ports | [`containers.txt`](evidence/containers.txt) |
| CONF-02 | Unfinished headers, idle keep-alive connections, slow bodies | See the timeout breakdown below the table | [`timeouts.txt`](evidence/timeouts.txt), `slow-headers` |
| | ZAP baseline | No alert above Informational. The three Informational rules about caching and single-page apps are accepted in `.zap/rules.tsv` | [`zap-baseline.png`](evidence/zap-baseline.png), [`zap-report.html`](evidence/zap-report.html) |

**Timeouts (CONF-02)**:
- **Unfinished headers on port 443**: Caddy held them for 60 s (F19). After the fix they are cut at 10 s.
- **Unfinished headers on port 80**: still 60 s after the F19 fix (F23). After the second fix, 10 s.
- **Idle keep-alive connections**: Caddy's documented default is 5 minutes. After the fix they close after 120 s, as in vaultd.
- **Slow request body**: vaultd ends it after 30 s; through Caddy the client gets the answer after 90 s.

**Status**: F19 and F23 fixed.

### A03:2025 Software Supply Chain Failures

The scope is everything that ends up in the build or the running service: Go modules, npm packages, GitHub Actions, base images and the Caddy binary.

**Controls**:
- **Pinning**: exact versions, recorded in `go.sum` and `package-lock.json`. Actions are pinned by commit SHA, images by digest.
- **Updates**: Dependabot proposes updates weekly for Go modules, npm packages, Actions, the Dockerfiles and Compose.
- **CI**: the CI token is read-only, and the scanners live in their own module (`server/tools`).
- **Install scripts**: npm runs none, in CI, in the `Dockerfile`, and on developer machines through `web/.npmrc`.

| Test | Result | Evidence |
|---|---|---|
| govulncheck on vaultd's source | No vulnerabilities | [`go-scan.txt`](evidence/go-scan.txt) |
| npm audit | 0 vulnerabilities | [`web-test.txt`](evidence/web-test.txt) |
| govulncheck in binary mode on `caddy` from the pinned image | 4 advisories in 3 modules (F22). The Caddyfile enables none of the handlers that use the affected packages, though binary mode cannot prove that no path reaches them | [`caddy-govulncheck.txt`](evidence/caddy-govulncheck.txt) |
| Install scripts in `package-lock.json` | Only `fsevents`, which is macOS only and never installed on Linux | |
| Pinning of every `uses:`, `FROM` and `docker run` image | 40-character SHAs and `sha256` digests throughout | `.github/workflows/ci.yml`, `Dockerfile`, `Dockerfile.caddy` |

**Not covered**:
- **Images Dependabot never sees**: the Semgrep and ZAP images are pinned inside `run:` commands, so they get no update pull requests and are updated by hand.
- **OS packages**: the packages of the Alpine-based Caddy image are not scanned.
- **Build provenance**: no SBOM is published, and reproducible builds are not verified.

**Status**: F22 accepted.

### A04:2025 Cryptographic Failures

The scope is the encryption scheme of SPEC section 4, key handling in the browser, transport encryption, randomness and what the server stores.

**Controls**:
- **Algorithms**:
  - Web Crypto provides AES-GCM, HKDF and HMAC; Argon2id comes from hash-wasm (D002).
  - File content is AES-256-GCM in RFC 8188 records, with nonces derived per record from a random per-file salt (D012).
  - An HKDF-SHA256 key tree derives the keys, and an HMAC-SHA256 challenge proves possession of the link.
  - Passwords go through Argon2id at 64 MiB with 2 passes (D019).
- **Key handling**: the key lives only in the URL fragment (D003), and pages send no Referer.
- **Tokens and randomness**:
  - Tokens are 256-bit random values stored as SHA-256 hashes; ids are 128-bit random values.
  - Randomness comes from `crypto/rand` and `crypto.getRandomValues`.

| WSTG | Test | Result | Evidence |
|---|---|---|---|
| CRYP-04 | Known-answer tests for HKDF (RFC 5869), RFC 8188 and AES-256-GCM (NIST CAVP); pinned Argon2id parameters | All pass | [`web-test.txt`](evidence/web-test.txt) |
| CRYP-04 | Changed ciphertext: each header byte, seven chosen body positions; records swapped, dropped, duplicated or appended; streams cut at six points | Every case fails decryption | [`web-test.txt`](evidence/web-test.txt) |
| | Every request Chromium sent while uploading, downloading and reopening a plain share. Searched for the fragment, the secret, the file key, the metadata key, the file name and a slice of the plaintext, in each of these forms: raw, hex, base64 at every alignment, percent-encoded and form-encoded | None of them in 16 requests (7 to the API), with every request body captured. The auth key appears once, in the create request, by design. No Referer header | [`browser-checks.txt`](evidence/browser-checks.txt) |
| | The requests of a password-protected share, searched in the same forms for the password and the wrapped secret | Neither appears | [`browser-checks.txt`](evidence/browser-checks.txt) |
| | A wrong password | Rejected in the browser without a request | [`password-wrong.png`](evidence/password-wrong.png) |
| CRYP-01 | TLS protocols and suites, each offered on its own | TLS 1.0 and 1.1 refused. TLS 1.2 only with ECDHE-ECDSA and AES-GCM or ChaCha20-Poly1305. TLS 1.3 accepted. Key exchange X25519 | [`tls.txt`](evidence/tls.txt), `tls` |
| CRYP-03 | Plain HTTP | Permanent redirect to the same HTTPS URL, before any request reaches vaultd | `redirect` |
| | What a copy of the data directory holds (attacker A3) | Ciphertext, token hashes, and keyed audit hashes together with the audit key, which inverts the IPv4 ones (D018). Also the auth keys, which pass the download check (F20) | [`database.txt`](evidence/database.txt) |

**Status**: F20 fixed in the SPEC and the threat model.

### A05:2025 Injection

The scope is SQL, JSON input, file names rendered in the browser, uploaded content served back, and request data in response headers.

**Controls**:
- **Server**: SQL is parameterized only. JSON input rejects unknown fields and is capped at 16 KiB, base64url decoding is strict, and numbers are range-checked.
- **Browser**: React renders text only, and nothing uses `dangerouslySetInnerHTML` or `innerHTML`. `safeFileName` cleans file names, and the CSP blocks inline and remote script.
- **Content**: downloads are `application/octet-stream` attachments sent with `nosniff`.
- **Headers**: vaultd's response headers carry no request data. Caddy's HTTP redirect repeats the requested host and path by design.

| WSTG | Test | Result | Evidence |
|---|---|---|---|
| INPV-05 | SQL metacharacters in path ids, tokens and JSON fields | 400 or 404 without detail. Semgrep finds no SQL built from strings | `input`, [`semgrep.txt`](evidence/semgrep.txt) |
| BUSL-01 | 19 malformed create bodies: wrong types and ranges, bad encodings, unknown fields, a 20 KiB body | All 400 with a generic code | `input` |
| INPV-02, CLNT-01, CLNT-03 | A file named `<img src=x onerror=alert(document.domain)>.html` | Shown as text, with the characters invalid in file names replaced. No element is created and no script runs | [`file-name-as-text.png`](evidence/file-name-as-text.png) |
| CLNT-02 | An injected inline handler, inline script, remote script, `javascript:` frame and string timer | None runs. The browser reports violations of `script-src`, `script-src-attr` and `script-src-elem` | [`browser-checks.txt`](evidence/browser-checks.txt) |
| BUSL-09 | An uploaded script, loaded from its content URL inside the app | Refused for its MIME type | [`browser-checks.txt`](evidence/browser-checks.txt) |

**Status**: pass.

### A06:2025 Insecure Design

The scope is whether the design bounds abuse: download counts, expiry, burn after reading, and the resources one client or all clients together can take.

**Controls**:
- a STRIDE threat model;
- download accounting in one statement, and stateless challenges (D014);
- per-client token buckets and lockout, kept in bounded tables (D017);
- a global storage quota with a per-client budget (D021);
- expiry cleanup and an audit budget (D018).

| WSTG | Test | Result | Evidence |
|---|---|---|---|
| BUSL-05 | Concurrent downloads against the count; concurrent uploads | `TestConcurrentDownloadsRespectTheLimit` and `TestConcurrentUploadsStoreOneCopy` pass with `-race` | [`go-test.txt`](evidence/go-test.txt) |
| BUSL-07 | Creates that name a new forged client address in four forwarding headers each time | 429 with `Retry-After` once the client's bucket is empty. Five more forged creates also get 429 | `rate-limit` |
| BUSL-07 | Storage quota and per-client budget | `TestQuotaIsAtomic`, `TestStorageQuota`, `TestStorageBudgetPerClient` and `TestStorageRefundWithARealClock` pass | [`go-test.txt`](evidence/go-test.txt) |
| BUSL-07 | Cross-site requests against a small request budget | Refused before the limiter, so the client's own requests still pass (`TestCrossSiteRequestsSpendNoBudget`) | [`go-test.txt`](evidence/go-test.txt) |
| | Per-client limits when other sites act through visitors' browsers | Each visitor counted as a new client (F18, fixed under A01) | [`cross-site.txt`](evidence/cross-site.txt) |

**Status**: pass. Section 5 lists the residual risks.

### A07:2025 Authentication Failures

Until M7 there were no user accounts; section 7 covers them. Sharing still authenticates by proving possession of one of these:
- the link, through an HMAC over a challenge;
- the delete link's owner token;
- a download token;
- optionally, a password.

**Controls**:
- Tokens are 256-bit random values. Owner tokens are compared in constant time. Download tokens are looked up by their SHA-256, so the lookup reveals nothing about the token.
- Five bad signatures lock that client out of that file for 15 minutes, and download authentication has its own rate limit.
- Challenges expire after 2 minutes and carry an HMAC tag that binds them to their file.
- Passwords go through Argon2id and, since F21, need at least 8 characters.
- Sharing sets no cookies and needs no session.

| WSTG | Test | Result | Evidence |
|---|---|---|---|
| ATHN-03 | Five bad signatures, then the right one | Locked out with the same 404 while the file stays live. Another file of the same client still gets a download token | `lockout` |
| ATHN-04 | A signature made with another file's key; the owner token used as a download token | Refused | `access` |
| ATHN-07 | Password length | Before F21, any non-empty password was accepted. Now 8 characters are required, and links made with shorter ones still open | [`password-minimum.png`](evidence/password-minimum.png), [`web-test.txt`](evidence/web-test.txt) |
| ATHN-06 | Caching of tokens, challenges and ciphertext | `no-store` on each | `cache` |
| ATHN-01 | Secrets on unencrypted channels | HTTPS only; plain HTTP is redirected before any request reaches vaultd | `tls`, `redirect` |

**Status**: F21 fixed.

### A08:2025 Software or Data Integrity Failures

The scope is the integrity of ciphertext and metadata, of uploads, of the code the browser runs, and of the build.

**Controls**:
- **Encryption**: ciphertext is AES-GCM per record with an end marker, and metadata is AES-GCM.
- **Uploads**: an upload must match its declared size and is stored once.
- **Input**: the API decodes JSON into fixed structs only, so no input chooses a type to deserialize.
- **Browser code**: scripts come only from the app's own origin.
- **Build**: build inputs are pinned and the CI token is read-only.

| WSTG | Test | Result | Evidence |
|---|---|---|---|
| | Changed and cut ciphertext | Decryption fails closed (the CRYP-04 tests under A04) | [`web-test.txt`](evidence/web-test.txt) |
| BUSL-03 | Upload bodies shorter than, longer than, or chunked past the declared size; a second upload | 400 for each wrong size, 409 for the second upload. The first complete upload is what downloads | `upload` |
| | Subresource Integrity | Not used. It cannot stop a compromised server, which serves the hashes too (D023) | |

**Status**: pass. Code served by a compromised server remains residual risk A4.

### A09:2025 Security Logging and Alerting Failures

The scope:
- whether security events are recorded;
- whether logs stay free of secrets and resist forging and flooding;
- whether anyone is alerted.

**Controls**:
- **Request log**: one JSON line per request, without the query string (D010). Panics go through the same logger. Caddy writes no access log.
- **Audit log**: audit events carry keyed client hashes (D018). The audit table is bounded, and failure events share a budget (F16).
- **Warnings**: vaultd warns about a misconfigured proxy and about dropped audit entries.

| Test | Result | Evidence |
|---|---|---|
| A full flow with the auth key and every token checked against every log line (the server never receives a password or a file key) | `TestLogsNeverContainSecrets`, `TestRequestLogOmitsQueryString` and `TestPanicIsLoggedAndAnswered` pass | [`go-test.txt`](evidence/go-test.txt) |
| vaultd and Caddy logs after the final runs | 527 request lines; none holds a query string, `token=` or `Bearer`. Caddy logged no request | [`logs.txt`](evidence/logs.txt) |
| Audit rows | Creates, uploads, grants, denials, lockouts and deletes, each with keyed client and user agent hashes | [`database.txt`](evidence/database.txt) |
| Log forging (CWE-117) | Paths are written through slog's JSON encoder, which escapes control characters | Code review |

**Gap**: nothing alerts. An operator should alert on these signals:
- bursts of 403 `cross_origin`, 421 `misdirected`, 429 `rate_limited` and 503 `capacity`;
- the warnings "audit failure events over budget were not recorded" and "audit log over capacity, oldest entries dropped";
- the warning about a trusted proxy that names no client;
- any `panic` line.

**Status**: partial. Logging passes; alerting is left to the operator.

### A10:2025 Mishandling of Exceptional Conditions

The scope is behaviour under bad input, storage failures, races, timeouts and panics, on the server and in the browser.

**Controls**:
- Input is validated before the lookup (F6), and storage failures give a logged 500 (F7).
- A panic is answered with a 500.
- Body sizes are capped, and every transfer has a deadline (F3).
- Burns and purges are ordered so that no granted download is lost (F4, F9).
- A create refused by the quota gives back its budget, and configuration is validated at startup.
- The browser discards partial output when decryption fails.

| WSTG | Test | Result | Evidence |
|---|---|---|---|
| ERRH-01, ERRH-02 | Error responses in the `errors`, `traversal` and `input` checks, matched against a pattern for stack traces, SQL errors and file contents | No match. API errors are generic JSON; errors from Go's HTTP server and file server are plain status text | `errors`, `traversal`, `input` |
| INPV-15 | Conflicting `Content-Length` values, an obfuscated `Transfer-Encoding` and an unsupported one, sent to an endpoint whose handler answers 405 | Refused with 400 or 501 before any handler runs, while a well-framed request reaches the handler | `framing`, [`probes.txt`](evidence/probes.txt) |
| | Failure paths: `TestStorageFailureIsNotTheClientsFault`, `TestGrantedDownloadSurvivesCleanup`, `TestDeleteDuringUploadLeavesNothing`, `TestSlowUploadStillGetsItsResponse` and `TestStorageRefundWithARealClock` | Pass | [`go-test.txt`](evidence/go-test.txt) |
| | A download whose ciphertext fails to decrypt | No partial file is handed over (`share.test.ts`) | [`web-test.txt`](evidence/web-test.txt) |

On the INPV-15 row: when a request carries both `Content-Length` and chunked encoding, Go uses the chunked framing. A request hidden after the body is then answered on the sender's own connection. Caddy frames every request it forwards anew, so Caddy and vaultd cannot disagree about where a request ends.

**Status**: pass.

## 4. Findings

| ID | Severity | Category | Summary | Status |
|---|---|---|---|---|
| [F18](FINDINGS.md#f18-cross-site-creates-through-visitors-browsers-medium) | Medium | A01, A06 | A page on another site could create files through its visitors' browsers | Fixed |
| [F19](FINDINGS.md#f19-slow-connections-held-longer-at-caddy-low) | Low | A02 | Caddy held slow and idle connections longer than vaultd | Fixed |
| [F20](FINDINGS.md#f20-download-keys-in-the-database-low) | Low | A04 | The database holds the keys that pass the download check, which the docs denied | Fixed in documentation |
| [F21](FINDINGS.md#f21-no-minimum-password-length-low) | Low | A07 | Password protection accepted passwords of any length | Fixed |
| [F22](FINDINGS.md#f22-advisories-in-the-pinned-caddy-info) | Info | A03 | The pinned Caddy release carries modules with published advisories | Accepted |
| [F23](FINDINGS.md#f23-http-redirect-server-kept-caddys-defaults-low) | Low | A02 | Caddy's HTTP redirect server kept the default timeouts after F19 | Fixed |
| [F24](FINDINGS.md#f24-cross-site-reads-spent-the-visitors-budget-low) | Low | A01, A06 | Cross-site reads through visitors' browsers could keep their request budget empty | Fixed |
| [F25](FINDINGS.md#f25-any-host-reached-the-api-low) | Low | A01 | The API answered any Host, so a rebound name reached a directly exposed vaultd as same-origin | Fixed |

The same work also hardened the build: npm runs no package install scripts (A03).

## 5. Residual Risks

The full list is in section 5 of the threat model. These are the ones a reader of this report most needs:

- **Compromised server**: it can serve code that steals keys (A4), and no browser mechanism prevents it.
- **Leaked link**: a leaked link is a leaked file. With a password, the holder can still guess offline at Argon2id cost per attempt.
- **Database copy**: whoever holds a copy can fetch ciphertexts and spend download counts, but cannot decrypt (F20).
- **Power loss**: a power loss can roll back the newest download decrement and grant one extra download (D005).
- **Many addresses**: limits count one IPv4 address or one IPv6 /64 as one client. An attacker with many of them can fill the quota or saturate the CPU, which needs protection upstream.
- **Single instance**: there is one instance, and its limiter state lives in memory and resets on restart.
- **Not covered by this assessment**:
  - OS packages of the Caddy image;
  - an SBOM;
  - reproducible builds;
  - alerting;
  - update pull requests for the Semgrep and ZAP images.

## 6. Reproducing

```bash
docker compose up --build --detach --wait
docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt root.crt
python3 scripts/blackbox.py https://localhost --cafile root.crt --http-url http://localhost
(cd web && npm ci && npx playwright install chromium)
NODE_PATH=web/node_modules node scripts/browser_checks.cjs https://localhost shots
```

To check vaultd alone, start it with `VAULT_BASE_URL` set to the address the script targets, such as `http://127.0.0.1:8090`. The API answers only for that host.

CI runs both scripts, and the end-to-end tests in `web/e2e`, against the Compose stack on every push.

The black-box script refuses non-local targets unless `--remote` confirms that the instance is yours. It creates test files and deletes them afterwards, locks one of them, and uses up the client's create budget.

## 7. M7: Accounts

Accounts were added in M7 (D026 to D031) and tested on 2026-11-07 on the Compose stack, with the black-box checks `accounts`, `totp` and `account-files` and the browser check for accounts. The threat model lists what they cover. The independent review of M7 found F38 to F40, an adversarial verification of their fixes found F41 to F45, and fixing F43 turned up F46 ([FINDINGS.md](FINDINGS.md)); the runs below are on the code with all of them fixed.

| Run at the end of M7 | Result |
|---|---|
| `scripts/blackbox.py`, Compose stack | 170 passed ([`blackbox-m7.txt`](evidence/blackbox-m7.txt)) |
| `scripts/browser_checks.cjs` | 30 passed ([`browser-checks-m7.txt`](evidence/browser-checks-m7.txt)) |
| End-to-end tests, disk and S3 | 6 passed on each; the bucket empty afterwards |
| Go tests with `-race` | 143 passed |
| Vitest | 107 passed |

| WSTG | Test | Result | Evidence |
|---|---|---|---|
| SESS-02 | The cookies set at sign-up | Both `__Host-`, Secure, HttpOnly, SameSite=Strict, for the whole origin and without a Domain; the session lasts a day. Scripts on the page see no cookie | `accounts`, [`browser-checks-m7.txt`](evidence/browser-checks-m7.txt) |
| SESS-03 | A sign-in while the browser holds a valid session | A new token; the old one gets 401 | `accounts` |
| SESS-05 | Sign-in, sign-out and every account request marked cross-site, same-site or from another Origin | 403 `cross_origin`, no cookie set, nothing changed (D028) | `accounts`, `TestCrossSiteRequestsCannotUseTheSession` |
| SESS-06 | Sign-out | 204 and the cookie cleared; the token gets 401 afterwards, also when the client hangs up at once (`TestSignOutFinishesAfterHangUp`) | `accounts`, Go tests |
| SESS-07 | Idle and absolute timeouts | An hour without use or a day after sign-in ends a session (`TestSessionTimeouts`, `TestSessionsEndADayAfterSignIn`) | Go tests |
| IDNT-04 | Salt lookups and sign-ins for usernames without an account | A stable 16-byte salt; the same 401 body as a wrong password. Sign-up still tells a taken name, which D027 accepts | `accounts` |
| ATHN-03 | Five failed sign-ins from one client; twenty from many; a browser that signed in before | 429 `locked` with `Retry-After: 900` for that username only; unknown browsers locked, the owner's browser not (`TestLoginLockouts`); an attempt refused only because others are in flight gets 503 `busy` (`TestAttemptsInFlightAnswerBusy`) | `accounts`, Go tests |
| ATHN-07 | Account password policy | 15 code points after NFKC normalization, checked in the browser, the only place that sees the password | Vitest |
| ATHN-09 | Password change | Asks for the current password, and a code while TOTP is on; ends the other sessions in the same transaction, also when the client hangs up (`TestChangesEndOtherSessionsAfterHangUp`) | `accounts`, `TestChangesNeedTheCodeWhileTOTPIsOn` |
| | Second step: a used code, a used ticket, a recovery code used twice, five failures, a ticket from before a password or TOTP change | Each refused; the second step locks after five | `totp`, Go tests |
| ATHZ-02 | Keeping a file without its owner token, or without a session; listing without a session | 404, 401, 401 | `account-files` |
| CRYP-04 | Account key derivation | Pinned vectors, computed with hash-wasm and WebCrypto and again with Go's x/crypto/argon2 and standard library | Vitest |
| | Every request during sign-up, a shared file and My files, in Chromium | None carries the password, the master, wrapping or account key, the share secret or the file name; local storage holds only the sealed account key | [`browser-checks-m7.txt`](evidence/browser-checks-m7.txt), [`my-files.png`](evidence/my-files.png) |
| | What the database keeps for an account | The browser's salt and sealed key, an Argon2id hash in PHC form, the SHA-256 of the session token; no auth secret, no token | [`database-m7.txt`](evidence/database-m7.txt) |
| | The vaultd log after all of the above | Paths only: no secret, cookie, username or hash | [`logs-m7.txt`](evidence/logs-m7.txt) |

## Evidence

| File | Content |
|---|---|
| [`blackbox-before.txt`](evidence/blackbox-before.txt), [`blackbox-after.txt`](evidence/blackbox-after.txt) | Black-box checks on the Compose stack before the first fixes, and after all fixes with the tightened checks |
| [`blackbox-direct.txt`](evidence/blackbox-direct.txt) | Black-box checks on vaultd without Caddy |
| [`browser-checks.txt`](evidence/browser-checks.txt) | Browser checks after the fixes |
| [`cross-site.txt`](evidence/cross-site.txt) | F18 and F24, from the server log and the browser's network log |
| [`timeouts.txt`](evidence/timeouts.txt) | F19 and F23 measurements |
| [`tls.txt`](evidence/tls.txt), [`probes.txt`](evidence/probes.txt) | TLS enumeration; raw framing and Host probes |
| [`containers.txt`](evidence/containers.txt), [`database.txt`](evidence/database.txt), [`logs.txt`](evidence/logs.txt) | Container privileges and data permissions; what the database holds; log contents |
| [`go-test.txt`](evidence/go-test.txt), [`go-scan.txt`](evidence/go-scan.txt), [`web-test.txt`](evidence/web-test.txt), [`semgrep.txt`](evidence/semgrep.txt), [`caddy-govulncheck.txt`](evidence/caddy-govulncheck.txt) | Test and scanner output |
| [`zap-baseline.png`](evidence/zap-baseline.png), [`zap-report.html`](evidence/zap-report.html) | ZAP baseline from the CI run on the fixed code |
| [`blackbox-m7.txt`](evidence/blackbox-m7.txt), [`browser-checks-m7.txt`](evidence/browser-checks-m7.txt), [`database-m7.txt`](evidence/database-m7.txt), [`logs-m7.txt`](evidence/logs-m7.txt), [`my-files.png`](evidence/my-files.png) | Section 7: accounts |
| [`file-name-as-text.png`](evidence/file-name-as-text.png), [`link-after-burn.png`](evidence/link-after-burn.png), [`password-wrong.png`](evidence/password-wrong.png), [`password-minimum.png`](evidence/password-minimum.png), [`framing-refused.png`](evidence/framing-refused.png) | Screenshots |
