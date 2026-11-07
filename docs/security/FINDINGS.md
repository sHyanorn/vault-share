# Security Findings

Issues found during development, how they were found and how they were fixed. Severity follows the impact on the threat model.

| ID | Date | Severity | Found by | Summary | Status |
|---|---|---|---|---|---|
| F1 | 2026-11-06 | High | Independent review of M2 | Orphaned ciphertext blobs let anonymous uploaders fill the disk | Fixed |
| F2 | 2026-11-06 | High | Independent review of M2 | Concurrent uploads with the owner token could replace or delete acknowledged content | Fixed |
| F3 | 2026-11-06 | High | Independent review of M2 | Uploads longer than 60 s were stored but never acknowledged, inviting retries | Fixed |
| F4 | 2026-11-06 | Medium | Independent review of M2 | A granted download could be purged between token use and content open | Fixed |
| F5 | 2026-11-06 | Medium | Independent review of M2 | Socket deadlines computed from the test clock made the suite time dependent | Fixed |
| F6 | 2026-11-06 | Low | Independent review of M2 | Validation order of the download endpoint distinguished live files from missing ones | Fixed |
| F7 | 2026-11-06 | Low | Independent review of M2 | Storage failures during upload were reported as client errors and not logged | Fixed |
| F8 | 2026-11-06 | Low | Independent review of M2 | Anyone holding a file id could evict pending challenges through the per-file cap | Fixed |
| F9 | 2026-11-06 | Low | Independent review of M2 | A file expiring while a download token was pending was purged under the recipient | Fixed |
| F10 | 2026-11-06 | Low | Independent review of M3 | Bidi override characters in a file name spoofed the extension shown on the download page | Fixed |
| F11 | 2026-11-06 | Low | Independent review of M3 | The uploader's MIME type became the type of the decrypted Blob | Fixed |
| F12 | 2026-11-06 | Medium | Independent review of M4 | Rate limits and lockouts counted every IPv6 address separately, so one client could rotate through its /64 | Fixed |
| F13 | 2026-11-06 | Medium | Independent review of M4 | Limiter and lockout tables grew without bound and rescanned on every insert past 10,000 keys | Fixed |
| F14 | 2026-11-06 | Low | Independent review of M4 | A trusted proxy without a usable X-Forwarded-For silently merged every client into one bucket | Fixed |
| F15 | 2026-11-06 | Medium | Adversarial verification of F12 to F14 | Only the first X-Forwarded-For line was read, so behind a proxy that appends a line the client chose its own address | Fixed |
| F16 | 2026-11-06 | Medium | Adversarial verification of F12 to F14 | Failed download authentications from many addresses wrote audit rows with no global bound | Fixed |
| F17 | 2026-11-06 | Medium | Adversarial verification of F15 and F16 | File creation had no global bound, so many addresses could fill the disk and push the audit history out | Fixed |
| F18 | 2026-11-06 | Medium | OWASP Top 10 self-assessment (M5) | A page on another site could create files through its visitors' browsers | Fixed |
| F19 | 2026-11-06 | Low | OWASP Top 10 self-assessment (M5) | Caddy held slow and idle connections longer than vaultd | Fixed |
| F20 | 2026-11-06 | Low | OWASP Top 10 self-assessment (M5) | The database holds the keys that pass the download check, which the docs denied | Fixed (documentation) |
| F21 | 2026-11-06 | Low | OWASP Top 10 self-assessment (M5) | Password protection accepted passwords of any length | Fixed |
| F22 | 2026-11-06 | Info | OWASP Top 10 self-assessment (M5) | The pinned Caddy release carries modules with published advisories | Accepted |
| F23 | 2026-11-06 | Low | Independent review of M5 | Caddy's HTTP redirect server kept the default timeouts after F19 | Fixed |
| F24 | 2026-11-06 | Low | Independent review of M5 | Cross-site reads through visitors' browsers could keep their request budget empty | Fixed |
| F25 | 2026-11-06 | Low | Independent review of M5 | The API answered any Host, so a rebound name reached a directly exposed vaultd as same-origin | Fixed |
| F26 | 2026-11-07 | High | Independent review of M6 | Concurrent uploads to one file held memory on S3 and temp files on disk outside the quota | Fixed |
| F27 | 2026-11-07 | Medium | Independent review of M6 | Burned, expired or deleted ciphertext could stay in the bucket for good | Fixed |
| F28 | 2026-11-07 | Medium | Independent review of M6 | S3 requests had no time limit, so a silent service stopped the cleanup job | Fixed |
| F29 | 2026-11-07 | Medium | Independent review of M6 | An upload could fail with its object stored, and the object outlived its record | Fixed |
| F30 | 2026-11-07 | Medium | Independent review of M6 | Stored content stayed unchanged only if the S3 service honoured If-None-Match, which nothing checked | Fixed |
| F31 | 2026-11-07 | Low | Independent review of M6 | A versioned bucket kept deleted ciphertext as old versions | Fixed |
| F32 | 2026-11-07 | Low | Independent review of M6 | A made-up download token cost an S3 GET before it was refused | Fixed |
| F33 | 2026-11-07 | Medium | Adversarial verification of F26 to F32 | Deleting or purging a file mid-upload released its quota charge while its bytes kept arriving | Fixed |
| F34 | 2026-11-07 | Low | Adversarial verification of F26 to F32 | A client that hung up right after its last byte left a stored object behind a failed upload | Fixed |
| F35 | 2026-11-07 | Low | Adversarial verification of F26 to F32 | An S3 service that stopped reading mid-upload held the request and its file for good | Fixed |

## F1 Orphaned ciphertext blobs (High)
- Impact: the upload handler published the blob before marking the record. When the record had been deleted or purged meanwhile, the blob stayed on disk with no record pointing to it, outside every cleanup rule. Each repetition leaked up to the file size limit, invisible to the database and to any future quota.
- Fix: the handler removes its blob when the record is gone, and the cleanup job deletes never-uploaded records only while they are still pending, so a completed upload is never purged under its own acknowledgement.

## F2 Concurrent uploads replaced acknowledged content (High)
- Impact: a second PUT with the same owner token overwrote the stored blob, and a bad body on a late PUT deleted the blob of the earlier successful one. Retrying clients, which F3 produced, could lose the file.
- Fix: the disk store links the finished upload into place and refuses an existing name, and refuses any byte count other than the declared size; the handler never deletes a published blob on a bad body.

## F3 Long uploads were stored but not acknowledged (High)
- Impact: only the read deadline was extended for large bodies; the server's 60-second write timeout cut the connection before the 204 reached the client, who then retried into F2.
- Fix: both deadlines are extended for the transfer and computed from the wall clock.

## F4 Granted download lost to a purge (Medium)
- Impact: the token was consumed before the content was opened, so a cleanup tick in that window could delete the file; the download count was already taken.
- Fix: the content is opened first, and the last permitted download removes the record only when no other token is pending.

## F5 Time-dependent test suite (Medium)
- Impact: deadlines derived from the fake clock would start failing the API tests once real time passed the pinned date.
- Fix: deadlines use the wall clock; the fake clock covers business time only.

## F6 Validation order revealed liveness (Low)
- Impact: a malformed download request answered 404 for missing files and 400 for live ones.
- Fix: the body is validated before the file is looked up; a bad body answers 400 either way.

## F7 Storage failures reported as client errors (Low)
- Impact: a full disk or broken storage path produced a silent 400.
- Fix: body failures stay 400; everything else answers 500 and is logged.

## F8 Evictable challenges (Low)
- Impact: challenges lived in a table capped at 16 per file, so sixteen metadata requests by anyone holding the id evicted a victim's pending challenge.
- Fix: challenges are stateless: expiry, nonce and an HMAC tag under a key drawn at startup. No table, no cap, nothing to evict. A replay only spends the holder's own download count.

## F9 Expiry ignored pending tokens (Low)
- Impact: a token issued shortly before expiry answered 404 after the next cleanup although the count was taken.
- Fix: expired files are kept until their pending tokens pass.

## F10 File name spoofing through format characters (Low)
- Impact: `safeFileName` removed control characters only. A name such as `invoice\u202Efdp.exe` rendered as `invoiceexe.pdf` on the download page, so the recipient decided to download a program believing it was a document. The browser sanitised the name on disk, so the saved file was honest; the deception was in the decision. This is threat model attacker A5.
- Fix: invisible format characters are stripped before display and download, except the joiner that emoji sequences need, and the length cap counts code points so a surrogate pair is never split.

## F11 Uploader-controlled MIME type in the decrypted Blob (Low)
- Impact: the Blob handed to the browser carried the uploader's declared type, `text/html` included. The `download` attribute kept browsers from rendering it, so there was no exploit, but a same-origin `blob:` URL of `text/html` is executable in the application origin if it is ever navigated to.
- Fix: the Blob is always `application/octet-stream`; the type is no longer passed through.


## F12 IPv6 clients bypassed rate limits and lockouts (Medium)
- Impact: buckets and lockouts were keyed by the full address. A home or mobile IPv6 connection holds at least a /64, 2^64 addresses, so one client rotated through fresh buckets at will: twelve creates from twelve addresses of one /64 got eleven successes against a burst of ten. Zoned literals from a trusted proxy (`fe80::1%eth0`, `%eth1`) also counted as distinct clients.
- Fix: zones are dropped, and rate limits and lockouts key one IPv4 address or one IPv6 /64; NAT64 and Teredo addresses, whose /64 spans many IPv4 clients, key the embedded IPv4 client. The audit log keeps the full address, hashed (D018), which a test pins.

## F13 Unbounded limiter tables (Medium)
- Impact: the tables swept only when inserting past 10,000 entries and only freed entries idle for 30 minutes, so a stream of fresh keys freed nothing and rescanned the whole table under the table's lock on every insert: 148 µs per insert at 20,000 keys, an 80,000-key run did not finish in ten minutes, and memory grew at about 180 bytes per key. Combined with F12 this was a memory and CPU denial of service at a few hundred requests per second.
- Fix: a sweep runs at most once a minute and rebuilds the map, so the storage eviction churn leaves behind is released (Go maps never shrink); a table never exceeds 50,000 entries, an arbitrary entry is evicted to make room. Tests insert 150,000 fresh keys into each table with a moving clock and fail as soon as the cap is exceeded or the inserts pass ten seconds. Adversarial verification measured 36,830 requests per second with fresh keys after the fix against 1,247 before, with flat memory.

## F14 Silent collapse behind a misconfigured proxy (Low)
- Impact: when a trusted proxy sent no usable `X-Forwarded-For`, every client got the proxy's address. The whole service then shared one bucket, and five bad signatures from anyone locked everyone out of a file. The shipped Compose file could reach this on an IPv6-enabled network, which it did not trust.
- Fix: vaultd logs a warning, at most once a minute on the monotonic clock and without addresses, when a trusted proxy names no client on an API request; Compose also trusts the unique local IPv6 range `fd00::/8`; IPv4-mapped and zoned entries in `VAULT_TRUSTED_PROXIES` are normalised so they match. D017 states that clients behind one address share their limits and that a proxy missing from the list still collapses its clients silently.

## F15 First X-Forwarded-For line read (Medium)
- Impact: `Header.Get` returns the first header line, but proxies such as HAProxy with `option forwardfor` pass the client's lines through and append their own. The first line was therefore the client's claim: through HAProxy one client got 40 of 40 creates against a burst of 10, escaped its own lockout, and locked a victim out of a file with five bad signatures sent in the victim's name. The shipped Caddy always replaces the header with a single line, so the shipped deployment was not affected. Present since the first M4 commit.
- Fix: the last entry of the last line counts. Tests cover a spoofed first line, a garbage first line and a rotating first line against the create limit.

## F16 Unbounded audit writes (Medium)
- Impact: every failed download authentication wrote an audit row. Per client that is bounded by the download budget and the lockout, but an attacker with an IPv6 /48 holds 65,536 /64s: a 60-second flood wrote 339,321 rows, about 50 MB, kept for 30 days. Mass file creation from many addresses grew the table the same way.
- Fix: the audit table is capped at 1,000,000 rows, trimmed oldest first every minute; failure events share a process-wide budget of one per second with a burst of 60 so they cannot push the other events out. Skipped and dropped entries are logged as counts. The CPU saturation the same flood causes is a residual risk in the threat model.

## F17 No global bound on file creation (Medium)
- Impact: creation was limited per client only. With distinct /64s a flood created about 308,000 records a minute without a single 429: the audit table reached its 1,000,000-row cap in 3.2 minutes, which cut its 30-day retention to minutes and let an uploader push out its own earlier entries, and vault.db grew to 404 MB in under four minutes, bounded only by the disk.
- Fix: a global storage quota (`VAULT_MAX_TOTAL_BYTES`, default 20 GiB) charges every record its size, its metadata and 64 KiB of overhead, enforced in the same statement as the insert; a per-client budget of 4 GiB a day stops one client from holding the quota. Tests cover the quota under 32 concurrent creates, the release on every delete path, the backfill of existing records, the budget, and its refund when the quota refuses a create.
- Design change from the proposal: a global cap of 1,000 records awaiting content was proposed and dropped, see D021. The availability trade-off is also larger than first stated: a group of clients with upload bandwidth can keep uploads unavailable for up to seven days, not one hour, which the threat model lists as a residual risk.

## F18 Cross-site creates through visitors' browsers (Medium)
- Impact: `POST /api/v1/files` accepted any content type from any origin. A page on another site can send it as a simple request, which browsers send without a CORS preflight; the page cannot read the answer, but the record is created. Each visitor is a separate client (D017), so the page turns its visitors into the group of clients of D021: a new visitor reserves up to 4 GiB for the hour a record may wait for its content, about five new visitors an hour keep the default 20 GiB quota full, and each visitor loses their own budget for the day while the audit log attributes the creates to them. Reproduced in Chromium from another origin: the page saw a network error, vaultd logged 201. Nothing was exposed: the page reads no response and never gets an owner token.
- Fix: Go's `http.CrossOriginProtection` wraps the API ahead of the rate limiter (D022). It refuses writes whose `Sec-Fetch-Site` is neither `same-origin` nor `none` and, from browsers without that header, writes whose `Origin` host differs from `Host`; requests without either header, such as scripts, pass. Refusals answer 403 `cross_origin`. A test covers each case, the write endpoints with valid credentials and the unaffected read; the black-box and browser checks repeat it against the Compose stack.

## F19 Slow connections held longer at Caddy (Low)
- Impact: Caddy closed a connection whose headers never finished after 60 s and kept idle keep-alive connections for 5 minutes, against 10 s and 2 minutes in vaultd, so holding connections open at the TLS front took a sixth of the effort it took against vaultd.
- Fix: the Caddyfile sets `read_header 10s` and `idle 2m`; measured afterwards at 10 s and 120 s. Bodies and responses keep no fixed deadline at Caddy, because vaultd gives each transfer one from its size (F3).

## F20 Download keys in the database (Low)
- Impact: SPEC section 4 said the server stores only a verifier of `authKey`, and the threat model said a database leak exposes no keys. The stored value is the HMAC key itself, as in Firefox Send, so whoever copies the database can sign challenges for every live file: fetch the ciphertexts and spend the download counts until the shares burn. Decryption still needs the secret in the link.
- Fix: the SPEC and the threat model say so. An asymmetric verifier would close the gap but changes the protocol, which is out of scope.

## F21 No minimum password length (Low)
- Impact: a link holder guesses offline at Argon2id cost per guess and no lockout applies (D019), so a four-digit password fell in seconds.
- Fix: the upload form requires 8 characters and wrapping refuses shorter passwords, counted in code points. Unwrapping accepts any length so earlier links still open, which a fixture test pins. The server never sees the password, so the rule lives in the client.

## F22 Advisories in the pinned Caddy (Info)
- Impact: govulncheck in binary mode reports GO-2026-6866 and GO-2026-6860 (`golang.org/x/net/html`), GO-2026-6865 (`klauspost/compress`) and GO-2026-5932 (`golang.org/x/crypto/openpgp`) in the Caddy 2.11.9 binary. The Caddyfile enables none of the handlers that use these packages (templates, Markdown, response compression), though binary mode cannot prove that no path reaches them.
- Status: accepted until upstream ships a fixed release; 2.11.9 is the latest, and Dependabot proposes the next image.

## F23 HTTP redirect server kept Caddy's defaults (Low)
- Impact: the timeouts of F19 went into the `servers` options of the Caddyfile, but Caddy builds its HTTP to HTTPS redirect server itself, after the Caddyfile is adapted and without those options. Port 80 still closed unfinished headers only after 60 s. The F19 check had probed port 443 only.
- Fix: an explicit HTTP site in the Caddyfile issues the same redirect, so the adapted configuration holds both servers with `read_header 10s` and `idle 2m`; measured afterwards at 10 s on both ports. The black-box slow-header check now probes the HTTP origin too.

## F24 Cross-site reads spent the visitor's budget (Low)
- Impact: F18's fix refused cross-origin writes only. A page on another site could still make its visitors' browsers send reads. The page never sees the answers, but every read counts against the visitor's request budget (D017), so two a second keep that budget empty while the page is open.
- Fix: every API request that Fetch Metadata marks `cross-site` or `same-site` is refused with 403 before the rate limiter (D022). A test sends ten cross-site reads against a budget of three and checks that the client's own three requests still pass.

## F25 Any Host reached the API (Low)
- Impact: vaultd answered whatever Host a request named. A page that rebinds its own name to a directly reachable vaultd, such as a developer's local instance, is same-origin to the browser, so F18's protection let its writes through. The shipped Compose stack was not affected, because Caddy forwards only its own site name.
- Fix: the API answers 421 `misdirected` unless the Host, compared without port and case, is the host of `VAULT_BASE_URL` (D022). The health check and the web client still answer any name.

## F26 Concurrent uploads to one file (High)
- Impact: nothing stopped a file's owner from running many uploads at once. The S3 store buffered each one in memory, up to 8 MiB, so 40 uploads to one record took vaultd from 18 to 341 MiB, and a client opening uploads at the rate limit could reach tens of GiB within the 35 minutes a 1 GiB upload may last. The disk store wrote a temp file per upload: six uploads to one 64 MiB record held 360 MiB, beyond the quota, which counts records only.
- Fix: a file takes one upload at a time and a second gets 409 while the first is in flight. The S3 store streams the body into a single PutObject without buffering, which caps files on S3 at 5 GiB (D025). Measured afterwards: ten uploads to ten records, 60 MiB sent on each, moved vaultd from 19 to 20 MiB; six uploads to one record held one 60 MiB temp file while the other five got 409.

## F27 Deleted ciphertext could stay in the bucket (Medium)
- Impact: the S3 store held back a Delete while the object was being read, ran it when the last reader closed and dropped its error. A failed delete, or vaultd stopping during a last download, left the object with no record and no rule that would ever remove it. The review left a 40 MiB object behind by stopping vaultd mid-download, and injected 503 errors went unlogged. Burn after reading, expiry and the owner's delete could fail silently, and the bytes escaped the quota. The disk store had a smaller gap: burning deletes the record first, so a failed file deletion was logged and then forgotten.
- Fix: the S3 store deletes at once and returns the error. A download in progress still gets every byte, which the store contract checks on Versity S3 Gateway and RustFS; AWS documents that updates to a key are atomic and a concurrent reader never gets partial data. Cleanup also lists the stored ids once an hour and deletes any without a record; its first run against the review's bucket removed the 40 MiB object.

## F28 No time limit on S3 requests (Medium)
- Impact: the SDK's HTTP client waited for a response forever. Against a service that accepted connections and never answered, calls hung, and because the cleanup job ran without a deadline, one stalled call stopped it for good: expired files stayed, download tokens never expired and the audit log was no longer trimmed.
- Fix: responses time out after a minute, as in minio-go's default transport, and each cleanup run gets five intervals. Upload and download bodies stream at the client's pace, and a client that goes away cancels its request. Tests cover a silent service and a store whose listing never returns.

## F29 A failed upload with its object stored (Medium)
- Impact: when the response to a write was lost, the SDK retried it, the retry got 412 because the first attempt had stored the object, and vaultd reported a conflict for its own upload. A client hanging up just after the object was stored had the same effect. The record never completed, and an hour later cleanup removed it but not the object.
- Fix: a streamed body cannot be sent twice, so writes are no longer retried; once the content is stored, the record is marked even if the client has gone; and cleanup deletes content left without a record (F27). A lost response still fails the upload, which the user sees, and nothing is left behind.

## F30 Unchecked conditional writes (Medium)
- Impact: the S3 store relied on `If-None-Match: *` to keep content from being replaced. On a service that ignores the header, two uploads to one file could both succeed, and the request that lost the race then deleted the content the winner had been told was stored, which is F2 again.
- Fix: one upload at a time per file (F26) keeps vaultd from sending concurrent writes for a file. At startup vaultd also writes a probe object twice and refuses to start unless the second write gets 412.

## F31 Versioned buckets kept deleted files (Low)
- Impact: with bucket versioning on, a delete only adds a marker, so every burned, expired or deleted file stayed in the bucket as an old version, open to anyone who can read the bucket and holds the link.
- Fix: vaultd refuses to start on a bucket whose versioning is enabled or suspended; a service without the versioning API passes.

## F32 S3 GET before the token check (Low)
- Impact: the content endpoint opened the object before it checked the download token, so each request with a made-up token for a known file id made vaultd fetch from S3, which costs requests and egress.
- Fix: the token is checked first, then the object is opened, then the token is consumed, so F4 stays fixed.

## F33 Deletes during an upload released its quota (Medium)
- Impact: the quota charge belongs to the record, while F26's one-upload rule only covered the upload. An owner delete, or the purge of a record that had waited an hour for its content, released the charge while that record's body kept arriving. Six rounds of creating a 64 MiB record, sending 60 MiB and deleting it held 360 MiB of temp files against a 128 MiB quota, which still accepted a new 64 MiB record. The same purge cut legitimate uploads short once `VAULT_MAX_FILE_BYTES` exceeded about 1.7 GiB, the most that 512 KiB/s moves in an hour.
- Fix: uploads, owner deletes and cleanup claim the file first (D025). A delete during an upload answers 409, cleanup leaves the file for a later run, and the upload reads its record again under the claim. Measured afterwards: the delete got 409 and the next 64 MiB create was refused for lack of quota.

## F34 Hang-up after the last byte (Low)
- Impact: an HTTP/1.1 server notices that a client has gone only after the body has been read, so the cancellation of F29's case landed during the S3 request: Put failed with the object stored, the record stayed unmarked, a retry got 409 and the share could never complete. Each such hang-up also wrote an ERROR line. Cleanup removed both after an hour.
- Fix: the caller's context governs only the body, which is checked before its last bytes go out; the request then runs to its answer. Measured afterwards: eight hang-ups after the last byte gave eight completed shares and no error lines.

## F35 Stalled writes to S3 (Low)
- Impact: F28's response timeout starts only once a body has been sent, and the transport had no write timeout, so a service that stopped reading mid-upload held the request, and with F33 the file's claim, for good. The file answered 409 and cleanup skipped it.
- Fix: each write to the service has a minute, through a connection wrapper like the one the SDK uses for read timeouts; reads keep no deadline, so slow downloads are unaffected. A test against a service that reads nothing fails the upload in a fraction of a second, where it hung before.
