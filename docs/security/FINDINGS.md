# Security Findings

Issues found during development, how they were found and how they were fixed. Those not fixed are marked Accepted or Open. Severity follows the impact on the threat model.

| ID | Date | Severity | Found by | Summary | Status |
|---|---|---|---|---|---|
| F1 | 2026-11-06 | High | Review of M2 | Orphaned ciphertext blobs let anonymous uploaders fill the disk | Fixed |
| F2 | 2026-11-06 | High | Review of M2 | Concurrent uploads with the owner token could replace or delete acknowledged content | Fixed |
| F3 | 2026-11-06 | High | Review of M2 | Uploads longer than 60 s were stored but never acknowledged, inviting retries | Fixed |
| F4 | 2026-11-06 | Medium | Review of M2 | A granted download could be purged between token use and content open | Fixed |
| F5 | 2026-11-06 | Medium | Review of M2 | Socket deadlines computed from the test clock made the suite time dependent | Fixed |
| F6 | 2026-11-06 | Low | Review of M2 | Validation order of the download endpoint distinguished live files from missing ones | Fixed |
| F7 | 2026-11-06 | Low | Review of M2 | Storage failures during upload were reported as client errors and not logged | Fixed |
| F8 | 2026-11-06 | Low | Review of M2 | Anyone holding a file id could evict pending challenges through the per-file cap | Fixed |
| F9 | 2026-11-06 | Low | Review of M2 | A file expiring while a download token was pending was purged under the recipient | Fixed |
| F10 | 2026-11-06 | Low | Review of M3 | Bidi override characters in a file name spoofed the extension shown on the download page | Fixed |
| F11 | 2026-11-06 | Low | Review of M3 | The uploader's MIME type became the type of the decrypted Blob | Fixed |
| F12 | 2026-11-06 | Medium | Review of M4 | Rate limits and lockouts counted every IPv6 address separately, so one client could rotate through its /64 | Fixed |
| F13 | 2026-11-06 | Medium | Review of M4 | Limiter and lockout tables grew without bound and rescanned on every insert past 10,000 keys | Fixed |
| F14 | 2026-11-06 | Low | Review of M4 | A trusted proxy without a usable X-Forwarded-For silently merged every client into one bucket | Fixed |
| F15 | 2026-11-06 | Medium | Adversarial verification of F12 to F14 | Only the first X-Forwarded-For line was read, so behind a proxy that appends a line the client chose its own address | Fixed |
| F16 | 2026-11-06 | Medium | Adversarial verification of F12 to F14 | Failed download authentications from many addresses wrote audit rows with no global bound | Fixed |
| F17 | 2026-11-06 | Medium | Adversarial verification of F15 and F16 | File creation had no global bound, so many addresses could fill the disk and push the audit history out | Fixed |
| F18 | 2026-11-06 | Medium | OWASP Top 10 self-assessment (M5) | A page on another site could create files through its visitors' browsers | Fixed |
| F19 | 2026-11-06 | Low | OWASP Top 10 self-assessment (M5) | Caddy held slow and idle connections longer than vaultd | Fixed |
| F20 | 2026-11-06 | Low | OWASP Top 10 self-assessment (M5) | The database holds the keys that pass the download check, which the docs denied | Fixed (documentation) |
| F21 | 2026-11-06 | Low | OWASP Top 10 self-assessment (M5) | Password protection accepted passwords of any length | Fixed |
| F22 | 2026-11-06 | Info | OWASP Top 10 self-assessment (M5) | The pinned Caddy release carries modules with published advisories | Accepted |
| F23 | 2026-11-06 | Low | Review of M5 | Caddy's HTTP redirect server kept the default timeouts after F19 | Fixed |
| F24 | 2026-11-06 | Low | Review of M5 | Cross-site reads through visitors' browsers could keep their request budget empty | Fixed |
| F25 | 2026-11-06 | Low | Review of M5 | The API answered any Host, so a rebound name reached a directly exposed vaultd as same-origin | Fixed |
| F26 | 2026-11-07 | High | Review of M6 | Concurrent uploads to one file held memory on S3 and temp files on disk outside the quota | Fixed |
| F27 | 2026-11-07 | Medium | Review of M6 | Burned, expired or deleted ciphertext could stay in the bucket for good | Fixed |
| F28 | 2026-11-07 | Medium | Review of M6 | S3 requests had no time limit, so a silent service stopped the cleanup job | Fixed |
| F29 | 2026-11-07 | Medium | Review of M6 | An upload could fail with its object stored, and the object outlived its record | Fixed |
| F30 | 2026-11-07 | Medium | Review of M6 | Stored content stayed unchanged only if the S3 service honoured If-None-Match, which nothing checked | Fixed |
| F31 | 2026-11-07 | Low | Review of M6 | A versioned bucket kept deleted ciphertext as old versions | Fixed |
| F32 | 2026-11-07 | Low | Review of M6 | A made-up download token cost an S3 GET before it was refused | Fixed |
| F33 | 2026-11-07 | Medium | Adversarial verification of F26 to F32 | Deleting or purging a file mid-upload released its quota charge while its bytes kept arriving | Fixed |
| F34 | 2026-11-07 | Low | Adversarial verification of F26 to F32 | A client that hung up right after its last byte left a stored object behind a failed upload | Fixed |
| F35 | 2026-11-07 | Low | Adversarial verification of F26 to F32 | An S3 service that stopped reading mid-upload held the request and its file for good | Fixed |
| F36 | 2026-11-07 | Low | Simplification review | A file size limit near the int64 maximum overflowed the quota arithmetic and disabled the quota | Fixed |
| F37 | 2026-11-07 | Low | Simplification review | A leading space let a file name keep its leading dots, and a joiner-only name displayed as blank | Fixed |
| F38 | 2026-11-07 | Medium | Review of M7 | Second-step codes sent at once escaped the ticket's and the account's attempt limits | Fixed |
| F39 | 2026-11-07 | Low | Review of M7 | Sign-ins and download signatures sent at once escaped their lockouts | Fixed |
| F40 | 2026-11-07 | Info | Review of M7 | Sign-in and second-step failures joined the audit log's shared failure budget | Accepted |
| F41 | 2026-11-07 | Low | Adversarial verification of F38 and F39 | A second step could spend its ticket and code without opening a session | Fixed |
| F42 | 2026-11-07 | Low | Adversarial verification of F38 and F39 | Attempts refused only because others were in flight were answered as a 15-minute lockout | Fixed |
| F43 | 2026-11-07 | Low | Adversarial verification of F38 and F39 | A ticket issued before a password or TOTP change could still complete the sign-in | Fixed |
| F44 | 2026-11-07 | Info | Adversarial verification of F38 and F39 | Evicting a lockout entry forgot its attempts in flight, and attempts that passed left entries behind | Fixed |
| F45 | 2026-11-07 | Info | Adversarial verification of F38 and F39 | A client that hung up after the code check left its failed second step uncounted | Fixed |
| F46 | 2026-11-07 | Low | Fixing F43 | A password or TOTP change could leave the account's other sessions alive, and a sign-out its own session | Fixed |
| F47 | 2026-11-10 | High | Production readiness review | A new database over existing storage made cleanup delete all stored content | Fixed |
| F48 | 2026-11-10 | Medium | Production readiness review | A download granted while an earlier one was redeemed could get a 500 and lose the file | Fixed |
| F49 | 2026-11-10 | Medium | Production readiness review | A missing `account.key` was replaced without notice, breaking two-factor sign-in for existing accounts | Fixed |
| F50 | 2026-11-10 | Info | Production readiness review | The health check answered ok with the database, the storage or the disk unusable | Fixed |
| F51 | 2026-11-10 | Low | Code review | A base URL without a host name turned the Host check off | Fixed |
| F52 | 2026-11-10 | Low | Code review | Valid downloads arriving together from one address can be told the file is gone | Open |
| F53 | 2026-11-10 | Info | Code review | An opened password field left empty shares without a password under a hint that asks for one | Open |
| F54 | 2026-11-10 | Info | Code review | A late answer from an ended session can sign a new session out in the browser | Open |
| F55 | 2026-11-10 | Info | Code review | A session that ends during an upload leaves the file shared but out of My files | Open |
| F56 | 2026-11-14 | Medium | Code review | Anyone who knew the password could lock the owner out of the second step and every change, known browsers included | Fixed |
| F57 | 2026-11-14 | Low | Code review | Device cookies outlived a password change and could be minted without bound | Fixed |
| F58 | 2026-11-14 | Low | Code review | A last download that overlapped an earlier one left the burned file stored until the next cleanup | Fixed |
| F59 | 2026-11-14 | Low | Code review | A code that confirmed a password change, TOTP switch-off or deletion was spent even when the change failed | Fixed |
| F60 | 2026-11-14 | Low | Code review | A new account could take the id, and with it the audit trail, of a deleted one | Fixed |
| F61 | 2026-11-14 | Low | Code review | Four security checks could not fail for the reason they gave | Fixed |
| F62 | 2026-11-14 | Info | Code review | The threat model overstated what an offline guess at an account password costs | Fixed (documentation) |
| F63 | 2026-11-14 | Info | Code review | The metadata's length gave the server the length of the file name | Fixed |
| F64 | 2026-11-14 | Low | Code review | Sign-ups from many addresses can fill the account cap for good | Accepted |
| F65 | 2026-11-14 | Info | Code review | A link whose # arrived as %23 put its key in the request log | Fixed |
| F66 | 2026-11-14 | Info | Code review | Codes sent with account changes had no length check | Fixed |
| F67 | 2026-11-14 | Info | Code review | JSON bodies were accepted with data after the value | Fixed |
| F68 | 2026-11-14 | Low | Code review | A download that failed at Caddy left its token in Caddy's error log | Fixed |

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

## F36 Quota overflow from an unbounded size limit (Low)
- Impact: with disk storage `VAULT_MAX_FILE_BYTES` had no upper bound. An operator who set it to the int64 maximum to mean "no limit" made `MaxFileBytes+1 MiB` wrap negative, so any `VAULT_MAX_TOTAL_BYTES` passed, and the router's burst check wrapped too. A client could then declare a size near the maximum: its charge wrapped negative, the per-client budget and the global quota both accepted it, and usage went negative, which disabled the quota (F17) for the hour the record waited for content. Needs an absurd but plausible setting; S3 was capped at 5 GiB.
- Fix: `VAULT_MAX_FILE_BYTES` is at most 1 TiB and `VAULT_MAX_TOTAL_BYTES` at most 1 PiB, so no sum built on them comes near the limit. Tests load the int64 maximum for each and expect a refusal; they failed before the fix.

## F37 File names that kept their leading dots (Low)
- Impact: `safeFileName` stripped leading dots before trimming whitespace, so `" .env"` became `.env` and `" ..bashrc"` became `..bashrc` on the download page and in the name suggested for saving. A name made only of joiners, kept for emoji since F10, displayed as an invisible name instead of the fallback. Browsers sanitise the name on disk, so the gap was in what the recipient saw (A5).
- Fix: leading whitespace and dots are stripped together, and a name with nothing visible left falls back to `download`. Tests cover both cases.

## F38 Concurrent second steps (Medium)
- Impact: the second step read its ticket, checked the code, then counted the failure, and the account's lockout was asked before the check and told after it. Codes sent at once all passed both gates before any failure was counted: 40 wrong codes on one ticket had 7 to 20 of them checked, where the ticket allows 5 and the account 5 per 15 minutes. Someone who knows the password and holds many addresses could so try thousands of codes per lockout window, enough over days to have a real chance against six digits. The same ordering spent a recovery code even when a sign-in at the same moment took the ticket (2 to 5 codes gone for one sign-in in a test), and a transaction that read before it wrote could fail with a 500 under concurrent writes.
- Fix: a ticket gives up an attempt in the same statement that checks its count, before the code is looked at; the account's second-step lockout admits attempts before they are checked (F39); a good code is spent in one transaction with its ticket, so neither goes without the other; every transaction takes the write lock when it begins. Tests send 40 codes at once, on one ticket and over eight, and five recovery codes at once on one ticket; they failed before the fix, and afterwards at most 5 codes are checked and one recovery code is spent. A store test runs 16 transactions that read before they write at once; it fails without the write lock at begin.

## F39 Concurrent sign-ins and signatures (Low)
- Impact: the lockouts were asked before an attempt was checked and told after it, so attempts in flight together were all checked: 50 wrong sign-ins at once from 50 addresses had all 50 checked where the account allows 20, 20 at once from one client had 19 or 20 checked where it allows 5, and 20 bad download signatures at once had 11 to 14 checked where 5 lock the client out of the file. Argon2id at both ends, the 15-character minimum, the four hashes at a time and the per-client budgets still bound guessing, and a download signature is a 256-bit HMAC that cannot be guessed, hence Low.
- Fix: a lockout admits an attempt before it is checked and refuses one while the failures counted and the attempts in flight could reach the limit; each admitted attempt ends counted as a failure or not. Tests send the attempts at once and failed before the fix; afterwards exactly 20, 5 and 5 are checked.

## F40 Account failures in the audit budget (Info)
- Impact: failed sign-ins and second steps share the process-wide budget for failure events with denied downloads and lockouts (D018), so a flood of failed sign-ins also keeps other failures out of the log for its duration.
- Decision: accepted as D018 states for failure events; recorded there and in the threat model. The lockouts themselves are unaffected.

## F41 Second steps that spent their factor without a session (Low)
- Impact: the second step spent the ticket and the code in one transaction (F38), recorded the sign-in in the audit log, and then opened the session in a statement of its own. If that insert failed, the user got a 500 and had to sign in again, the TOTP step or recovery code was spent, and the log showed a sign-in that never happened. It takes a database error at that moment and gives no one access.
- Fix: the session is inserted in the same transaction, and the sign-in is audited after the commit. A store test makes the insert fail and checks that the ticket still works and no code is spent; it fails when the insert is moved after the commit.

## F42 Attempts in flight answered as a lockout (Low)
- Impact: since F39 a lockout refuses an attempt while the failures counted and the attempts in flight could reach the limit, and every refusal was answered as a lockout, 429 `locked` with `Retry-After: 900`. A user with failures already counted who submitted twice, or signed in from two devices at once, was told to wait 15 minutes, though the attempt could be made a moment later. Introduced by F39.
- Fix: admission tells the two refusals apart; one caused only by attempts in flight answers 503 `busy` with `Retry-After: 5`, and downloads still answer 404. Admission returns a handle that a defer ends, so an early return or a panic cannot keep a slot. Tests check the busy answer, that attempts that pass never count against later ones, and exact counts when attempts arrive together.

## F43 Tickets that outlived a sign-in change (Low)
- Impact: a ticket stands for the password given when it was issued, yet a password change, or turning two-factor sign-in off and on again, left the account's tickets valid for the rest of their 5 minutes. Someone with the old password and a ticket could still finish signing in with a code; after TOTP was set up again, with a code of the new secret. A code is needed either way, hence Low.
- Fix: the three changes delete the account's tickets in the same transaction. An API test makes each change while a ticket is pending and expects `ticket_expired`; a store test covers each change on its own and checks that other accounts keep their tickets. Both fail without the fix.

## F44 Lockout entries lost to eviction (Info)
- Impact: a lockout table at 50,000 entries evicts an arbitrary entry for each new key (D017). It could evict an entry with attempts in flight; their failures then went to an entry no longer in the table, and the next attempt for that key started from nothing. Attempts that passed also left entries behind, so the table filled sooner. It takes tens of thousands of distinct, individually rate-limited keys.
- Fix: eviction skips entries with attempts in flight, so a lockout table can pass 50,000 by the requests in progress, and an attempt that ends leaves no entry with nothing to count. A test fills a table with attempts in flight and checks that none is evicted and that the table shrinks to its cap once they end; it fails without the fix.

## F45 Failed second steps uncounted after a hang-up (Info)
- Impact: failed second steps after a right password are counted and reported at the next sign-in (D029). The count used the request's context, so a client that hung up after its code was checked and before the count left no failure for the owner to see. The lockout and the audit log still counted it.
- Fix: the count runs without the request's cancellation, as the audit log already did. A test cancels the request at that point; it failed before the fix.

## F46 Sessions that outlived a sign-in change or a sign-out (Low)
- Impact: a password change and turning two-factor sign-in on or off committed the change, then ended the account's sessions in a statement of its own under the request's context. A client that hung up in between, or a database error there, left the change made and every other session alive for up to a day; the audit write between the two can wait seconds for the write lock. A user who changed the password to shut out a stolen session could so leave the thief signed in, and saw an error; turning TOTP on could end with it on and the recovery codes never shown. A sign-out looked its session up and deleted it under the request's context too, so one that hung up while the database was busy kept its session, and the browser kept the cookie it never got the answer to clear. Only the person making the request, or an accident, can trigger it, hence Low.
- Fix: the three changes end every session and ticket of the account and open this browser's new session in their own transaction, so all of it happens or none; after the commit only the cookies are set. A sign-out finishes without the request's cancellation. API tests cancel the request once each change has committed and expect the other session to be gone, and cancel a sign-out at once and expect its session to be gone; they failed before the fix. A store test makes the new session fail to open and checks that nothing changed.

## F47 A new database over existing storage deleted all content (High)
- Impact: vaultd created `vault.db` when it was missing, and the first cleanup run, at startup, deleted every stored object that had no record as orphaned. A lost or replaced data volume, a restore that left the database out, or a second instance pointed at the same bucket therefore emptied the storage within seconds: 300 blobs on disk and 30 objects in an S3 bucket, including ones vaultd never wrote, each leaving one INFO line. On S3 the database and the content live in different places, so losing only the database is the likely case. No request can trigger it; it takes an operator mistake or a lost volume, and the loss is every shared file, hence High.
- Fix: vaultd refuses to start when the database does not exist yet and the storage already holds content, before it creates a database, and names the two remedies; the first orphan sweep comes an hour after the start instead of at once; a sweep deletes at most 100 objects and warns with the number it found (D032). A sweep that fails waits an hour like any other: retried on the next run, as before, it would have deleted 100 objects a minute whenever one deletion failed, which the review of this fix found. Tests cover the refusal, that it leaves no database behind, the first hour, the limit and a failing sweep; the reproduction on disk and on the S3 gateway now ends with every object in place.
- Remaining: an existing database pointed at another instance's storage still loses that content, 100 objects an hour after the first; the bucket must belong to vaultd alone.

## F48 Last download lost between its count and its token (Medium)
- Impact: a grant took the download count in one statement and stored the download token in the next. When the grant took the last count while an earlier token was being redeemed, the redeeming request saw no downloads left and no token pending and removed the file; the token insert then failed on its foreign key. The recipient with a valid link got a 500, and the file and its last download were gone. It needs two recipients within the same moment; under load it happened to 1 to 12 files in 640.
- Fix: `GrantDownload` takes the count and stores the token in one transaction (D014), so a file with no downloads left always has its last token pending until that download is done. A test redeems one token while the last is granted, on many files at once, and failed on every run before the fix; store tests check that a grant whose token cannot be stored takes no download and that a file is kept from its last grant on.

## F49 A lost account key replaced without notice (Medium)
- Impact: vaultd created `account.key` whenever it was missing. Started on a data directory with accounts but without the key, after a restore that left it out or a copy of the database alone, it made a new one and ran: every authenticator code then got a 500, since the stored two-factor secrets are sealed under the old key, every browser was signed out, and nothing in the log said why. The old key still fixes it, but an operator who is not told to look for it keeps the new one. A key file cut short by a crash during its first write stopped every later start. No request can trigger it; it takes an operator mistake and locks out the accounts with two-factor sign-in until they use a recovery code, hence Medium.
- Fix: vaultd creates `account.key` only while the database holds no account; otherwise a missing key stops the start with the remedy (D034). The key is written to a temporary file, synced and renamed, so a crash leaves no key or a whole one. `docs/OPERATIONS.md` describes backup, restore and replacing the key on purpose. Tests cover the refusal, that it leaves no key behind, the first start, an operator-made key and wrong lengths; the start test failed before the fix. A backup and restore by the manual was run against a local instance, both stopped and running.
- Remaining: `audit.key` is still created when missing; losing it only stops address hashes from comparing across the loss.

## F50 A health check that could not fail (Info)
- Impact: `/healthz` answered 200 `ok` without looking at anything. With the blob directory deleted, with 680 KB left on the data volume and uploads failing with 500, and with the data directory gone, a monitor still saw a healthy instance; the operator learned of it from users. No data is exposed, hence Info.
- Fix: the probe queries the database, writes and removes a file where uploads go (on S3 it asks for the bucket) and requires 128 MiB free on the data directory's filesystem; any failure answers 503 `unavailable` (D033). The reason goes to the log only, and a result is shared for 5 seconds, since the probe is public and not rate limited. Tests break each part in turn; the three cases above now answer 503.
- Remaining: the probe reads one row, so it does not find damaged database pages it never touches; an overwritten database header under a running vaultd still answered 200.

## F51 A base URL without a host name turned the Host check off (Low)
- Impact: `VAULT_BASE_URL` set to a port alone, as in `http://:8080`, passed validation with an empty host name, and the API then answered for any `Host` (D022): the check against a page that rebinds its own name to the server's address was off, with nothing in the log. It takes that operator mistake, and Caddy in front still routes by name, hence Low.
- Fix: the configuration refuses a base URL without a host name, and the router no longer treats an empty host as "any": it fails to start without one. A configuration test covers the two forms; it failed before the fix.

## F52 Valid downloads refused as not found while others are in flight (Low)
- Impact: a download request is admitted against the lockout of its client address and file before its signature is checked, and one refused only because others are in flight is answered 404 like a locked one (F39, F42). With no earlier failures that takes six valid requests for one file from one address within the moment a signature check lasts, as recipients behind one NAT opening a link together could send; after wrong signatures from that address in the last 15 minutes it takes fewer. The recipient sees "This file is no longer available" for a file that is still there. No download is taken from the count, and a reload works, but nothing on the page says so.
- Status: open. The 404 is deliberate, so a refusal says nothing about the file; the page cannot tell it from a file that is gone.

## F53 An empty password field under a hint that asks for a password (Info)
- Impact: on the upload page an opened password field left empty now shares the file without a password; before, it disabled the button with no way back. The hint under the field still reads "At least N characters", and nothing says that empty means none. A user who opens the field and creates the link without typing gets an unprotected link; the only sign is that the result does not say "Password".
- Status: open. The wording or a way to close the field is a design decision.

## F54 A late 401 that signs out a new session (Info)
- Impact: the browser signs out when any request is answered 401 `unauthenticated`, through one handler for the page. A request sent under a session that has ended, answered only after the user has signed in again, signs that new session out in the browser: the stored account key is dropped and the sign-in page shows, while the server's session stays valid. It takes a request slower than a sign-in; the user signs in once more and nothing is exposed.
- Status: open.

## F55 A session that ends during an upload (Info)
- Impact: a file shared while signed in is added to My files before its content is sent. When the session has ended by then, that request is answered 401: the browser signs out while the upload goes on, and the result shows the link with "Could not save it to My files." The file is shared and can be deleted with its delete link, but the account's list never shows it.
- Status: open.

## F56 The second-step lock shut the owner out (Medium)
- Impact: second steps were counted per account alone, at sign-in and for the changes that ask for a code. Someone who knew the password could send five wrong codes from any address, and the owner was then refused every sign-in, password change, TOTP switch-off and deletion for 15 minutes, in a known browser and in a signed-in session, recovery codes included; six requests renewed it whenever it ended. The owner could not end it, since changing the password needed the locked second step, and the threat model's statement that the owner's known browsers keep working held for the password step only.
- Fix: the second step is counted per client, per known browser and for all other browsers together, as the password step is, and a change confirmed from a session is counted in that session alone (D035). One test locks the second step from browsers the account does not know, then signs in from a known browser with a recovery code and changes the password from the owner's session; another fails a session's confirmations five times, then signs in and confirms a change from another session. Both failed before the fix.

## F57 Device cookies that outlived the password (Low)
- Impact: a device cookie signed only the username and a random nonce, so it stayed valid for half a year whatever happened to the account, and every sign-in minted a new one. Someone who once knew the password could sign in from many addresses, keep the cookies and, after the owner changed the password, guess the new one with five checked guesses per cookie every 15 minutes, where the account allows twenty to all browsers it does not know: eight cookies gave 40. The cookies also counted for a new account under a deleted one's name.
- Fix: the cookie signs one of eight slots together with the account's auth hash and sealed TOTP secret (D036), so a password change, a TOTP change and a deletion end every cookie issued before, and an account has at most eight. A test signs eight browsers in before each of those changes and counts the checked guesses afterwards, then counts the distinct cookies of 40 sign-ins; it failed before the fix on all four counts. Since the account is now read before the lockouts are asked, another test checks that a username without an account gets exactly the answers of an account reached from a browser it does not know.

## F58 A burned file left behind by overlapping downloads (Low)
- Impact: a download decided whether to burn the file from the count it read before redeeming its token. When the last download was granted while an earlier one was between that read and its redemption, the last one found the earlier token pending and left the file, and the earlier one still saw a count above zero and did not burn it either. Both recipients got their bytes, but the record and the ciphertext stayed until the next cleanup run, a minute later or more if runs failed, readable to whoever reads the storage, where SPEC promises deletion as soon as the count is used up. No one could download it meanwhile.
- Fix: every redemption asks for the conditional delete, which removes nothing while downloads or tokens are left (D014). A test holds the earlier download between its read and its redemption while the last one completes, and expects neither the record nor the content after both; it failed before the fix. F52 is unchanged.

## F59 Codes spent by changes that did not happen (Low)
- Impact: a password change, turning two-factor sign-in off and deleting the account spent their TOTP step or recovery code in a statement of their own, before the change. When the change then failed, because the four hashing slots stayed taken for 10 seconds, the database failed or the client hung up, the code was gone and the change was not made; each retry that failed the same way took another recovery code, the only way back from a lost phone. F41 had closed the same gap for sign-in only.
- Fix: the code is spent in the transaction that makes the change, and the new password is hashed before it, so either both happen or neither (D029). An API test hangs up once the code is checked and expects the change and the spent code to go together; it failed before the fix. A store test sends each change a used code, and a code with a change that fails after spending it, and expects nothing to change.

## F60 Account ids reused after a deletion (Low)
- Impact: `users.id` was an `INTEGER PRIMARY KEY` without `AUTOINCREMENT`, so SQLite gave a new account the largest id plus one. Once the newest account was deleted, the next sign-up took its id, and with it the deleted account's audit entries, which name accounts by id and stay for 30 days. Anyone could arrange this by signing up, acting and deleting the account. A sealed TOTP secret of the old account would also open under the new one, for someone who can write the database.
- Fix: ids come from a counter that only grows (D037); migration 0007 starts it above every id in the users table and the audit log. A store test deletes the newest account and creates another, and a migration test starts from a database whose deleted newest account still has audit entries; both failed before the fix.

## F61 Checks that could not fail (Low)
- Impact: four checks that the test report cites held whatever the code did about the property they name. The download's tamper test asserted only that the download fails, while dropping the partial file is the sinks' work, and no test ran the sinks, the file sink Chromium users get included. The upload test looked for the file name in the base64 of the metadata, where a name sent in clear never shows. The log redaction test looked for the file contents only in the encoding they travel in, where a log line would hold them as text, standard base64 or hex. The black-box burn check read the metadata, which answers 404 for every file with no downloads left, burned or not.
- Fix: `save.test.ts` feeds both sinks a stream that fails after its first record and expects the file aborted and no Blob offered; the upload test decodes the metadata it sent and opens it with the link's key; the redaction test uses printable contents and looks for every secret as sent, as text, in standard base64 and in hex; the black-box check asks for the record with the owner token after the last download. Each new check failed on a change the old one let through: a file sink that commits its partial file, a download sink that offers its partial Blob, an upload that sends the metadata in clear, a download that logs the bytes it sends, and a last download that never burns the file.
- A fifth check had the same flaw: the password link test looked for the secret in the base64 of the fragment, which lines up with the secret's own only at offsets divisible by 3, so a secret left in clear at byte 28 passed it. It now searches the decoded fragment at every offset and fails on that change.

## F62 The cost of an offline password guess overstated (Info)
- Impact: the threat model said that, for A3 holding the users table, a guess at a password costs Argon2id in the browser and again on the server. A guess is checked against the sealed account key: Argon2id at the browser's parameters, HKDF and one AES-GCM decryption that fails for a wrong guess. The server's Argon2id hash of the auth secret is never needed, so it adds nothing to the cost; its purpose is that the copy holds no value a client could sign in with (D027). The assets table already gave the right cost.
- Fix: the row states the cost of one Argon2id at the browser's parameters and what the server's hash is for.

## F63 The file name's length in the metadata (Info)
- Impact: the metadata blob was `12 + 16 + len(JSON)` bytes and the server knows the exact size, so the server, a holder of the database and anyone with the file id learned the length of the name, to within the few lengths of the type the browser derives from the extension. With the size, that can tell which of a known set of documents was shared. SPEC said the server knows only the ciphertext size.
- Fix: the JSON is padded with spaces to a multiple of 1024 bytes, at most to the 4096 bytes the server accepts for the blob (D012), so every name up to about 900 bytes gives a blob of 1052. Old blobs still open, since JSON allows white space after a value, and the SPEC vectors encrypt their JSON directly. A test compares the blob lengths of short, long and CJK names and of names past one KiB; it failed before the fix.

## F64 An account cap that stays full (Low)
- Impact: sign-up creates accounts while fewer than `VAULT_MAX_ACCOUNTS` exist, 10,000 by default, at five an hour per client. 2,000 client addresses, a /53 of IPv6 /64s, fill the cap within an hour. Accounts never expire and vaultd cannot remove another's account, so every later sign-up answers 503 `capacity` until the operator raises the cap; the sign-ups also take usernames of the attacker's choosing. Existing accounts and anonymous sharing are unaffected. The storage quota, the comparable case, empties itself within seven days.
- Decision: accepted, without account expiry. The threat model lists it as a residual risk, and the operations manual tells the operator to raise the cap.

## F65 Keys in the request log through an encoded # (Info)
- Impact: the request log wrote the decoded path of every request. A mail gateway, messenger or link shortener that rewrites `#` as `%23` makes the browser send the key of a share link, or the owner token of a delete link, in the path; vaultd answered with the web client, which called the link incomplete, and logged the path with the key in clear next to the file id. API paths were logged the same way. It needs a fault outside vault-share, hence Info.
- Fix: the request log and the panic log keep the path as sent up to its first escaped character (D010), which no path vaultd serves contains. A test requests share, delete and API paths with `%23` and with `%2523` and checks that no key reaches the log; it failed before the fix.

## F66 Codes on account changes without a length check (Info)
- Impact: the sign-in's second step refused a code longer than 32 characters, but a password change, an account deletion and turning two-factor sign-in on or off passed any code up to the 16 KiB body limit to the code check, against the rule that every input is checked for length and format. It cost a counted wrong code and nothing more.
- Fix: those requests refuse a code longer than 32 characters with 400 before anything is checked or counted. A test sends each of them an overlong code six times and then confirms a change with a right one; it failed before the fix.

## F67 Data after a JSON body (Info)
- Impact: the API decoded the first JSON value of a body and ignored whatever followed it, so `{"username":"alice"}anything` was read as a valid request, against the rule that every input is checked for format. No effect was found.
- Fix: a body must end after its value, but for white space, or it is answered 400. A test sends bodies followed by text, a second object and a second value; it failed before the fix.

## F68 Download tokens in Caddy's error log (Low)
- Impact: Caddy writes a request that fails at Caddy itself, such as a 502 while vaultd restarts or is unreachable, to its error log at ERROR level with a `request` object whose `uri` keeps the query string, whether or not an access log is on (Caddy 2.11.9, `modules/caddyhttp/server.go`). A download that failed so left its one-time token, valid for five minutes, in `docker compose logs caddy`. The token only fetches ciphertext and spends a download already granted to its holder. The log checks of the test report ran without upstream failures. Found by reading Caddy's source.
- Fix: Caddy's default log replaces the `token` parameter of a logged URI with `REDACTED` (D020). A CI step stops vaultd, requests content with a made-up token, and requires both the 502 entry with the path and the replaced token in Caddy's log and the token nowhere in it.
