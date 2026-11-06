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
- Fix: zones are dropped, and rate limits and lockouts key one IPv4 address or one IPv6 /64. The audit log keeps the full address, hashed (D018).

## F13 Unbounded limiter tables (Medium)
- Impact: the tables swept only when inserting past 10,000 entries and only freed entries idle for 30 minutes, so a stream of fresh keys freed nothing and rescanned the whole table under the table's lock on every insert: 148 µs per insert at 20,000 keys, an 80,000-key run did not finish in ten minutes, and memory grew at about 180 bytes per key. Combined with F12 this was a memory and CPU denial of service at a few hundred requests per second.
- Fix: a sweep runs at most once a minute, and a table never exceeds 50,000 entries: an arbitrary entry is evicted to make room. Tests insert 150,000 fresh keys into each table and fail if the cap is exceeded or the inserts take more than ten seconds.

## F14 Silent collapse behind a misconfigured proxy (Low)
- Impact: when a trusted proxy sent no usable `X-Forwarded-For`, every client got the proxy's address. The whole service then shared one bucket, and five bad signatures from anyone locked everyone out of a file. The shipped Compose file could reach this on an IPv6-enabled network, which it did not trust.
- Fix: vaultd logs a warning, at most once a minute and without addresses, when a trusted proxy names no client; Compose also trusts the unique local IPv6 range `fd00::/8`; D017 states that clients behind one address share their limits.
