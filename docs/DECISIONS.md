# Technical Decision Log

## D001 Go for the backend, React + TypeScript for the frontend
- Date: 2026-11-04
- Rationale: Go suits streaming IO and works well with security tooling (gosec, govulncheck); sharing a language with the matching engine lowers the learning cost; the frontend reuses an already familiar stack

## D002 Use only the Web Crypto API and mature libraries
- Date: 2026-11-04
- Rationale: hand-rolled cryptographic primitives are highly error-prone; Web Crypto is implemented natively by the browser, fast and audited
- Alternatives: libsodium.js (more complete; can be added if needed)

## D003 Key in the URL fragment
- Date: 2026-11-04
- Rationale: browsers do not send the fragment to the server, which enables zero knowledge; this is the established approach of products such as Firefox Send
- Trade-off: the link is the credential; this must be stated in the documentation

## D004 No distinction between "not found" and "forbidden"
- Date: 2026-11-04
- Rationale: prevents attackers from probing whether a file exists

## D005 Metadata database
- Date: 2026-11-06
- Decision: SQLite through `modernc.org/sqlite` (pure Go) in WAL mode, one instance; PostgreSQL only if multi-instance deployment is ever needed
- Rationale: the image is a static binary built without CGO, which rules out the CGO SQLite driver; one writer at a time is enough here. Migrations are embedded SQL files applied by the standard library and queries are hand-written parameterized SQL (SPEC section 5), so neither a migration tool nor a code generator is needed
- Trade-off: `synchronous=NORMAL` with WAL means a power loss can roll back the newest download decrement, granting one extra download; blobs themselves are fsynced

## D006 oxlint instead of ESLint
- Date: 2026-11-05
- Decision: lint the frontend with oxlint, the default of the current `create-vite` template, and format with Prettier
- Rationale: one pinned dependency instead of the ESLint plugin set; the React hooks rules are built in; same rule set the official template ships with
- Trade-off: a smaller rule catalogue than ESLint; revisit if a needed rule is missing

## D007 Configuration through the standard library
- Date: 2026-11-05
- Decision: `internal/config` reads `VAULT_*` variables with `os.LookupEnv`; no configuration library
- Rationale: seventeen flat settings, six of them for S3; every invalid value is reported at startup; no extra dependency to justify

## D008 Supported Go toolchain
- Date: 2026-11-05
- Decision: `go.mod` pins `go 1.27.3`, the current stable release
- Rationale: Go 1.24 left support when Go 1.26 shipped and no longer receives security fixes; `GOTOOLCHAIN=auto` downloads the pinned version for any developer and CI reads it from `go.mod`
- Update: raised to Go 1.27.4 for GO-2026-6859, which govulncheck reports as reachable.

## D009 vaultd serves the web client, Caddy only terminates TLS
- Date: 2026-11-05
- Decision: the built frontend is served by vaultd from `VAULT_WEB_DIR`; Caddy reverse proxies every request
- Rationale: the security headers and CSP of M4 are then set in one place for both the API and the HTML, and trust boundary 4 (frontend code delivery) is owned by code under test; the Caddyfile stays small (three lines at first; D020 and F23 added global options and an explicit HTTP site)
- Trade-off: Go serves static files less efficiently than Caddy; irrelevant at this scale

## D010 Request logs carry the path but never the query string
- Date: 2026-11-05
- Decision: the request log records method, path, status, size and duration; no query string, no client address
- Rationale: download tokens travel in the query string (SPEC §7); client addresses belong in the audit log as keyed hashes (D018)
- Update: the path is logged as sent up to its first escaped character, in the request log and for a panic. No path vaultd serves holds one, while a share or delete link whose `#` reached the browser as `%23` carries its key there (F65)

## D011 Supply chain pinning
- Date: 2026-11-05
- Decision: npm dependencies at exact versions, GitHub Actions at commit SHAs, container base images at digests, govulncheck and gosec as `tool` dependencies of a separate `server/tools` module run with `-modfile`; Dependabot opens weekly update PRs for all of them
- Note: the scanners live in their own module because gosec alone pulls about 150 modules that vaultd never compiles; keeping them out of the server module keeps `go.sum` honest about what ships
- Rationale: a tag can be moved by whoever controls the upstream; a SHA or digest cannot; Dependabot keeps the pins from rotting

## D012 Ciphertext format
- Date: 2026-11-06
- Decision: files are encrypted in the browser in the record format of RFC 8188 (`aes128gcm` content encoding) with a 256-bit key, implemented in `web/src/crypto/ece.ts`
- Layout: `salt(16) | rs(4, big-endian, always 65536) | idlen(1, always 0)`, then records of `rs` bytes. A record is AES-256-GCM over `data | delimiter | zero padding` with a 16-byte tag; the delimiter is `0x01` in every record except the last and `0x02` in the last. Every stream ends with a last record, even an empty file. Only the last record may be shorter than `rs`; the others carry `rs - 17` bytes of data
- Keys: `fileKey = HKDF-SHA256(secret, salt = "", info = "vault-share/file", 32 bytes)` is the input keying material. Per file, `CEK = HKDF-SHA256(fileKey, salt, "Content-Encoding: aes256gcm\0", 32)` and `nonce_base = HKDF-SHA256(fileKey, salt, "Content-Encoding: nonce\0", 12)`; record `i` uses `nonce_base XOR i` in the last four bytes, so at most 2^32 records (256 TiB at this record size, far beyond the 1 GiB limit)
- Metadata: `iv(12) | AES-256-GCM(JSON {name, type, size})` under `metaKey = HKDF-SHA256(secret, "", "vault-share/meta", 32)` with a random IV per encryption
- Auth: `authKey = HKDF-SHA256(secret, "", "vault-share/auth", 32)` is an HMAC-SHA-256 key. The client signs the server's challenge with it; the server stores the raw key as the verifier (M2)
- Rationale: RFC 8188 is a published, reviewed format with test vectors and a browser implementation in Firefox Send. Keeping its layout lets the RFC section 3.1 vector run unchanged against this implementation with a 128-bit key. AES-256 follows SPEC section 4
- Differences from Firefox Send: the decrypter rejects a header whose `rs` differs from 65536 or that carries a key id instead of ignoring it; an empty file still produces a last record, so a stream cut after the header fails instead of decrypting to nothing; metadata uses a random IV instead of all zeros; password protection (M4) will use Argon2id instead of PBKDF2 with 100 iterations
- Bound: the 16-byte secret caps every key at 128 bits of entropy (SPEC section 4); AES-256 adds no strength beyond that and costs nothing
- Contract for consumers (M3): `decryptStream` emits each authenticated record as soon as it is verified, so a stream error can arrive after plaintext has been written; the download page must treat any error as fatal and discard the partial file (RFC 8188 section 4.2). `name` and `type` from `decryptMetadata` are uploader-controlled strings that only pass a type check; sanitize them before display and before use in `Content-Disposition`

## D013 Tokens are random secrets hashed with SHA-256
- Date: 2026-11-06
- Decision: the owner token and download tokens are 32 random bytes; the server stores their SHA-256 and compares hashes in constant time. Challenge nonces are 32 random bytes stored as is and deleted on first use (superseded: challenges are stateless, see D014 and F8)
- Rationale: Argon2id (CLAUDE.md) protects low-entropy passwords; a 256-bit random token cannot be guessed, so a fast hash is enough and still keeps a database leak from yielding usable tokens

## D014 Download accounting
- Date: 2026-11-06
- Decision: the download count is taken when a signed challenge is accepted and the one-time download token is issued: a conditional UPDATE and the token insert in one transaction (F48); the content upload requires the owner token; on the last permitted download the file is removed before the bytes are streamed, unless another download token is still pending; every redemption asks, so of downloads that overlap the one that redeems its token last removes the file (F58). A download token is valid for 5 minutes and for one use
- Challenges are stateless: 32 bytes of expiry, nonce and an HMAC-SHA256 tag under a key drawn at startup, valid for 2 minutes. The server verifies the tag and then the client's signature over the whole challenge; replaying a signed challenge only spends the holder's own download count, so one-time bookkeeping is unnecessary (F8)
- Rationale: Firefox Send counts a download when the stream finishes and without atomicity, so parallel requests can exceed the limit and an aborted download is free; counting at token issue closes both. The owner token on upload stops a third party from filling a slot it did not create
- Trade-off: a download interrupted by the network consumes a count and the recipient needs a new link. Transfers must sustain 512 KiB/s or they are cut off at their deadline

## D015 Browser transport for uploads and downloads
- Date: 2026-11-06
- Decision: the upload encrypts the file stream into a Blob and sends it with XMLHttpRequest; the download decrypts the response stream and writes it through `showSaveFilePicker` where the browser offers it, otherwise into a Blob that is handed to the browser's download
- Rationale: streaming request bodies with `fetch` work only in Chromium over HTTP/2, so Firefox Send streamed uploads over a WebSocket instead; a Blob body works everywhere and XMLHttpRequest is the one transport with upload progress. Encryption and decryption themselves stay streaming with constant memory
- Trade-off: browsers keep large Blobs in memory until they page them to disk, so a file near the 1 GiB limit can be heavy on low-memory devices; on browsers without `showSaveFilePicker` the decrypted file is buffered the same way. A streaming upload for browsers that support it is a candidate for M6

## D016 Security headers set by vaultd
- Date: 2026-11-06
- Decision: every response carries `Content-Security-Policy: default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'`, HSTS for two years with subdomains, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, a restrictive `Permissions-Policy`, `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Embedder-Policy: require-corp`, `Cross-Origin-Resource-Policy: same-origin` and `X-Frame-Options: DENY`
- Rationale: the built client has no inline script or style, and React sets styles through the CSSOM, which the policy does not govern, so nothing needs `unsafe-inline`. `'wasm-unsafe-eval'` is required for the Argon2id WebAssembly module and permits WebAssembly compilation only, not JavaScript eval. Setting the headers in Go rather than Caddy keeps them tested (D009)

## D017 Client address, rate limits and lockout
- Date: 2026-11-06
- Decision: the client address is the connecting address unless it falls inside `VAULT_TRUSTED_PROXIES`, in which case the last entry of the last `X-Forwarded-For` line counts, since some proxies append a line and others extend the last one (F15); zones are dropped. Rate limits and lockouts count one IPv4 address or one IPv6 /64 as one client; NAT64 (`64:ff9b::/96`) and Teredo addresses count as the IPv4 client they carry. Trusted proxy entries are normalised the same way (IPv4-mapped entries become IPv4, zones are dropped). Three token buckets per client: 120 requests per minute with a burst of 60 on the API, 10 per minute for creating files, 30 per minute for download authentication. Five failed signatures on one file lock that client out of the file for fifteen minutes. A fourth bucket, counted in bytes, is the storage budget (D021). State lives in memory and resets on restart
- Bounds: each table of buckets or lockouts rebuilds itself without idle entries at most once a minute past 10,000 entries and evicts an arbitrary entry at 50,000, so memory stays near 10 MiB per table under sustained churn and an insert costs the same whatever the key space (F13). A lockout entry with attempts in flight is never evicted, so a lockout table can pass 50,000 by the requests in progress, and an attempt that passes leaves no entry behind (F44). Eviction can hand a client a fresh bucket or end a lockout early, which takes tens of thousands of distinct, individually rate-limited keys
- Rationale: Firefox Send trusted `X-Forwarded-For` unconditionally, which lets any client choose its own address; the Compose network is private and only Caddy can reach vaultd, so it is trusted there. A per-client, per-file lockout cannot be used by one address to lock other addresses out. One instance (D005) makes in-memory state sufficient
- Trade-off: clients behind one address (NAT, VPN egress) share buckets and lockouts; a trusted proxy that sends no usable `X-Forwarded-For` collapses everyone onto its own address, which the server logs once a minute for API requests; a proxy missing from `VAULT_TRUSTED_PROXIES` collapses everyone silently, since its forwarded header is indistinguishable from a client's. The lockout bounds signature forgery and audit noise; it does not bound password guessing, which never reaches the server (D019)

## D018 Audit log hashing
- Date: 2026-11-06
- Decision: audit entries store the client address and user agent as the first 16 bytes of HMAC-SHA256 under a 32-byte key created in the data directory on first start; entries are kept for 30 days
- Bounds (F16): the table holds at most 1,000,000 entries, about 100 MB; the cleanup job drops the oldest beyond that every minute and logs the count. Failure events (download denied, client locked), which anyone can produce at will from many addresses, share one process-wide budget of one per second with a burst of 60, so a flood of failures cannot push the other events out; skipped ones are logged as a count once a minute, without file or client by design
- Trade-off: under a sustained flood the oldest entries and most failure events are lost; the counts in the log say how many. The budget is shared, so one client's failure flood also hides other clients' failures for its duration; the lockout itself is unaffected. Successful events such as file creation are not budgeted, see the threat model
- Accounts (F40): failed sign-ins and second steps are failure events too and share the same budget, so a flood of them also hides denied downloads and lockouts for its duration
- Rationale: a keyed hash still groups events by client for abuse investigation, but the table cannot be turned back into addresses without the key, and the key never leaves the host. An unkeyed hash of an IPv4 address would be trivially reversible

## D019 Password protection
- Date: 2026-11-06
- Decision: with a password, the link carries the 16-byte secret wrapped with AES-256-GCM under a key derived from the password by Argon2id (64 MiB, 2 passes, 1 lane, 16-byte salt) using `hash-wasm` 4.12.0 (MIT, WebAssembly inlined, no further dependencies). The server is unchanged and does not know whether a password exists
- Layout: the link fragment is `salt(16) | iv(12) | AES-256-GCM(secret)`, 60 bytes with the 16-byte tag, where a link without a password has the 16-byte secret; the length tells them apart. The key is the 32-byte Argon2id output, the IV is random per wrap, and there is no associated data (`web/src/crypto/password.ts`)
- Rationale: SPEC section 4; the OWASP Password Storage Cheat Sheet lists 19 MiB with 2 passes as the minimum and 46 MiB with 1 pass as an equivalent, and 64 MiB with 2 passes stays above both while taking well under a second in Chromium. Firefox Send only re-keyed the server-side authentication with PBKDF2 at 100 iterations, so its link still carried the file key
- Trade-off: the wrapped secret is in the link, so an attacker holding the link can guess passwords offline against the GCM tag at Argon2id cost per guess, and the server never sees a guess, so no lockout applies. A weak password remains a weak password. Browser password managers may offer to save the per-file password under the site origin
- Update: the server never sees the password but can tell whether a file has one. The download page asks for the metadata at once for a link without a password, and for a link with one only after the right password is entered; since D030, an entry kept in My files is 206 bytes with a password and 148 without. The threat model lists both.
- Minimum (F21): wrapping needs a password of at least 8 code points, the floor of OWASP ASVS 5.0 (6.2.1) and of NIST SP 800-63B-4 for a password used with another factor, here the link; unwrapping accepts any length, so links made before the minimum still open

## D020 Caddy runs unprivileged
- Date: 2026-11-06
- Decision: `Dockerfile.caddy` runs Caddy as uid 65532 with a read-only root filesystem and no capabilities; it listens on 8080 and 8443 inside the container and Compose maps 80 and 443 to them
- Rationale: SPEC section 8 asks every container to run as a non-root user; binding the privileged ports would have required a capability, and Caddy's `http_port` and `https_port` options exist for exactly this port-forwarding setup
- Note: HTTP/3 is off because Caddy would advertise the internal port in `Alt-Svc`; a deployment that upgrades from the root-owned Caddy needs fresh `caddy-data` and `caddy-config` volumes
- Timeouts (F19, F23): `read_header 10s` and `idle 2m`, the values of vaultd's own server, on both ports; the HTTP site is declared in the Caddyfile because the redirect server Caddy adds by itself ignores server options. Bodies and responses are left to vaultd, which gives each transfer a deadline from its size

## D021 Storage quota and per-client storage budget
- Date: 2026-11-06
- Decision: every record is charged its declared size, its metadata and 64 KiB of overhead against `VAULT_MAX_TOTAL_BYTES` (default 20 GiB) from creation until deletion; the check and the insert are one SQL statement and a trigger-maintained `usage` row holds the total. Over the quota a create answers 503 with code `capacity`. Each client (D017) may additionally reserve 4 GiB a day; over that a create answers 429. A create refused by the quota gives the client its budget back
- Rationale: F17 showed creation had no global bound. The overhead charge makes the quota a bound on disk for small files too and caps the record count at quota / 64 KiB; the per-client budget stops one client from holding the whole quota by re-reserving large uploads that never arrive. The disk a deployment needs is about the quota plus the audit cap (D018)
- Rejected: a global cap on records awaiting their content. With the per-client creation limit two ordinary clients could fill a cap of 1,000 and block every upload for an hour, and it would not have protected audit retention, because small files that are actually uploaded leave the pending state
- Trade-off: a group of clients with real upload bandwidth (five at the defaults) can fill the quota in a day and keep uploads unavailable until their files expire, up to seven days. Public instances need protection upstream; operators size the quota to the disk

## D022 Cross-origin writes are refused
- Date: 2026-11-06
- Decision: every API request whose `Sec-Fetch-Site` is `cross-site` or `same-site` is refused, reads included (F24). Writes also pass Go's `http.CrossOriginProtection`, which judges browsers without Fetch Metadata by their `Origin`. Refusals answer 403 with code `cross_origin` before the rate limiter, so they spend no client budget. Requests with neither header, such as scripts, pass. The API answers only requests whose Host, without port and case, is the host of `VAULT_BASE_URL`, and 421 `misdirected` to any other (F25)
- Rationale: F18. The check is in the standard library since Go 1.25 and follows the Fetch Metadata isolation policy that OWASP recommends against CSRF; the API has no sessions, so no token is needed. Requiring `application/json` would also force a preflight, but only through the CORS rules, without stating the rule
- Trade-off: a web client served from another origin than the API would need `AddTrustedOrigin`; a proxy in front must keep the Host header, as Caddy does, and a local run must set `VAULT_BASE_URL` to the address it is opened at

## D023 No Subresource Integrity
- Date: 2026-11-06
- Decision: the client's scripts and styles carry no `integrity` attributes, and SPEC section 4 no longer lists Subresource Integrity as a mitigation
- Rationale: every asset comes from the same origin as the page that references it. SRI protects a page against a third party that alters a sub-resource, such as a CDN; an attacker in control of the server (A4) serves index.html as well and rewrites the hashes along with the scripts
- Revisit: if assets move to another origin

## D024 No public demo site
- Date: 2026-11-07
- Decision: the project runs no public instance. The README shows the flow in a recorded GIF, and one command starts the full stack locally
- Rationale: an anonymous, end-to-end encrypted file host attracts malware and phishing distribution, which the operator cannot inspect and can only answer by deleting links; Firefox Send was shut down in 2020 for that reason. A public instance would also face the residual risks of the threat model, quota filling and CPU saturation from many addresses, without upstream protection, and need ongoing patching and abuse handling
- Revisit: a short-lived instance with tight limits on downloads and retention, if a live link is ever needed

## D025 S3-compatible blob store
- Date: 2026-11-07
- Decision: with `VAULT_STORAGE=s3` ciphertext lives in an S3-compatible bucket, through the official aws-sdk-go-v2. The body streams into one PutObject with `If-None-Match: *`. It goes unsigned, since its hash is only known at the end; TLS or the local network carries it and the browser's authenticated encryption detects any change. It is never retried, since it cannot be sent twice. The last bytes are held back until the body has ended at the declared size and the request is still wanted, so a wrong size or an upload cancelled before its last byte stores nothing; after that the request runs to its answer (F34). One request caps files on S3 at 5 GiB. Deletes happen at once and report errors (F27); responses time out after a minute (F28), and so does each write (F35). Credentials are static and come from the environment. A custom endpoint is addressed path-style unless `VAULT_S3_PATH_STYLE=false`, and plain http reaches only this machine or a single-label host
- Startup checks: vaultd refuses a bucket with versioning (F31) and a service that lets a second conditional write through (F30)
- Claims: an upload claims its file until its body has ended, and an owner delete or a purge must claim the file too, so no record goes while its bytes arrive (F33). vaultd runs as one process, so the claims live in memory
- Orphans: once an hour, and for the first time an hour after the start, cleanup deletes stored content that has no record, at most 100 objects a sweep (D032); the backstop for a crash or a failed delete
- Testing: one contract test runs against both stores. CI runs it against Versity S3 Gateway (Apache-2.0) on its posix backend, and runs the end-to-end tests on vaultd with that gateway (`compose.s3.yaml`). RustFS passed the same contract; Versity was chosen for its simpler setup and because it made no outbound connections. MinIO, named in the original plan, archived its open-source repository in April 2026 and no longer publishes images
- Rationale: every dependency of aws-sdk-go-v2 comes from AWS, while minio-go draws on modules from many authors (A03). Streaming holds no more memory per upload than the transport's buffers, where buffered parts held up to 8 MiB each (F26), and a single request leaves no multipart state for a crash to strand
- Trade-off: the bucket must belong to vaultd alone, because cleanup deletes every object named like a file id that has no record. The store relies on the service letting a started download finish after a delete, which AWS documents for updates to a key and the contract checks on each service tested. The credentials sit in the vaultd container's environment and can read and delete every object. Files above 5 GiB need the disk store. The versioning check runs at startup only, and the plain-http rule judges the endpoint as written, not what an HTTP proxy or a DNS search domain makes of it

## D026 Account keys
- Date: 2026-11-07
- Decision: the account password never leaves the browser. `master = Argon2id(NFKC(password), salt, 64 MiB, 2 passes, 1 lane, 32 bytes)` with a random 16-byte salt per account; sign-in sends `authSecret = HKDF-SHA256(master, "", "vault-share/account-auth", 32)`, of which the server keeps only an Argon2id hash (D027); `wrappingKey = HKDF-SHA256(master, "", "vault-share/account-wrap", 32)` seals a random 256-bit account key as `iv(12) | AES-256-GCM(key, aad = "vault-share/account-key")`, which the server stores. A password change seals the same account key again, so entries stay as they are
- Entries: each file kept in an account has `iv | AES-256-GCM(JSON {secret, key, owner}, aad = "vault-share/entry/" + file id)` under the account key: the share secret, the link key (the secret, or the secret wrapped under the share password) and the owner token. The file id in the AAD keeps an entry from being moved to another file
- Device: between page loads the browser keeps the account key only sealed under a device key, `iv | AES-256-GCM(key, aad = "vault-share/device")` in localStorage; the server derives the device key from the session token and returns it only while the session lasts (D027), so a copy of the browser's storage opens nothing once the session ends
- Password: at least 15 code points after NFKC normalization, the minimum NIST SP 800-63B-4 sets for a password used as the only factor; two-factor sign-in is optional. Only the browser can check this, since the server never sees the password
- Rationale: "My files" must show file names, which only the share secrets open, so the account needs a key the server does not hold. The split follows Bitwarden: a master key derived in the browser, a derived value sent for login and hashed again by the server, and a protected symmetric key that a password change re-encrypts. The Argon2id parameters are those of D019. The vectors in `account.test.ts` were computed with hash-wasm and WebCrypto and again with Go's x/crypto/argon2 and standard library, and are pinned, because a change to the derivation would lock every account out
- Trade-off: there is no e-mail and no recovery, so a forgotten password loses the account and its list; the files and their links keep working. A4 can serve a page that captures the password, as it can capture any key. The browser draws the salt at sign-up, where the plan had the server draw it: the salt only protects the user's own derivation, and this saves a round trip

## D027 Sign-in and sessions
- Date: 2026-11-07
- Decision: sign-up sends the username, the browser's salt, the auth secret and the sealed account key (D026). The server stores `Argon2id(auth secret)` with a random 16-byte salt at the OWASP minimum (19 MiB, 2 passes, 1 lane) in the PHC string format, compares in constant time, and runs at most four hashes at once; the rest wait up to 10 s, then get 503 `busy`. Sign-in first asks for the salt: a username without an account gets `HMAC(key, username)[:16]`, stable across restarts, and fails after the same work and with the same answer as a wrong secret. Usernames are 3 to 32 characters of `a-z 0-9 . _ -`, so no two look alike
- Sessions: a 256-bit random token in `__Host-vault_session` (Secure, HttpOnly, SameSite=Strict, Path=/, one day); the server keeps only its SHA-256. A session ends an hour after its last request or a day after sign-in, the NIST SP 800-63B-4 limits for AAL2. Sign-in always issues a new token and ends the one the browser held, so no session can be fixed beforehand; an account keeps its ten newest sessions; a password change ends them all in its own transaction, and a sign-out finishes even if the client hangs up (F46); cleanup drops dead ones every minute. The device key of D026 is `HMAC(key, token)`, returned at sign-in and by `GET /session`
- Lockouts: a lockout admits an attempt before it is checked, so attempts that arrive together count as they would one by one (F39). An attempt refused only because others are in flight gets 503 `busy` with `Retry-After: 5`, since it can be made a moment later; downloads answer 404 either way (F42). A client is refused a username for 15 minutes after 5 failures within 15 minutes. Failures from browsers that never signed in to the account count together, and 20 lock the username for all of them. A browser that signed in before carries a signed device cookie (`__Host-vault_device`, half a year) and is counted on its own, with 5; the cookie holds only while the account signs in as it did when it was issued, and an account knows at most eight browsers (D036). Unknown usernames are counted the same way. A password change or an account deletion asks for the password again, counted in the session that asks (D035)
- Bounds: 5 sign-ups an hour per client; 20 sign-in requests, then 10 a minute, per client; 10,000 accounts (`VAULT_MAX_ACCOUNTS`). `VAULT_SIGNUP=closed` stops sign-ups and keeps sign-ins
- Keys: `account.key` in the data directory, next to `audit.key`; fake salts, device keys and device cookies each use their own HKDF-SHA256 subkey of it
- Dependency: golang.org/x/crypto v0.58.0, maintained by the Go team, for Argon2id; only `argon2` is imported. govulncheck lists GO-2026-5932 for the module's `openpgp` package, which vaultd never imports
- Rationale: the OWASP Session Management Cheat Sheet (the `__Host-` prefix, SameSite=Strict, a new ID at sign-in and at every privilege change, timeouts enforced by the server), the OWASP Authentication Cheat Sheet (count failures per account, not only per address, and mind lockout as a denial of service), and OWASP's device-cookie scheme against exactly that denial of service. The plan proposed 12 hours idle and 7 days in all; the sources put both far above OWASP's common ranges and NIST's AAL2 limits, so the NIST values apply
- Trade-off: sign-up still tells whether a username is taken, at five tries an hour per client, so a locked username reveals nothing more. Someone who keeps failing for a username locks it for browsers that never signed in to it, with 20 attempts every 15 minutes; the owner's own browsers keep working. Lockouts live in memory and reset when vaultd restarts. A returning user signs in at least once a day

## D028 Cross-site requests and the session cookie
- Date: 2026-11-07
- Decision: no CSRF token. Every request that reads, uses or sets the session cookie passes the checks of D022: a `Sec-Fetch-Site` of `cross-site` or `same-site` is refused for every method, and a write from a browser without Fetch Metadata is judged by its `Origin` through `http.CrossOriginProtection`. Both cookies are `SameSite=Strict`, so a browser attaches them to no request another site starts, and a refused request sets no cookie. Sign-in is covered too, so another site cannot sign a visitor in to an account of its choosing (login CSRF). API answers carry `Vary: Sec-Fetch-Site, Origin`
- Rationale: the OWASP CSRF Prevention Cheat Sheet accepts Fetch Metadata for software that targets modern browsers, with the Origin check as the mandatory fallback and at least one defense in depth, here the SameSite=Strict cookie; it names Go's `CrossOriginProtection` as an implementation and asks for the Vary header. The web client is served from the API's own origin, so no legitimate request is cross-site. A token would need a pre-session for sign-in and changes in every client call, for no request the checks let through
- Testing: `csrf_test.go` sends every account request with each cross-site marking and checks that it is refused, sets no cookie and changes nothing: the session survives, the password stays, no account is planted
- Trade-off: a browser that sends neither Fetch Metadata nor Origin on a write is not covered by these checks; SameSite=Strict then still keeps the cookie off the request. Every major browser has sent Fetch Metadata since March 2023

## D029 Two-factor sign-in with TOTP
- Date: 2026-11-07
- Decision: optional TOTP per RFC 6238 with the parameters every authenticator app supports (HMAC-SHA-1, 30-second steps, six digits), written on the standard library in `internal/totp` and tested against the vectors of RFC 4226 appendix D and RFC 6238 appendix B. A code is accepted one step either way (RFC 6238 sections 5.2 and 6), each candidate compared in constant time, and only for a step later than the last one used, recorded in the same statement, so no code works twice, not even in parallel
- Setup: the server draws a 160-bit secret (RFC 4226 section 4) and returns it with an otpauth URI; it is kept apart until a code from the app and the password prove the setup. Turning it on returns ten recovery codes of 80 random bits once, keeps only their SHA-256, ends every other session and renews this one, in the transaction that turns it on (F46). Turning it off, changing the password and deleting the account need the password and a code; a recovery code counts as a code, and it is spent in the transaction that makes the change, so a change that fails keeps it (F59)
- Sign-in: a right password for an account with TOTP returns a ticket instead of a session: 256 bits, kept as SHA-256, valid for 5 minutes, for one sign-in and at most 5 codes. Each code takes one of the ticket's attempts before it is checked, and a good code is spent in one transaction with the ticket that also opens the session (F38, F41). A password change, or turning two-factor sign-in on or off, ends the account's tickets (F43). Second steps that fail count per account, and 5 within 15 minutes lock the second step for 15 minutes (superseded: counted per client, per known browser and for all other browsers together, and per session for a confirmed change, see D035). Failed second steps after a right password are counted, even when the client hangs up, and reported at the next sign-in (F45)
- Storage: secrets are sealed with AES-256-GCM under an HKDF subkey of `account.key`, with the account id as associated data, so a copy of the database alone holds none and a sealed secret cannot be moved to another account
- Rationale: the OWASP Multifactor Authentication Cheat Sheet (offer TOTP, single-use recovery codes at setup, ask for an enrolled factor before a change, tell the user about second steps that failed after a right password). The algorithm is a direct implementation of a standard with published vectors, a few lines over HMAC from the standard library; the common library pquerna/otp would also pull in a barcode library. No algorithm is invented
- Trade-off: the server must be able to read the secrets, so A3 with the whole data directory, `account.key` included, can produce codes. TOTP does not stop a phishing page that relays the code within its step. Recovery codes are the only way back from a lost phone; there is no e-mail. While someone who knows the password keeps failing the second step, they work only from a browser the account knows or in a signed-in session (D035)

## D030 My files
- Date: 2026-11-07
- Decision: a file shared while signed in is kept in the account. Right after the create, before the content, the browser sends the entry of D026 to `PUT /api/v1/account/files/{id}` with the session cookie and the file's owner token, so a file can only be kept by whoever created it, and only by one account. `GET /api/v1/account/files` lists the account's files that are still live or uploading, newest first, at most 1,000, with their encrypted metadata and entries; the browser opens the entries, then the names. Deleting from the list uses the owner token inside the entry, through the existing delete. Keeping a file is best effort: if it fails, the share still works and the result says it was not kept
- Account deletion: the account's files expire at once and lose their entries, so their links stop working and cleanup removes them within a minute; a download already granted finishes
- Rationale: the server can list a user's files without being able to read them, which keeps "the server never sees file names" true for accounts. Requiring the owner token keeps the existing proof of ownership instead of adding a second one, and makes planting a file in someone else's list impossible
- Trade-off: the server now knows which files belong to which account, and when they were created; an anonymous share stays unlinked. A file whose entry does not open, for example after a restore from a backup of another account key, is listed as unreadable and can only run out
- Update: entries are sealed without padding, so the server can also tell from an entry's length whether the file has a password: 206 bytes with one, 148 without. The threat model lists this.

## D031 Account pages
- Date: 2026-11-07
- Decision: sign-in, sign-up, My files and the account settings are pages of the same web client, at `/signin`, `/signup`, `/files` and `/account`. Moving between the app's own pages happens in the page (History API), so the account stays open; each URL also works when opened directly, since vaultd serves the client for every path. Signed in, the account key lives in memory as a non-extractable CryptoKey for entries and as bytes for sealing it again; code on the page could reach the same bytes through the device key, so the bytes add no exposure. A file shared while signed in goes to My files; a sign-in that follows failed second steps says so above the page
- QR code: uqr 0.1.3 (MIT, no dependencies, about 9.6 million weekly downloads, maintained by the unjs project) draws the otpauth URI for authenticator apps. Its encoder is Project Nayuki's reference QR code generator; the release is seven months old, and the code makes no network requests and evaluates nothing. The page renders its matrix as one SVG path built in React, so no markup is built from a string. The secret is shown as text as well, for apps that cannot scan
- Rationale: a QR code is how every authenticator app expects to receive a secret; typing 32 characters is where setups fail. The other candidates were larger (qrcode-generator, 556 KB with ports to other languages) or pulled in a command-line parser and a PNG encoder (qrcode)
- Trade-off: none of these pages are server-rendered, so they need JavaScript, as the rest of the client already does

## D032 Guards between the database and the storage
- Date: 2026-11-10
- Decision: vaultd refuses to start when `vault.db` does not exist, or is empty, while the storage already holds an object named like a file id. The check runs before the database is created, so a refused start leaves no database behind and the next one is refused too. There is no override: the operator restores the database or empties the storage. The orphan sweep of D025 first runs an hour after the start, and one sweep deletes at most 100 objects; above that it logs a warning with the number found and leaves the rest to later sweeps. A sweep that fails also waits an hour for the next, and a deletion that fails counts towards the 100, so errors cannot raise the rate
- Rationale: a database that does not match its storage makes every object an orphan (F47). The mismatch that can be detected for certain, a new database, stops the start. The others, an older backup or a foreign bucket, cannot be told from real leftovers, so they are slowed and made visible instead: an hour before the first delete, then 100 an hour, as `rsync --max-delete` bounds a sync. Real leftovers come from crashes and failed deletes, a few at a time
- Trade-off: after a restore from an older backup, content uploaded since the backup goes at 100 objects an hour instead of at once; it counts against the disk but not against the quota, which follows the database. An instance restarted more often than hourly never sweeps. A leftover startup probe (D025) in an otherwise empty bucket also stops a first start, and the message names it

## D033 Health check
- Date: 2026-11-10
- Decision: `/healthz` answers 200 `{"status":"ok"}` only when three checks pass: a query on the database; the blob store takes a write (on disk a file created and removed in `blobs/tmp`, on S3 a HeadBucket); the filesystem of the data directory has at least 128 MiB free. Otherwise it answers 503 `{"status":"unavailable"}` and logs the reason as a warning. The database query and the S3 request get 5 seconds, and a result is reused for 5 seconds
- Rationale: an instance that cannot store or serve files should not look healthy to a monitor or a load balancer (F50). The probe is public and outside the rate limits, so it shares results instead of turning each request into a database query and a storage request, and it does not tell a stranger what failed. On disk a stat is not enough: the open directory still answers after it was deleted. 128 MiB is a fixed floor under which the database and small uploads soon fail; it is not configurable, since the quota (D021) is the setting that sizes storage to the disk
- Trade-off: one row read does not find damage elsewhere in the database, and there is no integrity check at startup. The free-space floor says nothing about room for a large upload. The local file checks have no timeout, so on a stalled filesystem the probe hangs instead of answering 503, as the rest of vaultd does. With S3 storage a data volume that turned read-only passes, since the database check only reads. Compose defines no health check for the vaultd container: its image has no shell or HTTP client to run one with

## D034 Account key guard
- Date: 2026-11-10
- Decision: vaultd creates `account.key` only while the users table is empty. With accounts and no key it refuses to start; there is no override setting, the operator restores the key or writes 32 random bytes to the file by hand (docs/OPERATIONS.md). A key of the wrong length stops the start as before. New key files are written to a temporary file, synced and renamed into place. `audit.key` is still created whenever it is missing
- Rationale: the two-factor secrets (D029) and the device keys (D027) hang on this key, so a silent new one breaks sign-in for accounts that cannot tell why (F49). Whether anything depends on the key is exactly whether an account exists, which makes the check certain, as in D032. Losing `audit.key` costs only the comparison of address hashes across the loss (D018), which does not justify stopping a start
- Trade-off: a restore must bring the key along with the database, or the instance stays down until the operator decides. The made-up salts of D027 come from the same key, so after a replacement a salt that changed marks a username without an account to someone who recorded salts before

## D037 Account ids are never reused
- Date: 2026-11-14
- Decision: a new account takes its id from the one-row table `account_ids`, which a trigger keeps above every id inserted into `users`. Migration 0007 starts it above every id in `users` and in the audit log
- Rationale: audit entries outlive the account they name (D018), and SQLite gives a table without `AUTOINCREMENT` the largest id plus one, so the sign-up after the newest account's deletion took that account's id and its audit trail (F60). The sealed TOTP secret binds the id as well (D029)
- Rejected: `AUTOINCREMENT` needs `users` rebuilt. SQLite turns foreign keys off only outside a transaction, and migrations run inside one; with them on, dropping `users` cascades into sessions, recovery codes and tickets and unlinks the account's files
- Trade-off: an id freed before the upgrade whose audit entries had already expired can be given out once more; nothing refers to it by then

## D036 Device cookies follow the account's credentials
- Date: 2026-11-14
- Decision: a device cookie is `slot(1) | HMAC-SHA256(key, username, auth hash, slot, sealed TOTP secret)[:16]`, with the device-cookie subkey of `account.key` (D027) and a slot drawn at random from eight at each sign-in. It counts only for the account as it signs in now: a password change gives a new auth hash, turning two-factor sign-in on or off changes the sealed secret, and a new account under a deleted one's name has a hash of its own, so every cookie issued before stops counting. An account has at most eight valid cookies at a time. A sign-in reads the account before it asks the lockouts, and a username without an account takes the path of a browser the account does not know
- Rationale: F57. A cookie signed over the username and a random nonce stayed valid for half a year whatever happened to the account, and anyone able to sign in could mint any number of them, each with five guesses of its own, so someone who once knew the password was no longer held to the account's twenty. Binding the cookie to what the account signs in with needs no table, no column and no write at sign-in. A TOTP change ends the cookies too, so one minted while the account had no second factor does not outlive its enabling
- Trade-off: two browsers of one account can draw the same slot and share its count. Cookies issued before this change stop counting until their browser signs in again. After a password or TOTP change the owner's other browsers are unknown until they sign in, which the change makes them do anyway, since it ends their sessions

## D035 Second-step and confirmation lockouts
- Date: 2026-11-14
- Decision: the second step of a sign-in is counted as the password step is (D027): 5 failures per client and username, 5 per device cookie for a browser the account knows, and 5 within 15 minutes from all other browsers together lock it for them for 15 minutes. TOTP and recovery codes take the same path. A change confirmed from a session (a password change, TOTP on or off, an account deletion) is counted in that session alone: 5 wrong passwords, or apart from them 5 wrong codes, lock that session's changes for 15 minutes, and no sign-in lockout counts them
- Change: a second step that passes forgets the failures of its client and of its known browser, but no longer those counted for all unknown browsers together, which others share; before, a right code cleared the account's whole count
- Rationale: F56. One lockout per account let anyone who knows the password shut the owner out of every sign-in and every change, from any address and with recovery codes too, and renew it at six requests every 15 minutes. Device cookies keep the owner's browsers apart from a campaign at the password step (D027, D036); the second step now uses them as well. Only its holder can fail in a session, so no one else can fill its count, and a stolen session gets at most 5 codes every 15 minutes for the day a session can last
- Trade-off: while someone who knows the password keeps failing the second step, browsers the account does not know, the owner's new browser included, wait 15 minutes at a time. The owner ends the campaign by changing the password from a known browser or a signed-in session. A known browser has 5 code guesses of its own every 15 minutes; only a browser that signed in or set up the second factor under the current password and second factor holds one (D036)
