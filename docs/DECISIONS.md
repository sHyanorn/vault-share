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
- Rationale: fewer than ten settings; every invalid value is reported at startup; no extra dependency to justify

## D008 Supported Go toolchain
- Date: 2026-11-05
- Decision: `go.mod` pins `go 1.27.3`, the current stable release
- Rationale: Go 1.24 left support when Go 1.26 shipped and no longer receives security fixes; `GOTOOLCHAIN=auto` downloads the pinned version for any developer and CI reads it from `go.mod`

## D009 vaultd serves the web client, Caddy only terminates TLS
- Date: 2026-11-05
- Decision: the built frontend is served by vaultd from `VAULT_WEB_DIR`; Caddy reverse proxies every request
- Rationale: the security headers and CSP of M4 are then set in one place for both the API and the HTML, and trust boundary 4 (frontend code delivery) is owned by code under test; the Caddyfile stays small (three lines at first; D020 and F23 added global options and an explicit HTTP site)
- Trade-off: Go serves static files less efficiently than Caddy; irrelevant at this scale

## D010 Request logs carry the path but never the query string
- Date: 2026-11-05
- Decision: the request log records method, path, status, size and duration; no query string, no client address
- Rationale: download tokens travel in the query string (SPEC §7); client addresses belong in the audit log as keyed hashes (D018)

## D011 Supply chain pinning
- Date: 2026-11-05
- Decision: npm dependencies at exact versions, GitHub Actions at commit SHAs, container base images at digests, govulncheck and gosec as `tool` dependencies of a separate `server/tools` module run with `-modfile`; Dependabot opens weekly update PRs for all of them
- Note: the scanners live in their own module because gosec alone pulls about 150 modules that vaultd never compiles; keeping them out of the server module keeps `go.sum` honest about what ships
- Rationale: a tag can be moved by whoever controls the upstream; a SHA or digest cannot; Dependabot keeps the pins from rotting

## D012 Ciphertext format
- Date: 2026-11-06
- Decision: files are encrypted in the browser in the record format of RFC 8188 (`aes128gcm` content encoding) with a 256-bit key, implemented in `web/src/crypto/ece.ts`
- Layout: `salt(16) | rs(4, big-endian, always 65536) | idlen(1, always 0)`, then records of `rs` bytes. A record is AES-256-GCM over `data | delimiter | zero padding` with a 16-byte tag; the delimiter is `0x01` in every record except the last and `0x02` in the last. Every stream ends with a last record, even an empty file. Only the last record may be shorter than `rs`; the others carry `rs - 17` bytes of data
- Keys: `fileKey = HKDF-SHA256(secret, salt = "", info = "vault-share/file", 32 bytes)` is the input keying material. Per file, `CEK = HKDF-SHA256(fileKey, salt, "Content-Encoding: aes256gcm\0", 32)` and `nonce_base = HKDF-SHA256(fileKey, salt, "Content-Encoding: nonce\0", 12)`; record `i` uses `nonce_base XOR i` in the last four bytes, so at most 2^32 records (256 TB at this record size, far beyond the 1 GB limit)
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
- Decision: the download count is taken when a signed challenge is accepted and the one-time download token is issued, in a single conditional UPDATE; the content upload requires the owner token; on the last permitted download the file is removed before the bytes are streamed, unless another download token is still pending. A download token is valid for 5 minutes and for one use
- Challenges are stateless: 32 bytes of expiry, nonce and an HMAC-SHA256 tag under a key drawn at startup, valid for 2 minutes. The server verifies the tag and then the client's signature over the whole challenge; replaying a signed challenge only spends the holder's own download count, so one-time bookkeeping is unnecessary (F8)
- Rationale: Firefox Send counts a download when the stream finishes and without atomicity, so parallel requests can exceed the limit and an aborted download is free; counting at token issue closes both. The owner token on upload stops a third party from filling a slot it did not create
- Trade-off: a download interrupted by the network consumes a count and the recipient needs a new link. Transfers must sustain 512 KiB/s or they are cut off at their deadline

## D015 Browser transport for uploads and downloads
- Date: 2026-11-06
- Decision: the upload encrypts the file stream into a Blob and sends it with XMLHttpRequest; the download decrypts the response stream and writes it through `showSaveFilePicker` where the browser offers it, otherwise into a Blob that is handed to the browser's download
- Rationale: streaming request bodies with `fetch` work only in Chromium over HTTP/2, so Firefox Send streamed uploads over a WebSocket instead; a Blob body works everywhere and XMLHttpRequest is the one transport with upload progress. Encryption and decryption themselves stay streaming with constant memory
- Trade-off: browsers keep large Blobs in memory until they page them to disk, so a file near the 1 GB limit can be heavy on low-memory devices; on browsers without `showSaveFilePicker` the decrypted file is buffered the same way. A streaming upload for browsers that support it is a candidate for M6

## D016 Security headers set by vaultd
- Date: 2026-11-06
- Decision: every response carries `Content-Security-Policy: default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'`, HSTS for two years with subdomains, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, a restrictive `Permissions-Policy`, `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Embedder-Policy: require-corp`, `Cross-Origin-Resource-Policy: same-origin` and `X-Frame-Options: DENY`
- Rationale: the built client has no inline script or style, and React sets styles through the CSSOM, which the policy does not govern, so nothing needs `unsafe-inline`. `'wasm-unsafe-eval'` is required for the Argon2id WebAssembly module and permits WebAssembly compilation only, not JavaScript eval. Setting the headers in Go rather than Caddy keeps them tested (D009)

## D017 Client address, rate limits and lockout
- Date: 2026-11-06
- Decision: the client address is the connecting address unless it falls inside `VAULT_TRUSTED_PROXIES`, in which case the last entry of the last `X-Forwarded-For` line counts, since some proxies append a line and others extend the last one (F15); zones are dropped. Rate limits and lockouts count one IPv4 address or one IPv6 /64 as one client; NAT64 (`64:ff9b::/96`) and Teredo addresses count as the IPv4 client they carry. Trusted proxy entries are normalised the same way (IPv4-mapped entries become IPv4, zones are dropped). Three token buckets per client: 120 requests per minute with a burst of 60 on the API, 10 per minute for creating files, 30 per minute for download authentication. Five failed signatures on one file lock that client out of the file for fifteen minutes. A fourth bucket, counted in bytes, is the storage budget (D021). State lives in memory and resets on restart
- Bounds: each of the four tables (three bucket sets and the lockouts) rebuilds itself without idle entries at most once a minute past 10,000 entries and evicts an arbitrary entry at 50,000, so memory stays near 10 MiB per table under sustained churn and an insert costs the same whatever the key space (F13). Eviction can hand a client a fresh bucket or end a lockout early, which takes tens of thousands of distinct, individually rate-limited keys
- Rationale: Firefox Send trusted `X-Forwarded-For` unconditionally, which lets any client choose its own address; the Compose network is private and only Caddy can reach vaultd, so it is trusted there. A per-client, per-file lockout cannot be used by one address to lock other addresses out. One instance (D005) makes in-memory state sufficient
- Trade-off: clients behind one address (NAT, VPN egress) share buckets and lockouts; a trusted proxy that sends no usable `X-Forwarded-For` collapses everyone onto its own address, which the server logs once a minute for API requests; a proxy missing from `VAULT_TRUSTED_PROXIES` collapses everyone silently, since its forwarded header is indistinguishable from a client's. The lockout bounds signature forgery and audit noise; it does not bound password guessing, which never reaches the server (D019)

## D018 Audit log hashing
- Date: 2026-11-06
- Decision: audit entries store the client address and user agent as the first 16 bytes of HMAC-SHA256 under a 32-byte key created in the data directory on first start; entries are kept for 30 days
- Bounds (F16): the table holds at most 1,000,000 entries, about 100 MB; the cleanup job drops the oldest beyond that every minute and logs the count. Failure events (download denied, client locked), which anyone can produce at will from many addresses, share one process-wide budget of one per second with a burst of 60, so a flood of failures cannot push the other events out; skipped ones are logged as a count once a minute, without file or client by design
- Trade-off: under a sustained flood the oldest entries and most failure events are lost; the counts in the log say how many. The budget is shared, so one client's failure flood also hides other clients' failures for its duration; the lockout itself is unaffected. Successful events such as file creation are not budgeted, see the threat model
- Rationale: a keyed hash still groups events by client for abuse investigation, but the table cannot be turned back into addresses without the key, and the key never leaves the host. An unkeyed hash of an IPv4 address would be trivially reversible

## D019 Password protection
- Date: 2026-11-06
- Decision: with a password, the link carries the 16-byte secret wrapped with AES-256-GCM under a key derived from the password by Argon2id (64 MiB, 2 passes, 1 lane, 16-byte salt) using `hash-wasm` 4.12.0 (MIT, WebAssembly inlined, no further dependencies). The server is unchanged and does not know whether a password exists
- Rationale: SPEC section 4; the OWASP Password Storage Cheat Sheet lists 19 MiB with 2 passes as the minimum and 46 MiB with 1 pass as an equivalent, and 64 MiB with 2 passes stays above both while taking well under a second in Chromium. Firefox Send only re-keyed the server-side authentication with PBKDF2 at 100 iterations, so its link still carried the file key
- Trade-off: the wrapped secret is in the link, so an attacker holding the link can guess passwords offline against the GCM tag at Argon2id cost per guess, and the server never sees a guess, so no lockout applies. A weak password remains a weak password. Browser password managers may offer to save the per-file password under the site origin
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
- Orphans: once an hour cleanup deletes stored content that has no record, the backstop for a crash or a failed delete
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
- Sessions: a 256-bit random token in `__Host-vault_session` (Secure, HttpOnly, SameSite=Strict, Path=/, one day); the server keeps only its SHA-256. A session ends an hour after its last request or a day after sign-in, the NIST SP 800-63B-4 limits for AAL2. Sign-in always issues a new token and ends the one the browser held, so no session can be fixed beforehand; an account keeps its ten newest sessions; a password change ends them all; cleanup drops dead ones every minute. The device key of D026 is `HMAC(key, token)`, returned at sign-in and by `GET /session`
- Lockouts: a client is refused a username for 15 minutes after 5 failures within 15 minutes. Failures from browsers that never signed in to the account count together, and 20 lock the username for all of them. A browser that signed in before carries a signed device cookie (`__Host-vault_device`, half a year) and is counted on its own, with 5. Unknown usernames are counted the same way. A password change or an account deletion asks for the password again under the same lockouts
- Bounds: 5 sign-ups an hour per client; 20 sign-in requests, then 10 a minute, per client; 10,000 accounts (`VAULT_MAX_ACCOUNTS`). `VAULT_SIGNUP=closed` stops sign-ups and keeps sign-ins
- Keys: `account.key` in the data directory, next to `audit.key`; fake salts, device keys and device cookies each use their own HKDF-SHA256 subkey of it
- Dependency: golang.org/x/crypto v0.58.0, maintained by the Go team, for Argon2id; only `argon2` is imported. govulncheck lists GO-2026-5932 for the module's `openpgp` package, which vaultd never imports
- Rationale: the OWASP Session Management Cheat Sheet (the `__Host-` prefix, SameSite=Strict, a new ID at sign-in and at every privilege change, timeouts enforced by the server), the OWASP Authentication Cheat Sheet (count failures per account, not only per address, and mind lockout as a denial of service), and OWASP's device-cookie scheme against exactly that denial of service. The plan proposed 12 hours idle and 7 days in all; the sources put both far above OWASP's common ranges and NIST's AAL2 limits, so the NIST values apply
- Trade-off: sign-up still tells whether a username is taken, at five tries an hour per client, so a locked username reveals nothing more. Someone who keeps failing for a username locks it for browsers that never signed in to it, with 20 attempts every 15 minutes; the owner's own browsers keep working. Lockouts live in memory and reset when vaultd restarts. A returning user signs in at least once a day
