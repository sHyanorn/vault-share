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
- Date: TBD
- Decision: start with SQLite and switch to PostgreSQL if multi-instance deployment is needed; confirm at the start of M2

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
- Rationale: the security headers and CSP of M4 are then set in one place for both the API and the HTML, and trust boundary 4 (frontend code delivery) is owned by code under test; the Caddyfile stays three lines
- Trade-off: Go serves static files less efficiently than Caddy; irrelevant at this scale

## D010 Request logs carry the path but never the query string
- Date: 2026-11-05
- Decision: the request log records method, path, status, size and duration; no query string, no client address
- Rationale: download tokens travel in the query string (SPEC §7); client addresses belong in the audit log as salted hashes (M4)

## D011 Supply chain pinning
- Date: 2026-11-05
- Decision: npm dependencies at exact versions, GitHub Actions at commit SHAs, container base images at digests, govulncheck as a `tool` dependency in `go.mod`; Dependabot opens weekly update PRs for all of them
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
