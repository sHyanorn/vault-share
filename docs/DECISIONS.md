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
