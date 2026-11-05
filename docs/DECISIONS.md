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
