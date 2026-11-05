# Threat Model (Draft)

Method: STRIDE. This file is a starting point; Claude Code and Aaron update it together at the end of each milestone.

## 1. Assets

| Asset | Sensitivity |
|---|---|
| File plaintext and file names | Highest |
| Master key secret | Highest |
| Delete token | High |
| Ciphertext | Medium (unreadable without the key, but size and timing can be analyzed) |
| Audit log | Medium |

## 2. Trust Boundaries

1. Between the user's browser and the network
2. Between the network and the server
3. Between the server and storage
4. Frontend code delivery (the server serves JS to the browser)

## 3. Attackers

- A1 Network eavesdropper
- A2 Ordinary external attacker holding information other than the share link
- A3 Attacker who has obtained the database and storage
- A4 Attacker in full control of the server
- A5 Malicious uploader (abuses the service to spread malicious files or exhaust resources)

## 4. Threats and Mitigations

| Category | Threat | Mitigation | Status |
|---|---|---|---|
| S Spoofing | Someone without the link tries to download | authKey challenge signature | To do |
| T Tampering | Modifying or reordering ciphertext chunks | AES-GCM authentication, chunk index in the nonce, end marker | To do |
| R Repudiation | Uploader denies having uploaded | Audit log (hashed IPs) | To do |
| I Information disclosure | Key leaks via Referer or logs | Key only in the URL fragment; Referrer-Policy: no-referrer; log filtering | Partial (request log omits the query string) |
| I Information disclosure | Probing file existence via 404 vs 403 responses | Always return 404 | To do |
| I Information disclosure | A3 reads the database | Only ciphertext and verifiers, no keys | Covered by design |
| D Denial of service | Mass uploads exhaust disk space | Size limits, rate limiting, expiry cleanup, total storage quota | To do |
| D Denial of service | Password brute forcing | Browser-side Argon2id plus server-side lockout after failed authentication | To do |
| E Elevation of privilege | Path traversal to read arbitrary files | Strict file id validation; storage paths never built from user input; static files served from an `os.DirFS` root with no directory listing | Partial (static handler done, storage in M2) |
| E Elevation of privilege | XSS stealing the key from the page | Strict CSP, no inline scripts, React default escaping, no rendering of user HTML | To do |

## 5. Residual Risks

- A4 can serve malicious frontend code to steal keys. This limitation is shared by all web-based encryption products and must be stated in the README
- File size and upload time are visible to the server
- Once a link leaks, anyone holding it can download the file
