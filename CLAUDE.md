# CLAUDE.md

This repository is an end-to-end encrypted file sharing service. The server never sees file contents or file names. It is a security-focused project, so the security documentation matters as much as the code.

## Read Before Starting

1. `docs/SPEC.md`: requirements, encryption scheme, API
2. `docs/security/THREAT_MODEL.md`: threat model; revisit it for every feature change
3. `docs/TASKS.md`: start from the first unchecked milestone
4. `docs/DECISIONS.md`: decisions already made

## Directory Layout

```
server/   Go backend (cmd/vaultd, internal/...)
web/      React + TypeScript + Vite frontend; crypto logic lives in web/src/crypto
docs/     Specs, decisions, security docs
```

## Working Practices

- Write a plan before starting each milestone
- One commit per task, Conventional Commits format in English
- When a task is done, check it off in TASKS.md; record new decisions in DECISIONS.md
- At the end of each milestone, summarize what was done, what new attack surface was introduced, and how it is mitigated
- Everything committed to GitHub (code, comments, docs, commit messages) is in English and concise: say what changed and why, not the step-by-step process. Commit messages use Conventional Commits with a short subject and at most a brief body.

## Common Commands

```bash
cd server && go test -race ./... && go vet ./...
cd server && gosec ./... && govulncheck ./...
cd web && npm test && npm run lint && npm audit
docker compose up --build
```

## Mandatory Security Rules

- Do not invent cryptographic algorithms. Use only the Web Crypto API (AES-256-GCM, HKDF) and mature libraries (Argon2id)
- The encryption key may appear only in the URL fragment (after `#`); it must never be sent to the server in any request and never written to logs
- Every AES-GCM encrypted chunk uses a unique random nonce; nonces must never be reused
- Server-side password hashing uses Argon2id, and comparisons use constant-time functions
- Validate the length and format of all input; all SQL uses parameterized queries
- Logs must never contain keys, tokens, passwords or file contents
- Pin dependency versions; justify any new dependency before adding it
- When a security issue is found, stop and record it in `docs/security/FINDINGS.md`
- Security testing targets only this project's own deployed instances
