# vault-share

Zero-knowledge, end-to-end encrypted file sharing. Files are encrypted in the browser before upload, the key lives only in the link fragment, and the server never sees file contents or names. Links can expire, be limited by download count, or burn after reading.

> Status: in development. See [docs/TASKS.md](docs/TASKS.md).

## Quick start

```bash
docker compose up --build
```

Then open <https://localhost>. Caddy issues a locally trusted certificate for `localhost`; the browser will warn once unless you run `caddy trust`.

For development without Docker: `cd server && go run ./cmd/vaultd` and `cd web && npm install && npm run dev`. Settings are documented in [.env.example](.env.example).

## Docs

- [Specification](docs/SPEC.md)
- [Threat model](docs/security/THREAT_MODEL.md)
- [Design decisions](docs/DECISIONS.md)

## License

MIT
