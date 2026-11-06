# vault-share

Zero-knowledge, end-to-end encrypted file sharing. Files are encrypted in the browser before upload, the key lives only in the link fragment, and the server never sees file contents or names. Links can expire, be limited by download count, or burn after reading.

> Status: in development. See [docs/TASKS.md](docs/TASKS.md).

## Quick start

```bash
docker compose up --build
```

Then open <https://localhost>. Caddy signs the `localhost` certificate with its own local CA, so the browser warns once; accept it for local use.

For development without Docker: `cd server && go run ./cmd/vaultd` and `cd web && npm install && npm run dev`. Settings are documented in [.env.example](.env.example).

Caddy runs unprivileged since M4; a deployment created before that needs fresh volumes once (`docker compose down --volumes`).

## Docs

- [Specification](docs/SPEC.md)
- [Threat model](docs/security/THREAT_MODEL.md)
- [Design decisions](docs/DECISIONS.md)

## License

MIT
