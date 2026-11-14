# Verifying the client

The browser runs the JavaScript the server sends, so a server in someone else's control can send a client that steals keys (SPEC section 4). These checks show afterwards whether a server sent the person running them the client built from this repository.

## Rebuild a release

The client builds to the same bytes in the Dockerfile's Node image, on Linux x64 and arm64 and on macOS arm64, all with Node 22.23.4; CI compares the four builds on every push. To rebuild a release with Node 22.23.4 and list its files, in any directory:

```bash
git clone --branch v1.0.0 https://github.com/sHyanorn/vault-share
cd vault-share/web
npm ci --ignore-scripts
npm run build
cd dist && find . -type f | LC_ALL=C sort | xargs shasum -a 256
```

## Check a release manifest

Each release carries `client-manifest.json`, which lists every file of the client with its size and SHA-256 and gives the Content-Security-Policy vaultd sends, and `client-manifest.sigstore.json`, the Sigstore bundle in which this repository's release workflow attests the manifest (D038). With the GitHub CLI, signed in with `gh auth login`, from the root of the clone:

```bash
gh release download v1.0.0 --repo sHyanorn/vault-share --pattern 'client-manifest*'
gh attestation verify client-manifest.json --repo sHyanorn/vault-share \
  --signer-workflow sHyanorn/vault-share/.github/workflows/release.yml --source-ref refs/tags/v1.0.0
```

To verify offline against the bundle, write Sigstore's trusted root with `gh attestation trusted-root > trusted_root.jsonl` and add `--bundle client-manifest.sigstore.json --custom-trusted-root trusted_root.jsonl` to the second command.

To compare the manifest with your own build, from `server/`:

```bash
go run ./cmd/webcheck verify -manifest ../client-manifest.json -dir ../web/dist
```

## Check a deployment

From `server/`:

```bash
go run ./cmd/webcheck verify -manifest ../client-manifest.json https://vault.example
```

`webcheck` fetches each file of the manifest but `index.html`, which it checks at `/` and at a share link's path instead, without following redirects, and compares the bytes and the Content-Security-Policy of every response. It prints one line per check and exits 1 when anything differs.

## Build hashes of v1.0.0

(The table of each platform's hashes, from the CI run of the tag and from one machine outside CI, lands after the tag.)

## What this does not do

These checks find a changed client after the fact, and only in what the server sends the person running them. A server can send the released client to whoever checks and a changed one to chosen visitors, on any visit, since the browser asks the server for the page every time. The signature shows that this repository's release workflow produced the manifest, not that the client is free of flaws, and anyone who can push a tag to the repository can have the workflow sign a changed client. webcheck compares each response's body and Content-Security-Policy only, so another header, such as Refresh, could still send a browser elsewhere. Only the client is covered; the server program is not.
