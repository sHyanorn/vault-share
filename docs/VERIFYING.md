# Verifying the client

The browser runs the JavaScript the server sends, so a server in someone else's control can send a client that steals keys (SPEC section 4). These checks show afterwards whether a server sent the person running them the client built from this repository.

## Rebuild a release

The client builds to the same bytes in the Dockerfile's Node image, on Linux x64 and arm64 and on macOS arm64, all with Node 22.23.4; CI compares the four builds on every push. To rebuild a release with Node 22.23.4 and list its files, in any directory:

```bash
git clone --branch v1.0.1 https://github.com/sHyanorn/vault-share
cd vault-share/web
npm ci --ignore-scripts
npm run build
cd dist && find . -type f | LC_ALL=C sort | xargs shasum -a 256
```

## Check a release manifest

Each release carries `client-manifest.json`, which lists every file of the client with its size and SHA-256 and gives the Content-Security-Policy vaultd sends, and `client-manifest.sigstore.json`, the Sigstore bundle in which this repository's release workflow attests the manifest (D038). With the GitHub CLI, signed in with `gh auth login`, from the root of the clone:

```bash
gh release download v1.0.1 --repo sHyanorn/vault-share --pattern 'client-manifest*'
gh attestation verify client-manifest.json --repo sHyanorn/vault-share \
  --signer-workflow sHyanorn/vault-share/.github/workflows/release.yml --source-ref refs/tags/v1.0.1
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

## Build hashes of v1.0.1

The client of v1.0.1, from commit `eada149d7f2af6e2995aa7ff24ed6a76d482bd63`, built to the same three files in each of these environments:

| Build | Environment | Run |
|---|---|---|
| The Dockerfile's Node image | Node v22.23.4, Alpine 3.24.3, x86_64 | [CI run of the tag](https://github.com/sHyanorn/vault-share/actions/runs/45014006761) |
| Linux x64 | Node v22.23.5, ubuntu-24.04, x86_64 | CI run of the tag |
| Linux arm64 | Node v22.23.5, ubuntu-24.04-arm, aarch64 | CI run of the tag |
| macOS arm64 | Node v22.23.5, macos-15, arm64 | CI run of the tag |
| Linux x64 | Node v22.23.4, Ubuntu 24.04.5, glibc 2.39, x86_64 | One machine outside CI |
| Linux x64 | Node v22.23.5, Ubuntu 24.04.5, glibc 2.39, x86_64 | The same machine |

| File | Bytes | SHA-256 |
|---|---|---|
| `assets/index-DU2Mut1y.js` | 314508 | `b28ad325e6c0ba2b9c6f770052f7b88358fe93273d947c4f62f79e7a1b1a5df0` |
| `assets/index-DeL24qnR.css` | 12767 | `7d05717d0660d7439eba24bdd9f5509309d229996284f90594cfb06b9306ba14` |
| `index.html` | 396 | `7d06c361b054ced917b4546a1a12c8aec6068a02f205d724e5d1ccf665ac324c` |

The release's `client-manifest.json` lists the same files, sizes and hashes. Its own SHA-256, which the attestation names, is `86f8af4dbaa4ff9cbb2ad51c46ebbf4dc96796d82514ac0715a05bf0ec1b9c40`.

## Build hashes of v1.0.0

The client of v1.0.0, from commit `8da9b130a3d76f59e556ae56eff7c1d27084a229`, built to the same three files in each of these environments:

| Build | Environment | Run |
|---|---|---|
| The Dockerfile's Node image | Node v22.23.4, Alpine 3.24.3, x86_64 | [CI run of the tag](https://github.com/sHyanorn/vault-share/actions/runs/43628958957) |
| Linux x64 | Node v22.23.4, ubuntu-24.04, x86_64 | CI run of the tag |
| Linux arm64 | Node v22.23.4, ubuntu-24.04-arm, aarch64 | CI run of the tag |
| macOS arm64 | Node v22.23.4, macos-15, arm64 | CI run of the tag |
| Linux x64 | Node v22.23.4, Ubuntu 24.04.5, glibc 2.39, x86_64 | One machine outside CI |

| File | Bytes | SHA-256 |
|---|---|---|
| `assets/index-C9eG6dna.css` | 12469 | `4a8c1e44d8b25ab0724c9a26af742604a3329de2ebbfe414cd9deeba9c31a4fb` |
| `assets/index-DAeX8toZ.js` | 312686 | `d06c847ff75f7f72daf4da8e9f64cd0cf3447c3f8c9d940d8fd5be0a1f105c46` |
| `index.html` | 396 | `7f1abd9f08e5d741f0fdb367f1bda1d86353b10bb273fe2a69efe18f639dca00` |

The release's `client-manifest.json` lists the same files, sizes and hashes. Its own SHA-256, which the attestation names, is `44b8e80c6298b072c28e81eb5b2498296061092414f606dca728fc699e5d45c8`.

## What this does not do

These checks find a changed client after the fact, and only in what the server sends the person running them. A server can send the released client to whoever checks and a changed one to chosen visitors, on any visit, since the browser asks the server for the page every time. The signature shows that this repository's release workflow produced the manifest, not that the client is free of flaws, and anyone who can push a tag to the repository can have the workflow sign a changed client. webcheck compares each response's body and Content-Security-Policy only, so another header, such as Refresh, could still send a browser elsewhere. Only the client is covered; the server program is not.
