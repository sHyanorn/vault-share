# Security Policy

vault-share is an end-to-end encrypted file sharing service. Its security documentation lives in [docs/security](docs/security): the [threat model](docs/security/THREAT_MODEL.md), the [test report](docs/security/TEST_REPORT.md) and the [findings](docs/security/FINDINGS.md) so far.

## Supported Versions

The project has no releases. Only the latest commit on `main` is supported, and fixes land there.

## Reporting a Vulnerability

Report privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**, or go to <https://github.com/sHyanorn/vault-share/security/advisories/new>. Do not open a public issue.

Please include:

- the affected component (server, web client, deployment files) and the commit you tested
- steps to reproduce, ideally against a local `docker compose up`
- what an attacker gains

## What to Expect

| Step | Target |
|---|---|
| Acknowledgement | within 7 days |
| Assessment, with a severity and a plan | within 14 days |
| Fix for a confirmed High or Medium issue | within 30 days |

Each confirmed issue is recorded in [FINDINGS.md](docs/security/FINDINGS.md) and published as a GitHub security advisory once fixed. Reporters are credited unless they prefer not to be. Please keep details private until the advisory is out, or for 90 days after your report, whichever comes first.

## Scope

In scope:

- code in this repository, and instances you run from it yourself
- anything that lets the server or the network read file contents or file names, or learn the secret in a link
- ways around download limits, expiry, delete tokens, rate limits or the storage quota
- anything that lets the server learn an account password or open an account key, signs in without the password or the second factor, or keeps a session alive past sign-out or its timeouts

Out of scope:

- the limitations stated in the threat model, such as a compromised server serving malicious code, or a leaked link
- volumetric denial of service, and load or automated scans against instances you do not run
- vulnerabilities in third-party dependencies without a demonstrated impact on vault-share; please report those upstream
- social engineering and physical attacks

## Safe Harbor

Research done in good faith under this policy is considered authorized. The maintainer will not pursue or support legal action against it and will work with you to understand and fix the issue.

Good faith means:

- testing only instances you run
- stopping and reporting as soon as you find a vulnerability
- never accessing, keeping or sharing other people's data
- not degrading the service for others
