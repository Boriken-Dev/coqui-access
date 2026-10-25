# coqui-access-peer

[![Version](https://img.shields.io/badge/version-0.1.0--dev-blue.svg)](https://github.com/Boriken-Dev/coqui-access/blob/main/CHANGELOG.md#unreleased)
[![Rust version](https://img.shields.io/badge/rust-1.89%2B-blue.svg)](https://github.com/Boriken-Dev/coqui-access/blob/main/Cargo.toml)
[![License: MPL-2.0](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](https://github.com/Boriken-Dev/coqui-access/blob/main/LICENSE)
[![Docs](https://img.shields.io/badge/docs-latest-blue.svg)](https://boriken-dev.github.io/coqui-access/rust/coqui_access_peer/)
[![CI](https://img.shields.io/github/actions/workflow/status/Boriken-Dev/coqui-access/test.yml)](https://github.com/Boriken-Dev/coqui-access/actions/workflows/test.yml)

**Peer certificates as accounts.** The transport (see `coqui-peer`) proves a peer holds the
key of its certificate and hands over its fingerprint; this provider maps accepted
fingerprints to a name and groups. A certificate nobody accepted is not authenticated and is
kept for a while as waiting, with the address it came from, so an operator can accept it.

## Features

- **Authenticator, directory and `Accounts`** over one TOML file, read again when it changes.
- **Waiting list** — the last few unaccepted fingerprints, one place per address, rewritten at
  most once a minute per certificate.
- **Any spelling** — `sha256:<hex>`, bare hex, colon-separated hex or grouped base32.

## Installation

```bash
cargo add coqui-access-peer --git https://github.com/Boriken-Dev/coqui-access
```

Build `coqui-access-peer-plugin` for the loadable library.

## Quick start

Provider id `coqui_access_peer`, configuration:

```toml
path = "/etc/example/peers.toml"
```

The file (the waiting list is kept beside it in `peers.toml.waiting`):

```toml
[[peers]]
id = "service-1"
name = "site-a"
certificate = "sha256:3f157512c98267c4b88cf6483c66abdd5a19a15de27f5a5ed93a8978d1a4173c"
groups = ["site-a"]
```

## API overview

| Item | Purpose |
| --- | --- |
| `Peers` | The provider: `open(path)` and the three kinds. |
| `PeersConfig` | The Guatiao configuration: `path`. |

## Development

```bash
cargo test -p coqui-access-peer --all-features
cargo clippy -p coqui-access-peer --all-targets --all-features -- -D warnings
```

### Releasing

This project follows [Semantic Versioning](https://semver.org/) and keeps a
[`CHANGELOG.md`](https://github.com/Boriken-Dev/coqui-access/blob/main/CHANGELOG.md).
Pushing a tag matching `v*` triggers the release workflow of the repository.

## License

MPL-2.0 — see [LICENSE](https://github.com/Boriken-Dev/coqui-access/blob/main/LICENSE).
