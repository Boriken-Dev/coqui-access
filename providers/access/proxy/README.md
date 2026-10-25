# coqui-access-proxy

[![Version](https://img.shields.io/badge/version-0.1.0--dev-blue.svg)](https://github.com/Boriken-Dev/coqui-access/blob/main/CHANGELOG.md#unreleased)
[![Rust version](https://img.shields.io/badge/rust-1.89%2B-blue.svg)](https://github.com/Boriken-Dev/coqui-access/blob/main/Cargo.toml)
[![License: MPL-2.0](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](https://github.com/Boriken-Dev/coqui-access/blob/main/LICENSE)
[![Docs](https://img.shields.io/badge/docs-latest-blue.svg)](https://boriken-dev.github.io/coqui-access/rust/coqui_access_proxy/)
[![CI](https://img.shields.io/github/actions/workflow/status/Boriken-Dev/coqui-access/test.yml)](https://github.com/Boriken-Dev/coqui-access/actions/workflows/test.yml)

**Reverse-proxy identity headers** as an authenticator: a request from a trusted proxy address
carries the account name in a header or a client-certificate subject, and the configured
directory supplies groups. Group claims in headers are never trusted.

## Features

- **Trusted networks only** — addresses and CIDR ranges; an empty list trusts nobody.
- **Header or subject** — an account header, or a field of a certificate subject.
- **Ambiguity refused** — a header sent twice is `Invalid`.

## Installation

```bash
cargo add coqui-access-proxy --git https://github.com/Boriken-Dev/coqui-access
```

Build `coqui-access-proxy-plugin` for the loadable library.

## Quick start

Provider id `coqui_access_proxy`, configuration:

```toml
trusted = ["10.0.0.0/24", "::1"]
user_header = "x-remote-user"      # optional; the default unless subject_header is set
subject_header = ""                # optional
subject_field = "CN"               # used with subject_header
```

Only configure headers the proxy overwrites.

## API overview

| Item | Purpose |
| --- | --- |
| `ProxyWord` | The provider: `new(config)` and the `Authenticator` kind. |
| `ProxyWordConfig` | The Guatiao configuration. |
| `field_of` | Reads a field from a `CN=a,O=b` or `/O=b/CN=a` subject. |

## Development

```bash
cargo test -p coqui-access-proxy --all-features
cargo clippy -p coqui-access-proxy --all-targets --all-features -- -D warnings
```

### Releasing

This project follows [Semantic Versioning](https://semver.org/) and keeps a
[`CHANGELOG.md`](https://github.com/Boriken-Dev/coqui-access/blob/main/CHANGELOG.md).
Pushing a tag matching `v*` triggers the release workflow of the repository.

## License

MPL-2.0 — see [LICENSE](https://github.com/Boriken-Dev/coqui-access/blob/main/LICENSE).
