# coqui-access

[![Version](https://img.shields.io/badge/version-0.1.0--dev-blue.svg)](https://github.com/Boriken-Dev/coqui-access/blob/main/CHANGELOG.md#unreleased)
[![Rust version](https://img.shields.io/badge/rust-1.89%2B-blue.svg)](https://github.com/Boriken-Dev/coqui-access/blob/main/Cargo.toml)
[![License: MPL-2.0](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](https://github.com/Boriken-Dev/coqui-access/blob/main/LICENSE)
[![Docs](https://img.shields.io/badge/docs-latest-blue.svg)](https://boriken-dev.github.io/coqui-access/)
[![CI](https://img.shields.io/github/actions/workflow/status/Boriken-Dev/coqui-access/test.yml)](https://github.com/Boriken-Dev/coqui-access/actions/workflows/test.yml)

Shared building blocks for **who is asking and may they**: authentication, identity
directory, authorization and account-management kinds on
[Guatiao](https://github.com/Boriken-Dev/guatiao), ready-made providers for local accounts,
bearer keys, LDAP, reverse-proxy headers and peer certificates, and a role authorizer. A host loads the providers it
wants; none of them knows the host. See the [documentation](https://boriken-dev.github.io/coqui-access/).

## Features

- **Four small kinds** — `coqui_authenticator` (credentials to a lookup), `coqui_directory`
  (lookup to a person), `coqui_authorizer` (person, action, resource to a decision) and the
  optional `coqui_accounts` (list, put, remove, waiting).
- **Providers as plugins** — each provider is an ordinary library plus a one-line `cdylib`.
- **Peer certificates as accounts** — fingerprints from [coqui-peer-tls](https://github.com/Boriken-Dev/coqui-peer-tls)
  mapped to identities.

## Installation

The crates are not published; depend on them by git revision:

```toml
coqui-access = { git = "https://github.com/Boriken-Dev/coqui-access", rev = "<commit>" }
```

The mutual-TLS crate [coqui-peer-tls](https://github.com/Boriken-Dev/coqui-peer-tls) and the
access control list crate [coqui-net-acl](https://github.com/Boriken-Dev/coqui-net-acl) live in
their own repositories.

Build the provider libraries with `cargo build --release -p coqui-access-key-plugin` (and the
other `-plugin` crates) against the same Guatiao revision as the host.

## Quick start

Open a key table and check a key, without any plugin host:

```text
cargo test -p coqui-access-key
```

A host loads a plugin library, builds `coqui_access_key` with `{ path = "keys.toml" }` and
calls `authenticate`. The per-crate READMEs show each provider's configuration.

## API overview

| Crate | Purpose |
| --- | --- |
| `coqui-access` | The kinds and models; re-exports `guatiao`. |
| `coqui-access-kit` | Secret generation and hashing, private atomic files, reloading TOML tables. |
| `coqui-roles` | First-match role authorizer with configurable scope kinds. |
| `coqui-access-local` | Argon2id passwords in a TOML file. |
| `coqui-access-key` | Hashed bearer keys in a TOML file. |
| `coqui-access-ldap` | LDAP and Active Directory. |
| `coqui-access-proxy` | Trusted reverse-proxy identity headers. |
| `coqui-access-peer` | Peer certificate fingerprints mapped to identities. |

## Development

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
```

### Releasing

This project follows [Semantic Versioning](https://semver.org/) and keeps a
[`CHANGELOG.md`](CHANGELOG.md). Pushing a tag matching `v*` triggers the release
workflow: test gate, a strict docs build as a gate, then a GitHub release. The release
workflow never deploys the docs site itself: for a final release its last job dispatches the
docs workflow at the tag, which owns every Pages deploy.

## License

MPL-2.0 — see [LICENSE](LICENSE).
