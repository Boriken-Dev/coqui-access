# coqui-access

[![Version](https://img.shields.io/badge/version-0.1.0--dev-blue.svg)](https://github.com/Boriken-Dev/coqui-access/blob/main/CHANGELOG.md#unreleased)
[![Rust version](https://img.shields.io/badge/rust-1.89%2B-blue.svg)](https://github.com/Boriken-Dev/coqui-access/blob/main/Cargo.toml)
[![License: MPL-2.0](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](https://github.com/Boriken-Dev/coqui-access/blob/main/LICENSE)
[![Docs](https://img.shields.io/badge/docs-latest-blue.svg)](https://boriken-dev.github.io/coqui-access/)
[![CI](https://img.shields.io/github/actions/workflow/status/Boriken-Dev/coqui-access/test.yml)](https://github.com/Boriken-Dev/coqui-access/actions/workflows/test.yml)

Shared building blocks for **who is asking and may they**: authentication, identity
directory, authorization and account-management kinds on
[Guatiao](https://github.com/Boriken-Dev/guatiao), ready-made providers for password accounts,
bearer keys, LDAP, the operating system's accounts, reverse-proxy headers and peer
certificates, a role authorizer and access control lists on items. A host loads the providers it
wants; none of them knows the host. See the [documentation](https://boriken-dev.github.io/coqui-access/).

## Features

- **Four small kinds** — `coqui_authenticator` (credentials to a lookup), `coqui_directory`
  (lookup to a person), `coqui_authorizer` (person, action, resource to a decision) and the
  optional `coqui_accounts` (list, put, remove, waiting).
- **Code first** — every provider is built with a builder over a typed `Table` of records
  (memory by default; a file, a SQL database or an HTTP API are tables you supply). The
  libraries name no format: records derive guatiao's value traits, and a plugin hands the
  kit's file table the serde format it offers.
- **Providers as plugins** — each provider library has a `cdylib` plugin crate, which is where
  a storage format is chosen from its Guatiao config.
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

Make a key and check it, without any plugin host:

```rust
use coqui_access::{AccountPut, Accounts, Attempt, Authenticator, Verdict};
use coqui_access_key::Keys;

let keys = Keys::builder().build().unwrap();
let made = keys
    .put(AccountPut { name: "relay".into(), ..AccountPut::default() })
    .unwrap();
let verdict = keys
    .authenticate(Attempt { secret: made.secret, ..Attempt::default() })
    .unwrap();
assert!(matches!(verdict, Verdict::Valid(_)));
```

A host loads a plugin library and builds `coqui_access_key` from its Guatiao config, for
example `{ "source": { "file": { "path": "keys.toml" } } }`; the `source` object names where
the records live (`file` is the one implemented; others can be added without touching the
other options). The per-crate READMEs show each provider's configuration.

## API overview

| Crate | Purpose |
| --- | --- |
| `coqui-access` | The kinds and models; re-exports `guatiao`. |
| `coqui-access-kit` | `Table` sources, key and password hashing to use with your own data, secrets, private atomic file writes. |
| `coqui-roles` | First-match role authorizer with configurable scope kinds. |
| `coqui-access-acl` | Access control lists on items: rights, entries, evaluation modes, inheritance. |
| `coqui-access-password` | Argon2id passwords in any table. |
| `coqui-access-key` | Hashed bearer keys (SHA-256 or Argon2id) in any table. |
| `coqui-access-ldap` | LDAP and Active Directory. |
| `coqui-access-proxy` | Trusted reverse-proxy identity headers. |
| `coqui-access-system` | The operating system's accounts: PAM and NSS, or a Windows logon. |
| `coqui-access-mtls` | Peer certificate fingerprints, in any table, mapped to identities. |

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
