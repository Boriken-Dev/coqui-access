# coqui-access-local

[![Version](https://img.shields.io/badge/version-0.1.0--dev-blue.svg)](https://github.com/Boriken-Dev/coqui-access/blob/main/CHANGELOG.md#unreleased)
[![Rust version](https://img.shields.io/badge/rust-1.89%2B-blue.svg)](https://github.com/Boriken-Dev/coqui-access/blob/main/Cargo.toml)
[![License: MPL-2.0](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](https://github.com/Boriken-Dev/coqui-access/blob/main/LICENSE)
[![Docs](https://img.shields.io/badge/docs-latest-blue.svg)](https://boriken-dev.github.io/coqui-access/rust/coqui_access_local/)
[![CI](https://img.shields.io/github/actions/workflow/status/Boriken-Dev/coqui-access/test.yml)](https://github.com/Boriken-Dev/coqui-access/actions/workflows/test.yml)

**Local accounts** in one TOML file: names and Argon2id password hashes, groups, and the
account-management kind to make, change and remove them. It is an authenticator, a directory
and an `Accounts` provider over the same file, which is read again whenever another process
writes it.

## Features

- **Argon2id** hashes only; a name that is not kept costs the same time as a wrong password.
- **One file** — bounded to 1 MiB, written atomically and owner-readable only.
- **Account management** — `put` makes an account (a password is required for a new one),
  changes groups or the disabled flag, or replaces the password.

## Installation

```bash
cargo add coqui-access-local --git https://github.com/Boriken-Dev/coqui-access
```

Build `coqui-access-local-plugin` for the loadable library.

## Quick start

Provider id `coqui_access_local`, configuration:

```toml
path = "/etc/example/accounts.toml"
```

The file:

```toml
[[accounts]]
id = "person-1"
name = "alice"
password_hash = "$argon2id$..."   # made by coqui_access_local::hash_password or Accounts::put
groups = ["staff"]
```

## API overview

| Item | Purpose |
| --- | --- |
| `LocalAccounts` | The provider: `open(path)`, and the `Authenticator`, `Directory` and `Accounts` kinds. |
| `LocalAccountsConfig` | The Guatiao configuration: `path`. |
| `hash_password` | Argon2id hash for an account record. |

## Development

```bash
cargo test -p coqui-access-local --all-features
cargo clippy -p coqui-access-local --all-targets --all-features -- -D warnings
```

### Releasing

This project follows [Semantic Versioning](https://semver.org/) and keeps a
[`CHANGELOG.md`](https://github.com/Boriken-Dev/coqui-access/blob/main/CHANGELOG.md).
Pushing a tag matching `v*` triggers the release workflow of the repository.

## License

MPL-2.0 — see [LICENSE](https://github.com/Boriken-Dev/coqui-access/blob/main/LICENSE).
