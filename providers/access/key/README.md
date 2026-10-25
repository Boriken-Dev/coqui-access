# coqui-access-key

[![Version](https://img.shields.io/badge/version-0.1.0--dev-blue.svg)](https://github.com/Boriken-Dev/coqui-access/blob/main/CHANGELOG.md#unreleased)
[![Rust version](https://img.shields.io/badge/rust-1.89%2B-blue.svg)](https://github.com/Boriken-Dev/coqui-access/blob/main/Cargo.toml)
[![License: MPL-2.0](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](https://github.com/Boriken-Dev/coqui-access/blob/main/LICENSE)
[![Docs](https://img.shields.io/badge/docs-latest-blue.svg)](https://boriken-dev.github.io/coqui-access/rust/coqui_access_key/)
[![CI](https://img.shields.io/github/actions/workflow/status/Boriken-Dev/coqui-access/test.yml)](https://github.com/Boriken-Dev/coqui-access/actions/workflows/test.yml)

**Bearer keys** for clients that have nobody to type a password: a relay, a script, a device.
A key is 256 random bits made here, shown once, and kept only as its SHA-256. Each key can be
disabled, expire or be removed alone. Authenticator, directory and `Accounts` provider over
one TOML file that is read again whenever it changes.

## Features

- **Hash only** — the table holds digests; a leaked table presents nothing.
- **Your prefix** — keys begin with a configurable prefix (default `ck_`), so a key is
  recognized where it turns up.
- **Rotation** — `put` with nothing else said makes the account another key and the old one
  stops being taken.

## Installation

```bash
cargo add coqui-access-key --git https://github.com/Boriken-Dev/coqui-access
```

Build `coqui-access-key-plugin` for the loadable library.

## Quick start

Provider id `coqui_access_key`, configuration:

```toml
path = "/etc/example/keys.toml"
prefix = "ck_"          # optional
```

The file:

```toml
[[keys]]
id = "robot-1"
name = "relay"
hash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"   # SHA-256 of the key
groups = ["station"]
```

## API overview

| Item | Purpose |
| --- | --- |
| `Keys` | The provider: `open(path, prefix)`, `new_key`, and the three kinds. |
| `KeysConfig` | The Guatiao configuration: `path`, `prefix`. |
| `DEFAULT_PREFIX` | `"ck_"`. |

## Development

```bash
cargo test -p coqui-access-key --all-features
cargo clippy -p coqui-access-key --all-targets --all-features -- -D warnings
```

### Releasing

This project follows [Semantic Versioning](https://semver.org/) and keeps a
[`CHANGELOG.md`](https://github.com/Boriken-Dev/coqui-access/blob/main/CHANGELOG.md).
Pushing a tag matching `v*` triggers the release workflow of the repository.

## License

MPL-2.0 — see [LICENSE](https://github.com/Boriken-Dev/coqui-access/blob/main/LICENSE).
