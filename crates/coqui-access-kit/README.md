# coqui-access-kit

[![Version](https://img.shields.io/badge/version-0.1.0--dev-blue.svg)](https://github.com/Boriken-Dev/coqui-access/blob/main/CHANGELOG.md#unreleased)
[![Rust version](https://img.shields.io/badge/rust-1.89%2B-blue.svg)](https://github.com/Boriken-Dev/coqui-access/blob/main/Cargo.toml)
[![License: MPL-2.0](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](https://github.com/Boriken-Dev/coqui-access/blob/main/LICENSE)
[![Docs](https://img.shields.io/badge/docs-latest-blue.svg)](https://boriken-dev.github.io/coqui-access/rust/coqui_access_kit/)
[![CI](https://img.shields.io/github/actions/workflow/status/Boriken-Dev/coqui-access/test.yml)](https://github.com/Boriken-Dev/coqui-access/actions/workflows/test.yml)

The **small, boring parts every access provider needs**, written once: secrets that are
generated and hashed, files that are written atomically and privately, and TOML tables that
reload when another process writes them. It has no plugin-host dependency.

## Features

- **Secrets** — a prefix plus 256 random bits, SHA-256 with optional domain separation,
  constant-time comparison.
- **Private files** — written whole beside the target and renamed into place, `0600` on Unix.
- **Reloading tables** — a bounded TOML document that is read again when its file changes.

## Installation

```bash
cargo add coqui-access-kit --git https://github.com/Boriken-Dev/coqui-access
```

## Quick start

```rust,ignore
use coqui_access_kit::secret;

let key = secret::generate("ck_")?;          // ck_ + 43 URL-safe characters
let kept = secret::hash(&key, None);          // 64 lowercase hex characters
assert!(secret::same(&kept, &secret::hash(&key, None)));
```

## API overview

| Module | Purpose |
| --- | --- |
| `secret` | `generate`, `identifier`, `hash`, `same`, `is_hash`. |
| `file` | `write_private`, `read_bounded`, `stamp`, `Stamp`. |
| `store` | `Store<T>`: `open`, `read`, `change`. |

## Development

```bash
cargo test -p coqui-access-kit --all-features
cargo clippy -p coqui-access-kit --all-targets --all-features -- -D warnings
```

### Releasing

This project follows [Semantic Versioning](https://semver.org/) and keeps a
[`CHANGELOG.md`](https://github.com/Boriken-Dev/coqui-access/blob/main/CHANGELOG.md).
Pushing a tag matching `v*` triggers the release workflow of the repository.

## License

MPL-2.0 — see [LICENSE](https://github.com/Boriken-Dev/coqui-access/blob/main/LICENSE).
