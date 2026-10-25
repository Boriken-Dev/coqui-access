# coqui-access-kit

[![Version](https://img.shields.io/badge/version-0.1.0--dev-blue.svg)](https://github.com/Boriken-Dev/coqui-access/blob/main/CHANGELOG.md#unreleased)
[![Rust version](https://img.shields.io/badge/rust-1.89%2B-blue.svg)](https://github.com/Boriken-Dev/coqui-access/blob/main/Cargo.toml)
[![License: MPL-2.0](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](https://github.com/Boriken-Dev/coqui-access/blob/main/LICENSE)
[![Docs](https://img.shields.io/badge/docs-latest-blue.svg)](https://boriken-dev.github.io/coqui-access/rust/coqui_access_kit/)
[![CI](https://img.shields.io/github/actions/workflow/status/Boriken-Dev/coqui-access/test.yml)](https://github.com/Boriken-Dev/coqui-access/actions/workflows/test.yml)

The **small, boring parts every access provider needs**, written once: typed tables a
provider reads its records through, key and password hashing, generated secrets, and private
atomic file writes. It never parses a format and has no plugin-host dependency.

## Features

- **Tables** - `Table<T>` is the source of a provider's records. `MemoryTable` is built in
  code; a file with a codec, a SQL database or an HTTP API are tables the caller implements.
  `Reloading` caches the latest snapshot and follows `changes_since`.
- **Hashing** - `sha256:<hex>` or Argon2id, self-describing, constant-time verification.
- **Secrets** - a prefix plus 256 random bits, SHA-256 with optional domain separation,
  constant-time comparison.
- **Private files** - written whole beside the target and renamed into place, `0600` on Unix.
  They move bytes and know no format.

## Installation

```bash
cargo add coqui-access-kit --git https://github.com/Boriken-Dev/coqui-access
```

## Quick start

```rust,ignore
use std::sync::Arc;
use coqui_access_kit::{MemoryTable, Reloading, SourceError, check_keys};

// Records are keyed by name; a table built in code works out of the box.
let table = Arc::new(MemoryTable::from_records(my_records));
let records = Reloading::new(table, |all| check_keys(all, 10_000))?;
let n = records.read(|all| all.len())?;
```

## Use these with your own data

The hashing and verification are plain functions and types, so a provider of your own over
your own storage does not need ours.

```rust
use coqui_access_kit::{Argon2Params, KeyHash, PasswordHasher, generate_key, verify_key};

// Bearer keys: made, said once, kept as a self-describing string.
let key = generate_key("ck_").unwrap();                 // ck_ + 43 URL-safe characters
let fast = KeyHash::Sha256.hash(&key).unwrap();         // "sha256:<64 hex>"  (the default)
let slow = KeyHash::Argon2id(Argon2Params::new(64, 1, 1).unwrap()).hash(&key).unwrap();
assert!(verify_key(&fast, key.as_bytes()) && verify_key(&slow, key.as_bytes()));
assert!(!verify_key(&fast, b"ck_other"));                // a table may mix both

// Passwords: Argon2id, with a dummy hash so an unknown name costs the same time.
let hasher = PasswordHasher::new(Argon2Params::new(64, 1, 1).unwrap()).unwrap();
let stored = hasher.hash("correct horse").unwrap();      // "$argon2id$v=19$m=64,t=1,p=1$..."
assert!(hasher.verify(Some(&stored), "correct horse"));
assert!(!hasher.verify(None, "correct horse"));          // no such account
```

`KeyHash::Sha256` is the default: it is fast and enough for a key of 256 random bits.
`Argon2id` costs one verification per Argon2id record a presented key is checked against, and
is for keys a person might have chosen. `verify_key` branches only on the algorithm prefix of
the stored string; a string naming no known algorithm never matches. `Argon2Params::default()`
is 19 MiB, 2 passes, 1 lane.

## API overview

| Module | Purpose |
| --- | --- |
| `table` | `Table<T>`, `Keyed`, `Snapshot`, `Revision`, `SourceError`, `MemoryTable`, `Reloading`, `check_keys`. |
| `hash` | `KeyHash`, `Argon2Params`, `verify_key`, `is_key_hash`, `PasswordHasher`, `verify_password`, `is_password_hash`, `generate_key`. |
| `secret` | `generate`, `identifier`, `hash`, `hash_bytes`, `same`, `is_hash`. |
| `file` | `write_private`, `read_bounded`, `stamp`, `Stamp`. |

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
