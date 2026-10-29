# coqui-access-peer

[![Version](https://img.shields.io/badge/version-0.1.0--dev-blue.svg)](https://github.com/Boriken-Dev/coqui-access/blob/main/CHANGELOG.md#unreleased)
[![Rust version](https://img.shields.io/badge/rust-1.89%2B-blue.svg)](https://github.com/Boriken-Dev/coqui-access/blob/main/Cargo.toml)
[![License: MPL-2.0](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](https://github.com/Boriken-Dev/coqui-access/blob/main/LICENSE)
[![Docs](https://img.shields.io/badge/docs-latest-blue.svg)](https://boriken-dev.github.io/coqui-access/rust/coqui_access_peer/)
[![CI](https://img.shields.io/github/actions/workflow/status/Boriken-Dev/coqui-access/test.yml)](https://github.com/Boriken-Dev/coqui-access/actions/workflows/test.yml)

**Peer certificates as accounts.** The transport (see `coqui-peer-tls`) proves a peer holds the
key of its certificate and hands over its fingerprint; this provider maps accepted
fingerprints, kept in a `Table`, to a name and groups. A certificate nobody accepted is not
authenticated and is kept for a while as waiting, with the address it came from, in a second
`Table`, so an operator can accept it.

## Features

- **Code first** - `Peers::builder()` works out of the box with in-memory tables.
- **Any source** - an `Arc<dyn Table<PeerRecord>>` for the peers and an
  `Arc<dyn Table<Unaccepted>>` for the waiting list.
- **Waiting list** - unaccepted fingerprints under coqui-peer's `WaitingQueue`: one place per
  source (an IPv4 address or an IPv6 /64), 16 in all, the same certificate from one source
  written down at most once a minute; each bound is an option.
- **Any spelling** - `sha256:<hex>`, bare hex, colon-separated hex or grouped base32.

## Installation

```bash
cargo add coqui-access-peer --git https://github.com/Boriken-Dev/coqui-access
```

Build `coqui-access-peer-plugin` for the loadable library.

## Quick start

```rust
use coqui_access::{Attempt, Authenticator, Verdict};
use coqui_access_peer::{DEFAULT_WAITING_LIMITS, Peers};

let peers = Peers::builder().waiting_limits(DEFAULT_WAITING_LIMITS).build().unwrap();
let verdict = peers
    .authenticate(Attempt { certificate: Some("not a fingerprint".into()), ..Attempt::default() })
    .unwrap();
assert_eq!(verdict, Verdict::Unknown);
```

Peers of your own come from a table: `Peers::builder().table(table).build()?`, where `table`
is a `MemoryTable::from_records([PeerRecord::new(id, name, &fingerprint)])` or your own
`Table<PeerRecord>`; `.waiting(table)` keeps the waiting list somewhere else. The records
derive guatiao's value traits, so any table keeps them.

The loadable plugin (provider id `coqui_access_peer`) is configured with a `source`, for example
`{ "source": { "file": { "path": "peers.toml", "format": "toml" } } }` (`format` is `toml` or
`json`); the waiting list defaults to
`peers.toml.waiting` beside a file source and can be given its own `waiting` source. With no
`source` both live in memory.

## API overview

| Item | Purpose |
| --- | --- |
| `Peers` | The provider: `builder()` and the three kinds. |
| `PeersBuilder` | Options: `table`, `waiting`, `max_peers`, `waiting_limits`; `build`. |
| `PeerRecord`, `Unaccepted` | The records the two tables keep; guatiao value traits. |

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
