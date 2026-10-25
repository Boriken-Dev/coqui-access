# coqui-net-acl

[![Version](https://img.shields.io/badge/version-0.1.0--dev-blue.svg)](https://github.com/Boriken-Dev/coqui-access/blob/main/CHANGELOG.md#unreleased)
[![Rust version](https://img.shields.io/badge/rust-1.89%2B-blue.svg)](https://github.com/Boriken-Dev/coqui-access/blob/main/Cargo.toml)
[![License: MPL-2.0](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](https://github.com/Boriken-Dev/coqui-access/blob/main/LICENSE)
[![Docs](https://img.shields.io/badge/docs-latest-blue.svg)](https://boriken-dev.github.io/coqui-access/rust/coqui_net_acl/)
[![CI](https://img.shields.io/github/actions/workflow/status/Boriken-Dev/coqui-access/test.yml)](https://github.com/Boriken-Dev/coqui-access/actions/workflows/test.yml)

An **ordered access control list** like a router ACL: rules are read top to bottom, the first
match wins, and a default action applies when none does (deny, unless you set it). It has no
TLS dependency and works on any listener, before the first byte is read. See the
[documentation](https://boriken-dev.github.io/coqui-access/).

## Features

- **Source and destination rules** — a source network, an optional local address and port.
- **Two evaluation points** — at accept time from addresses alone, and after a handshake with
  the verified peer fingerprint.
- **Router-style listing** — `Display` prints `10 permit 10.6.0.0/16`, ...
- **Plain text form** with the `serde` feature.

## Installation

```bash
cargo add coqui-net-acl --git https://github.com/Boriken-Dev/coqui-access
```

| Feature | Adds | Needed for |
| --- | --- | --- |
| `serde` | `serde` | reading and writing an ACL as TOML or JSON |

## Quick start

```rust,ignore
use coqui_net_acl::{Acl, Action, IpNet, Outcome, Rule};

let mut acl = Acl::default();                       // no rules, default deny
acl.push(Rule::new(Action::Permit, "10.6.0.0/16".parse::<IpNet>().unwrap()));
let decision = acl.decide("10.6.1.2:5000".parse().unwrap(), "10.6.0.1:443".parse().unwrap());
assert_eq!(decision.outcome, Outcome::Permit);
```

In TOML (`serde` feature):

```toml
default = "deny"

[[rule]]
action = "permit"
source = "10.9.0.0/16"
destination = "10.6.20.5"     # optional: the local address, or a CIDR
port = "7000-7100"            # optional: a port or an inclusive range

[[rule]]
action = "deny"
source = "any"
```

## API overview

| Item | Purpose |
| --- | --- |
| `Acl` | `rules`, `default`; `push`, `prepend`, `decide`, `decide_peer`, `permits_bind`, `weakened`. |
| `Rule` | `action`, `source`, `destination?`, `port?`, `fingerprint?`, `log`. |
| `IpNet`, `PortRange` | Parsed networks (`any`, a host, CIDR) and ports. |
| `Outcome`, `AclDecision`, `BindDecision` | What was decided, and by which rule. |

## Development

```bash
cargo test -p coqui-net-acl --all-features
cargo clippy -p coqui-net-acl --all-targets --all-features -- -D warnings
```

### Releasing

This project follows [Semantic Versioning](https://semver.org/) and keeps a
[`CHANGELOG.md`](https://github.com/Boriken-Dev/coqui-access/blob/main/CHANGELOG.md).
Pushing a tag matching `v*` triggers the release workflow of the repository.

## License

MPL-2.0 — see [LICENSE](https://github.com/Boriken-Dev/coqui-access/blob/main/LICENSE).
