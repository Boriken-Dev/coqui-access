# coqui-access-acl

[![Version](https://img.shields.io/badge/version-0.1.0--dev-blue.svg)](https://github.com/Boriken-Dev/coqui-access/blob/main/CHANGELOG.md#unreleased)
[![Rust version](https://img.shields.io/badge/rust-1.89%2B-blue.svg)](https://github.com/Boriken-Dev/coqui-access/blob/main/Cargo.toml)
[![License: MPL-2.0](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](https://github.com/Boriken-Dev/coqui-access/blob/main/LICENSE)
[![Docs](https://img.shields.io/badge/docs-latest-blue.svg)](https://boriken-dev.github.io/coqui-access/rust/coqui_access_acl/)
[![CI](https://img.shields.io/github/actions/workflow/status/Boriken-Dev/coqui-access/test.yml)](https://github.com/Boriken-Dev/coqui-access/actions/workflows/test.yml)

Access control lists **on items**: each item carries a list of entries naming who may do
what to it, and this crate decides a request against that list. **One model writes each
product's lists as they are**: Windows and NFSv4 (ordered allow and deny, inheritance
flags), POSIX.1e (classes and a mask), NetBox and TrueNAS RBAC (additive), Proxmox (a walk
where the most specific level wins). The consumer stores items and their lists; the crate
evaluates. See the [narrative docs](https://boriken-dev.github.io/coqui-access/acl/).

## Features

- **Named rights per item type** - a `RightsSchema` turns names into bits of a growable
  `Rights` set; aliases stand for several (generic rights, NFSv4 basic permissions, Proxmox
  roles), and a cancelling name refuses everything.
- **Five evaluation modes** - `Ordered`, `DenyOverrides` (the default, since no order can be
  wrong), `Additive`, `Posix`, `MostSpecific`. A `Decision` says what was granted, what was
  denied and which entry decided.
- **Inheritance, both ways** - copied at creation (`Acl::inherited_by`, Windows' flag table)
  or walked at check time (`AclStore`, Proxmox paths).
- **Options, not floors** - every bound is a default the caller lifts, and what weakens a
  decision (`OnMissing::AllowAll`, an `Everyone` allow) is reported as data.

## Installation

```bash
cargo add coqui-access-acl --git https://github.com/Boriken-Dev/coqui-access
```

No Cargo features. It depends on `coqui-access` alone.

## Quick start

```rust
use coqui_access::Person;
use coqui_access_acl::{Acl, Context, Entry, Mode, RightsSchema};

let schema = RightsSchema::builder()
    .rights(["read", "write"])
    .alias("full", ["read", "write"])
    .build()?;
let acl = Acl::new(Mode::DenyOverrides)
    .entry(Entry::allow("group:staff".parse::<coqui_access::Subject>()?, ["full"]))
    .entry(Entry::deny("account:guest".parse::<coqui_access::Subject>()?, ["write"]));

let guest = Person {
    name: "guest".into(),
    groups: vec!["staff".into()],
    ..Person::default()
};
let decision = acl.check(&Context::new(&schema).person(&guest), &schema.rights(["write"])?)?;
assert!(!decision.allowed);
assert_eq!(decision.deciding, Some(1));
# Ok::<(), Box<dyn std::error::Error>>(())
```

## API overview

| Item | Purpose |
| --- | --- |
| `Rights`, `RightsSchema` | Rights as bits, and the names and aliases of one item type. |
| `Principal`, `Entry`, `Effect`, `Inherit` | One line of a list: who, allow or deny, which rights, how it is inherited. |
| `Acl`, `Mode`, `ItemAcl` | A list, how its entries combine, and an item's list with its owner. |
| `Context`, `Decision` | Who asks and with what options; what the check came to. |
| `Child`, `AclStore` | Copied inheritance for a new child; walked inheritance over the consumer's tree. |
| `Options`, `Limits`, `OnMissing`, `Weakening` | Bounds and choices, and what they weaken. |
| `Conditions`, `Truth` | The consumer's decision on an entry's condition. |
| `AclError` | Why a schema, list or walk could not be used. |

## Development

```bash
cargo test -p coqui-access-acl
cargo clippy -p coqui-access-acl --all-targets -- -D warnings
```

### Releasing

This project follows [Semantic Versioning](https://semver.org/) and keeps a
[`CHANGELOG.md`](https://github.com/Boriken-Dev/coqui-access/blob/main/CHANGELOG.md).
Pushing a tag matching `v*` triggers the release workflow of the repository.

## License

MPL-2.0 — see [LICENSE](https://github.com/Boriken-Dev/coqui-access/blob/main/LICENSE).
