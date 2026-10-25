# coqui-roles

[![Version](https://img.shields.io/badge/version-0.1.0--dev-blue.svg)](https://github.com/Boriken-Dev/coqui-access/blob/main/CHANGELOG.md#unreleased)
[![Rust version](https://img.shields.io/badge/rust-1.89%2B-blue.svg)](https://github.com/Boriken-Dev/coqui-access/blob/main/Cargo.toml)
[![License: MPL-2.0](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](https://github.com/Boriken-Dev/coqui-access/blob/main/LICENSE)
[![Docs](https://img.shields.io/badge/docs-latest-blue.svg)](https://boriken-dev.github.io/coqui-access/rust/coqui_roles/)
[![CI](https://img.shields.io/github/actions/workflow/status/Boriken-Dev/coqui-access/test.yml)](https://github.com/Boriken-Dev/coqui-access/actions/workflows/test.yml)

A **first-match role authorizer**: named roles list actions, ordered rules bind an account,
person or group to a role at a scope, and anything not allowed is denied. Scope kinds such as
`site` or `project` are configured by the deployment; the crate has no vocabulary of its own.

## Features

- **Roles and rules in TOML** — bounded in size, with unknown keys rejected.
- **Configurable scopes** — `*` or `<kind>:<id>` for the kinds you allow, or any kind.
- **A Guatiao provider** — `coqui_roles` implements `Authorizer`; `coqui-roles-plugin` is its
  loadable library.

## Installation

```bash
cargo add coqui-roles --git https://github.com/Boriken-Dev/coqui-access
```

## Quick start

```rust,ignore
use coqui_roles::RoleAuthorizer;

let policy = RoleAuthorizer::from_toml(
    r#"
    [role.viewer]
    actions = ["document.read"]

    [[rule]]
    subject = "group:staff"
    scope = "site:north"
    role = "viewer"
    "#,
    &["site".to_owned()],
)?;
```

As a provider the configuration is `{ policy_toml = "...", scope_kinds = ["site"] }`.

## API overview

| Item | Purpose |
| --- | --- |
| `RoleAuthorizer` | `from_toml`, `load`; implements `Authorizer`. |
| `RoleAuthorizerProvider`, `RoleAuthorizerConfig` | The provider `coqui_roles` and its configuration. |
| `RolePolicyError` | An invalid or unreadable policy. |

## Development

```bash
cargo test -p coqui-roles --all-features
cargo clippy -p coqui-roles --all-targets --all-features -- -D warnings
```

### Releasing

This project follows [Semantic Versioning](https://semver.org/) and keeps a
[`CHANGELOG.md`](https://github.com/Boriken-Dev/coqui-access/blob/main/CHANGELOG.md).
Pushing a tag matching `v*` triggers the release workflow of the repository.

## License

MPL-2.0 — see [LICENSE](https://github.com/Boriken-Dev/coqui-access/blob/main/LICENSE).
