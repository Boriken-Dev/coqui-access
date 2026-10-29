# coqui-access — repository orientation

Contributor guidance for this checkout. Each crate has an `AGENTS.md` API header beside its
README; those headers describe the public API and ship with the crate.

| Header | Covers |
| --- | --- |
| `crates/coqui-access/AGENTS.md` | Kinds, models, error helpers, the pinned contract. |
| `crates/coqui-access-kit/AGENTS.md` | Secrets, private files, reloading tables. |
| `crates/coqui-roles/AGENTS.md` | Role authorizer. |
| `crates/coqui-access-acl/AGENTS.md` | Access control lists on items: rights, entries, evaluation modes, inheritance, `AclAuthorizer`. |
| `providers/access/<name>/AGENTS.md` | One provider each: local, key, ldap, proxy, peer, system. |

## Layout

| Path | What |
| --- | --- |
| `crates/` | Library crates: kinds, kit, roles, item ACLs. The TLS peer crate and the network address list crate (`coqui-net-acl`) live in their own repositories and come from crates.io. |
| `providers/access/<name>/` | A provider as an ordinary library. |
| `providers/access/<name>/plugin/`, `crates/coqui-roles/plugin/` | The same provider as a `cdylib`: its Guatiao config, the `providers!` line, and (local, key, peer) the storage formats it offers (`toml`, `json`) as a kit `Codec`. |
| `docs/`, `mkdocs.yml` | Narrative site; Rust API docs are published under `/rust/`. |

## Commands

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
```

Regenerate the kind description after a deliberate contract change:
`GUATIAO_WRITE_HEADER=1 cargo test -p coqui-access --test contract`.

## Rules

- Kind names and the hashes of required methods are an ABI. A new method has a default body
  and comes after every required one; the contract test names a break.
- Providers depend on `coqui-access`, `coqui-access-kit` and at most `coqui-peer-tls`,
  `coqui-peer` and `coqui-net-acl`; never on a host or on each other. Code two providers share belongs in a crate under `crates/`.
- `coqui-peer-tls` is pinned to an exact crates.io version (`=0.0.0-alpha.0`) in
  `[workspace.dependencies]`. A change it needs that is not published yet pins a commit of
  that repository's `main` by git revision, never a branch, until it is released.
- The shared libraries are code first: builders over `coqui_access_kit::Table`, records and
  configuration with guatiao derives, no `from_toml`/`from_json`, no format crate in a normal
  dependency under any feature (a dev-dependency for tests is fine), nothing read from a file
  or the environment unless the caller asks. A storage format is chosen only in a `-plugin`
  crate, which implements the kit's `Codec` over the format crate it depends on.
- A secret never reaches a log, a `Debug` output or an error message.
- Limits are defaults the caller can change; do not add a refusal a caller cannot lift.

## CI and release

- `.github/workflows/test.yml` runs fmt, clippy, tests and strict rustdoc on Linux, macOS and
  Windows, on stable and Rust 1.89, on demand and on `ci-*` tags.
- `.github/workflows/docs.yml` builds the narrative site and Rust API reference and deploys
  Pages. `release.yml` gates a source release on tests and a strict docs build; a `v*` tag
  requires the owner's authorization for that release.
- `.github/workflows/cla.yaml` asks outside contributors to sign `CLA.md`.
