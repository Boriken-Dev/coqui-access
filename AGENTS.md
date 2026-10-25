# coqui-access — repository orientation

Contributor guidance for this checkout. Each crate has an `AGENTS.md` API header beside its
README; those headers describe the public API and ship with the crate.

| Header | Covers |
| --- | --- |
| `crates/coqui-access/AGENTS.md` | Kinds, models, error helpers, the pinned contract. |
| `crates/coqui-access-kit/AGENTS.md` | Secrets, private files, reloading tables. |
| `crates/coqui-peer/AGENTS.md` | Peer identity, trust, policy, the on-disk and text formats. |
| `crates/coqui-net-acl/AGENTS.md` | Access control lists. |
| `crates/coqui-roles/AGENTS.md` | Role authorizer. |
| `providers/access/<name>/AGENTS.md` | One provider each: local, key, ldap, proxy, peer. |

## Layout

| Path | What |
| --- | --- |
| `crates/` | Library crates: kinds, kit, peer, net-acl, roles. |
| `providers/access/<name>/` | A provider as an ordinary library. |
| `providers/access/<name>/plugin/`, `crates/coqui-roles/plugin/` | The same provider as a `cdylib`: one `providers!` line. |
| `docs/`, `mkdocs.yml` | Narrative site; Rust API docs are published under `/rust/`. |

## Commands

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
```

Regenerate the kind description after a deliberate contract change:
`GUATIAO_WRITE_HEADER=1 cargo test -p coqui-access --test contract`. Regenerate the peer
vectors only for a format change (commands in `crates/coqui-peer/tests/*.rs`).

## Rules

- Kind names and the hashes of required methods are an ABI. A new method has a default body
  and comes after every required one; the contract test names a break.
- Providers depend on `coqui-access`, `coqui-access-kit` and at most `coqui-peer`; never on a
  host or on each other. Code two providers share belongs in a crate under `crates/`.
- No process-global state in `coqui-peer`: no default crypto provider is installed.
- A secret never reaches a log, a `Debug` output or an error message.
- Limits are defaults the caller can change; do not add a refusal a caller cannot lift.
- Files are LF, `crates/coqui-peer/tests/vectors/**` are byte-exact (`-text`).

## CI and release

- `.github/workflows/test.yml` runs fmt, clippy, tests and strict rustdoc on Linux, macOS and
  Windows, on stable and Rust 1.89, on demand and on `ci-*` tags.
- `.github/workflows/docs.yml` builds the narrative site and Rust API reference and deploys
  Pages. `release.yml` gates a source release on tests and a strict docs build; a `v*` tag
  requires the owner's authorization for that release.
- `.github/workflows/cla.yaml` asks outside contributors to sign `CLA.md`.
