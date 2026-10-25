# Contributing to coqui-access

## Licence

This project is distributed under the **Mozilla Public License 2.0**
(`LICENSE`). Its copyleft is per file, which means:

- **Using coqui-access imposes nothing on your code.** Depend on the crates,
  load the provider libraries, and ship a closed-source application. The only
  obligation is that coqui-access's own source stays available to the people
  you ship it to, which it is, here.
- **Changing coqui-access's own files does carry an obligation.** A modified
  file of this project must be published under the MPL 2.0. Your files beside
  it are yours, under whatever licence you choose.
- A combined work may be distributed under terms of your choosing (MPL 2.0
  section 3.3), and MPL 2.0 remains compatible with the GPL.

## Contributor licence agreement

A first pull request needs a one-time signature. The bot will comment with
the exact sentence to reply with; read [`CLA.md`](CLA.md) first.

It exists so the project can be relicensed later without tracking down every
past contributor. You keep the copyright in everything you write.

## Before you open a pull request

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
```

All checks must pass. See [`AGENTS.md`](AGENTS.md) for the repository's layout
and the rules every change keeps:

- the kind names and hashes in `coqui-access` are an ABI: a change to a
  required method is a break, and the contract test says so;
- providers depend on `coqui-access` and `coqui-access-kit`, never on a host;
- a secret value never reaches a log, a `Debug` output or an error message;
- files are LF, on every platform.
