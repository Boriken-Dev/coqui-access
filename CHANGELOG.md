# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- `coqui-access-kit`: the TOML-backed `Store<T>` is replaced by `Table<T>`, a typed source trait
  (`load`, `changes_since`, `put`, `remove`; the last two default to `ReadOnly`), with
  `MemoryTable`, `Reloading`, `Keyed`, `Snapshot`, `Revision`, `SourceError` and `check_keys`.
  The kit no longer depends on `serde` or `toml` and parses no format. `secret::hash_bytes` is
  new; the file helpers stay and know no format.
- `coqui-access-local`, `-key`, `-peer`: built with `LocalAccounts::builder()`,
  `Keys::builder()` and `Peers::builder()` over an `Arc<dyn Table<Record>>` (memory by default)
  instead of `open(path)`. The `*Config` Guatiao types, the `Provider` derive and the `path`
  option moved to the plugin crates. The record types (`AccountRecord`, `KeyRecord`,
  `PeerRecord`, `Unaccepted`) are public and derive serde behind a new `serde` feature. The
  peer waiting list is a second table, no longer `<path>.waiting`. The dependency on `toml` is
  gone. `coqui_access_local::hash_password` is replaced by `coqui_access_kit::PasswordHasher`.
- `coqui-access-key`: a stored hash is a self-describing string, `sha256:<hex>` or
  `$argon2id$...`, instead of bare hex; keys made from now on use the builder's `KeyHash`
  (default SHA-256).
- `coqui-access-local-plugin`, `-key-plugin`, `-peer-plugin`: configured with a `source` object
  (`{ "file": { "path", "format": "toml" } }`) instead of `path`; no `source` means memory.
  Key adds `key_hash`, `argon2` and `max_keys`; local adds `max_accounts` and `argon2`; peer
  adds `waiting`, `max_peers`, `waiting_places` and `seen_every_secs`.
- `coqui-roles`: `RoleAuthorizer::from_toml` and `load` are replaced by
  `RoleAuthorizer::builder()` and `RoleAuthorizer::new(RolePolicy)`; `RolePolicy`, `Role` and
  `Rule` are plain data with serde behind a new `serde` feature. The `toml` dependency, the
  1 MiB source bound and the Guatiao provider types (now in `coqui-roles-plugin`) are gone;
  the role, action, rule and scope-kind bounds remain and are public constants.
  `coqui-roles-plugin` takes structured `scope_kinds`, `roles` and `rules` instead of
  `policy_toml`.
- `coqui-peer` and `coqui-net-acl` moved to their own repositories, with their history:
  `coqui-peer` as `coqui-peer-tls`, at
  <https://github.com/Boriken-Dev/coqui-peer-tls>, and `coqui-net-acl` at
  <https://github.com/Boriken-Dev/coqui-net-acl>. `coqui-access-peer` now depends on
  `coqui-peer-tls` by git revision. Replace `coqui_peer::` with `coqui_peer_tls::` in imports and
  depend on the new repositories instead of this one.
- `coqui-peer-tls` is pinned at a revision that builds on
  [Boriken-Dev/coqui-peer](https://github.com/Boriken-Dev/coqui-peer): the peer id (still
  exported as `Fingerprint`) and the trust store come from that core crate. No source change
  was needed here.

### Added

- `coqui-access-kit`: `KeyHash` (`Sha256`, `Argon2id`), `verify_key`, `is_key_hash`,
  `generate_key`, `PasswordHasher` (Argon2id with a dummy-hash path for unknown accounts),
  `verify_password`, `Argon2Params` and `is_password_hash`: hashing and constant-time
  verification to use with your own data.
- `coqui-access-local`: the Argon2id costs are an option. `coqui-access-key`: the hash
  algorithm is an option, and one table may mix both.
- `providers/access/plugin-support` (not published): the plugins' `source` config and a
  file-backed `Table` with a TOML codec.
- `coqui-access`: the kinds `coqui_authenticator`, `coqui_directory`, `coqui_authorizer` and
  the optional `coqui_accounts`, with their models. `Attempt::headers` is an ordered list of
  `(name, value)` pairs; `describe` has a default body. Floor hashes are pinned by a contract
  test and `kinds.json`: `0xfaa87428`, `0x737a3b19`, `0xa08d4555`, `0x3ac3bd3c`.
- `coqui-access-kit`: prefixed 256-bit secrets, SHA-256 with optional domain separation,
  constant-time comparison, atomic owner-only file writes and bounded reads.
- `coqui-access-local`, `-key`, `-ldap`, `-proxy`, `-peer`: providers, each with a `-plugin`
  library crate. Local, key and peer also implement `coqui_accounts`. The key prefix is
  configurable (default `ck_`).
- `coqui-roles`: first-match role authorizer with configurable scope kinds, and its provider.
