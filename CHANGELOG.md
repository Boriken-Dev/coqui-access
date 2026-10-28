# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `coqui-access`: the kinds `coqui_authenticator`, `coqui_directory`, `coqui_authorizer` and
  the optional `coqui_accounts`, with their models. `Attempt::headers` is an ordered list of
  `(name, value)` pairs; `describe` has a default body. Floor hashes are pinned by a contract
  test and `kinds.json`: `0xc9379b44`, `0x8f7a4451`, `0xa08d4555`, `0x2468f527`.
- `coqui-access`: `Subject` (`account:<name>`, `person:<id>`, `group:<name>`, with `FromStr`,
  `Display` and `matches(&Person)`), the one subject type `coqui-roles` and
  `coqui-access-acl` use.
- `coqui-access-kit`: prefixed 256-bit secrets, SHA-256 of a secret with optional domain
  separation (`secret::hash`) and of raw bytes (`secret::hash_bytes`), constant-time
  comparison. `KeyHash` (`Sha256`, `Argon2id`), `verify_key`, `is_key_hash`, `generate_key`,
  `PasswordHasher` (Argon2id with a dummy-hash path for unknown accounts), `verify_password`,
  `Argon2Params` and `is_password_hash`: hashing and constant-time verification to use with
  your own data. `Argon2Params` is also configuration (guatiao `FromValue`, `ToValue`,
  `Schema`): each cost defaults to the library's, and reading refuses a combination Argon2
  would.
- `coqui-access-kit`: `Table<T>`, a typed source trait (`load`, `changes_since`, `put`,
  `remove`; the last two default to `ReadOnly`), with `MemoryTable`, `Reloading`, `Keyed`,
  `Snapshot`, `Revision`, `SourceError` and `check_keys`.
- `coqui-access-kit` feature `file`: `FileTable<T, C>`, a table kept in one private file
  (atomic owner-only writes, bounded reads, change stamps; `max_bytes`, default 1 MiB), written
  in any serde format through a caller-supplied `Codec`, with records crossing through their
  guatiao derives and guatiao-serde's bridge. `Source<F>`/`FileSource<F>` are the
  `{ "file": { "path", "format" } }` configuration a plugin names its table with. The kit
  depends on no format crate under any feature.
- `coqui-access-local`, `-key`, `-ldap`, `-proxy`, `-peer`: providers, each with a `-plugin`
  library crate. Local, key and peer also implement `coqui_accounts` and are built with
  `LocalAccounts::builder()`, `Keys::builder()` and `Peers::builder()` over an
  `Arc<dyn Table<Record>>` (memory by default). The record types (`AccountRecord`,
  `KeyRecord`, `PeerRecord`, `Unaccepted`) are public and derive guatiao's `ToValue`,
  `FromValue` and `Schema`, so any table keeps them. The peer waiting list is a table of its own.
- `coqui-access-local`: the Argon2id costs are an option. `coqui-access-key`: a stored hash is
  a self-describing string, `sha256:<hex>` or `$argon2id$...`; the builder's `KeyHash` (default
  SHA-256) picks the algorithm for new keys, and one table may hold both. The key prefix is
  configurable (default `ck_`).
- `coqui-access-peer`: verifies peers through
  [`coqui-peer-tls`](https://crates.io/crates/coqui-peer-tls) `=0.0.0-alpha.0` from
  crates.io.
- `coqui-access-local-plugin`, `-key-plugin`, `-peer-plugin`: configured with a `source` object
  (`{ "file": { "path", "format" } }`, `format` being `toml` or `json`, each plugin's own codec
  over the kit's `FileTable`); no `source` means memory. Key also takes
  `prefix`, `key_hash`, `argon2` and `max_keys`; local takes `max_accounts` and `argon2`; peer
  takes `waiting`, `max_peers`, `waiting_places` and `seen_every_secs`. Peer's `waiting`
  defaults to a file beside a file source (`<path>.waiting`) and to memory otherwise.
- `coqui-access-acl`: access control lists on items. `RightsSchema` names the rights of an
  item type as bits of a growable `Rights` set, with aliases and cancelling names; `Entry`
  (a `Principal`, allow or deny, rights, inheritance flags, a condition), `Acl` and
  `ItemAcl` are plain data with guatiao derives. `Acl::check` evaluates in one of five
  modes, `Ordered`, `DenyOverrides` (the default), `Additive`, `Posix` and `MostSpecific`,
  into a `Decision` naming what was granted, what was denied and the deciding entry. Bounds
  (`Limits`: 1 024 entries, 1 024 rights) are options; `OnMissing::AllowAll` and an
  `Everyone` allow are reported as `Weakening`s. Inheritance both ways: `Acl::inherited_by`
  copies entries into a new child by Windows' flag table (with CREATOR OWNER mapped to the
  creator), and `AclStore::check` walks the consumer's tree from the root down as Proxmox
  does (a deeper level replaces, a user's entries beat its groups', `propagate`, cancelling
  names), within `Limits::depth` (64) and refusing a cycle.
- `coqui-roles`: a first-match role authorizer with configurable scope kinds, built with
  `RoleAuthorizer::builder()` or `RoleAuthorizer::new(RolePolicy)`. `RolePolicy`, `Role` and
  `Rule` are plain data with serde behind a `serde` feature; the role, action, rule and
  scope-kind bounds are public constants. `coqui-roles-plugin` is its provider, configured
  with structured `scope_kinds`, `roles` and `rules`.
