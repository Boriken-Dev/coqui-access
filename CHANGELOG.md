# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `coqui-access`: `Attempt::certificates`, the client's certificates as DER (leaf first, then
  the intermediates it sent) for a provider that decides trust or reads names from them.
- `coqui-access`: `Limit`, a count bound or none (`null` in configuration), for the resource
  bounds of the crates here.
- `coqui-access`: the kinds `coqui_authenticator`, `coqui_directory`, `coqui_authorizer` and
  the optional `coqui_accounts`, with their models. `Attempt::headers` is an ordered list of
  `(name, value)` pairs; `describe` has a default body. Floor hashes are pinned by a contract
  test and `kinds.json`: `0xc9379b44`, `0x8f7a4451`, `0xa08d4555`, `0x2468f527`.
- `coqui-access`: `Subject` (`account:<name>`, `person:<id>`, `group:<name>`, with `FromStr`,
  `Display` and `matches(&Person)`), the one subject type `coqui-roles` and
  `coqui-access-acl` use.
- `coqui-access-kit`: prefixed 256-bit secrets, SHA-256 of a secret with optional domain
  separation (`secret::hash`) and of raw bytes (`secret::hash_bytes`), constant-time
  comparison. `KeyHash` (`Sha256`, `Argon2id`; as configuration a map tagged by `algorithm`),
  `verify_key`, `is_key_hash`, `generate_key`,
  `PasswordHasher` (Argon2id with a dummy-hash path for unknown accounts), `verify_password`,
  `Argon2Params` and `is_password_hash`: hashing and constant-time verification to use with
  your own data. `Argon2Params` is also configuration (guatiao `FromValue`, `ToValue`,
  `Schema`): each cost defaults to the library's, and reading refuses a combination Argon2
  would.
- `coqui-access-kit`: `Table<T>`, a typed source trait (`load`, `changes_since`, `put`,
  `remove`; the last two default to `ReadOnly`) over `Keyed` records, whose key is borrowed
  or written from a value, with `MemoryTable`, `Reloading`, `Keyed`,
  `Snapshot`, `Revision`, `SourceError` and `check_keys`. `SourceError::reading` and
  `writing` turn a table error into the `ProviderError` a host acts on. `check_field` and
  `unix_now` are the record checks and clock the providers share.
- `coqui-access-kit` feature `file`: `FileTable<T, C>`, a table kept in one private file
  (atomic owner-only writes, bounded reads, change stamps; `max_bytes`, default 1 MiB), written
  in any serde format through a caller-supplied `Codec`, with records crossing through their
  guatiao derives and guatiao-serde's bridge. `Source<F>`/`FileSource<F>` are the
  `{ "file": { "path", "format" } }` configuration a plugin names its table with. The kit
  depends on no format crate under any feature.
- `coqui-access-password`, `-key`, `-ldap`, `-proxy`, `-mtls`: providers, each with a `-plugin`
  library crate. Password, key and mtls also implement `coqui_accounts` and are built with
  `PasswordAccounts::builder()`, `Keys::builder()` and `MtlsAccounts::builder()` over an
  `Arc<dyn Table<Record>>` (memory by default). The record types (`AccountRecord`,
  `KeyRecord`, `PeerRecord`, `Unaccepted`) are public and derive guatiao's `ToValue`,
  `FromValue` and `Schema`, so any table keeps them. The mtls waiting list is a table of its own.
- `coqui-access-password`: the Argon2id costs are an option. `coqui-access-key`: a stored hash is
  a self-describing string, `sha256:<hex>` or `$argon2id$...`; the builder's `KeyHash` (default
  SHA-256) picks the algorithm for new keys, and one table may hold both. The key prefix is
  configurable (default `ck_`).
- `coqui-access-mtls` (id `coqui_access_mtls`): client certificates through
  [`coqui-peer-tls`](https://crates.io/crates/coqui-peer-tls) `=0.0.0-alpha.1`, trusted as
  `pinned` (a record of its table, as a paired peer), `ca` (a `CaPolicy`: CA file, subject and
  SAN globs, the chain from `Attempt::certificates` checked with `verify_client_chain`) or
  `pinned-or-ca`. A CA-trusted certificate names its account through `account` picks over its
  fields (default its fingerprint, by `certificate`); two values are `Invalid`. An IP written as
  a DNS name counts as an IP, by default, in SAN globs and picks. `max_chain` (8) bounds what a
  client sends. Fingerprints in its records are `PeerId`s, written canonical and read in any
  spelling. Its waiting list is coqui-peer's `WaitingQueue` over a table, under
  `WaitingLimits` (default one place per source, an IPv6 source being its /64; 16 in all; a
  newcomer past them waits unrecorded; one rerecord a minute).
- `coqui-access-password-plugin`, `-key-plugin`, `-mtls-plugin`: configured with a `source` object
  (`{ "file": { "path", "format" } }`, `format` being `toml` or `json`, each plugin's own codec
  over the kit's `FileTable`); no `source` means memory. Key also takes
  `prefix`, `key_hash` (`{ "algorithm": "sha256" }`, or `argon2id` with its costs beside it)
  and `max_keys`; password takes `max_accounts`, `argon2` and `max_password_bytes`; mtls
  takes `waiting`, `max_records`, `waiting_per_source`, `waiting_total`,
  `waiting_rerecord_secs`, `trust`, `ca_file`, `subject`, `san`, `ip_in_dns`, `account` and
  `max_chain`, and its `waiting` defaults to a file beside a file source (`<path>.waiting`)
  and to memory otherwise. All three take `record_limits`. Every
  numeric option is a plain number whose default the schema declares, and an empty
  configuration reads as those defaults.
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
  names), within `Limits::depth` (64) and refusing a cycle. `AclAuthorizer` answers the
  `coqui_authorizer` kind over any `AclStore` (a store error is an error, never a denial);
  entry conditions are decided by the consumer's `Conditions` (unknown: an allow is skipped,
  a deny applies); `Decision::intersect` and `union_where_unset` combine a token's or a
  pool's decision. Conformance suites write NetBox, Windows, TrueNAS and Proxmox examples in
  this model.
- `coqui-access-system`: the operating system's own accounts as an Authenticator and a
  Directory (id `coqui_access_system`, read only), with `coqui-access-system-plugin`. On Unix,
  NSS for accounts and groups and PAM (`pam_authenticate`, then `pam_acct_mgmt`) for
  passwords; on Windows, `LogonUserW` with a network logon, the NetUser API and SID strings as
  ids. Options `pam_service` (default `coqui-access`), `min_uid` (default the platform's first
  person uid: Linux 1000, FreeBSD 1001, macOS 501), `groups` (empty admits any) and `domain`
  (Windows, default `.`); `weakenings()` reports a `min_uid` that admits root or service
  accounts. Building on Unix links the system `libpam`.
- `coqui-access-kit`: `RecordLimits` (groups, field bytes, email bytes, display-name bytes;
  by default 256, 256, 320 and 1 024) bound the records of the password, key and peer
  providers, each a `Limit` set on the builder (`record_limits`) or in the plugin's
  configuration; `PasswordHasher::max_password_bytes` (default `DEFAULT_MAX_PASSWORD_BYTES`,
  4 096) is the password provider's `max_password_bytes`. Ids and names of keys and peers are
  256 bytes by default, as accounts' are.
- `coqui-access-kit`: `pick::pick` chooses the account a credential names from its fields (a
  certificate's SANs, subject attributes, fingerprint) by an ordered list of `Pick`s (`field`,
  `by`, an optional `domain`): `Found`, `Ambiguous` for two values, or `Absent`. An IP address
  written as a DNS name counts as an IP name unless a pick's `ip_in_dns` is off, compared in
  one spelling.
- `coqui-access-kit` feature `cache`: `Cached<T>` keeps a directory's lookups and an
  authorizer's decisions for a short while (`CacheOptions`: 5 s, 1 s for "not found" or a
  denial, 10 000 entries, each an option, `off()` for none), never a credential or an error;
  `Accounts` writes through it clear it. `CacheSetting` is the `true`/`false`/options
  configuration. `coqui-access-ldap` caches its lookups by default (`cache` in its
  configuration).
- `coqui-access-ldap`: a `ca_file` builds its client TLS configuration with `coqui-peer-tls`
  under its default policy (TLS 1.2 with extended master secret, and 1.3); `weakened()`
  reports anything past that default.
- `coqui-access-proxy`: trusted proxies are `coqui-net-acl` networks, so an IPv4-mapped
  network trusts the IPv4 addresses it maps; `any` is refused.
- `coqui-roles`: a first-match role authorizer with configurable scope kinds, built with
  `RoleAuthorizer::builder()` or `RoleAuthorizer::new(RolePolicy)`. `RolePolicy`, `Role` and
  `Rule` are plain data with guatiao's value traits; its bounds (roles, actions per
  role, rules, scope kinds, name bytes) are `RoleLimits`, each a `coqui_access::Limit` a caller
  changes or lifts, in code or in the policy's `limits`. `RoleAuthorizer` is the `coqui_roles` provider, configured with
  a `RolePolicy` (`scope_kinds`, `roles`, `rules`); `coqui-roles-plugin` exports it.
