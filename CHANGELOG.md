# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **File tables lock their file.** `FileTable` holds an exclusive operating-system lock on `<path>.lock` from the read
  to the write of every `put`, `remove` and `update`, so processes sharing a file lose no update. `Table::update(&mut
  Update<T>)` (default: load, decide, put) lets a change be computed from the records a table read for it, and
  `Reloading::put_with` uses it: the providers that keep a file table (password, key, mtls, totp) now have atomic
  read-modify-write across processes. `FileSource::max_bytes` (and `Source::max_bytes`, `max_bytes_unless_set`) bounds
  a file; absent, the bound is the provider's default.
- **`coqui-access-totp` delays an account under wrong codes.** `Lockout` (default: after five wrong codes in a row, 30 s,
  doubling to an hour; `Lockout::OFF` lifts it) with `TotpRecord::failures` and `locked_until_unix` (old files read).
  The plugin takes `lockout_after`, `lockout_seconds` and `lockout_longest_seconds`, and sizes its file bound from
  `max_records` (2 KiB each, at least 1 MiB); it used to stop at about 1 200 accounts.
- **`Factor::person`.** The `Person::id` a step named; the rules provider refuses a sign-in whose steps name different
  people. The contract requires counting second-factor failures per person, the person to be looked up again at resume,
  and per-address-and-account throttling before anyone is named. The shared flows gain the cases for each.
- **`coqui-access-totp`**, the `coqui_access_totp` provider: one-time codes (RFC 6238, checked against its Appendix B
  values for SHA-1, SHA-256 and SHA-512) as a second factor, with replay protection, skew, ten recovery codes made at
  enrolment and presented as the method `recovery_code`, and enrolment, rotation and reset through the `Accounts` kind.
  It does not throttle: the consumer's throttle bounds guessing.
- **`coqui-access-signin`**, the `coqui_signin_rules` provider of the sign-in policy kind: ordered rules over purpose,
  client network, kind of client, service and subject, whose chains of methods say what a sign-in may use and when it
  asks for a further step. `SignInRules::single_factor` is the policy of a deployment with none. Its `test-support`
  feature carries the shared vectors (`policy.json`, `flows.json`); `docs/sign-in.md` is the contract a consumer follows.
- **Claims and a matcher.** `Lookup` carries optional `Claims` (what an authenticator obtained, in full) and
  `by: "claims"` means the authenticator names no account itself. `coqui-access-mtls` answers a certificate with its
  subject and issuer names, serial, UPN, email, DNS, URI and IP SANs, fingerprint, public key hash and the DER.
  `coqui_access_kit::matcher` ties claims to a directory account by ordered templates (`{san.upn|local}`) and LDAP
  filters whose substituted values are escaped per RFC 4515; the first rule that finds exactly one account wins, more
  than one is refused, a directory error is an error. `coqui_access::error::ambiguous` is how a directory says one
  lookup found several. `coqui_access_ldap` answers `by: "filter"` lookups, ANDed with a new `object_filter`.
- **Pin sources.** `coqui_access_kit::pins::PinSource` is where a rule's account is checked for a pinned certificate
  (fingerprint or public key), asked only about the one account the rule named. `AuthorizedFile` reads a per-user file
  (`{home}/.myapp/authorized_certificates` style, one `sha256:<hex>` or `spki-sha256:<hex>` per line, comments allowed)
  through a `PinFileReader` the consumer may supply; the default reader checks the owner, group/other-writable files
  and parents up to the home, symlinks and escapes from the home as sshd does, and a file that fails counts as no pins
  with a reason. `TablePins` keeps pins in any table; `MtlsAccounts` is a source over its own records;
  `coqui_access_system` puts `uid` and `home` among a Unix person's attributes.
- **`coqui-access-mtls` pins by public key as well as by fingerprint, and an account holds several pins.** `Pin`
  (`kind` `fingerprint` or `key`, SHA-256 of the whole certificate or of its SubjectPublicKeyInfo) names what a record
  pins; `PeerRecord::pins` lists them beside the existing `certificate`, `PeerRecord::keyed` makes a record from one,
  `MtlsAccountsBuilder::max_pins` (and the plugin's `max_pins`, default 4) bounds them. A certificate renewed on the
  same key signs in under a key pin. `Accounts::put` takes `key:sha256:<hex>` as well as a fingerprint, adds the pin
  to an existing account, and `remove:<pin>` takes one away alone.
- **`coqui_sign_in_policy`**, a kind (`SignInPolicy::decide`) that decides which methods a sign-in may use and what
  it still needs, with the models `SignInContext`, `SignInDecision`, `Factor` and `Offer`, and the word modules
  `methods`, `purposes` and `clients`. `takes::OTP` names an authenticator that takes a one-time code.
- `Attempt::method`, `PutOutcome::codes` and `AccountPut::display_name`, all optional: a provider serving two methods
  tells them apart, an enrolment answers with recovery codes once, and an enrolment carries a label.

### Changed

- **Breaking: the per-user pin file reader walks the path without following links and cannot be hung.**
  `DirectReader` is no longer a unit struct (`DirectReader::new()`, `timeout`, `max_waiting`; it is `Clone`, not `Copy`):
  it walks from the home one component at a time and refuses a symlink anywhere on the path (one staying inside the
  home too), a component on another device, and a file that is not the regular file it saw; opens with
  `O_NOFOLLOW | O_NONBLOCK`; and bounds the walk and read to 2 seconds, refusing a read while one for the same account is stuck, and any when 8 are.
  `coqui-access-kit` depends on `libc` on Unix for the open flags.
- **Breaking: the matcher and the directory take no raw filter.** `Matcher::resolve` answers `NotFound` to a lookup
  `by: "filter"` handed to it, `Pick::check` (and the `account` of `coqui_access_mtls` and `coqui_access_proxy`,
  which refuse it when built) rejects `filter` and `claims` as a pick's `by`, and `coqui_access_ldap` answers
  `by: "filter"` only with the new setting `allow_filter_lookups` (default false; a lookup otherwise is
  `GUATIAO_ERR_UNSUPPORTED`).
- **Breaking: `object_filter` of `coqui_access_ldap` defaults to `(&(objectCategory=person)(objectClass=user))`**, people and
  not Active Directory's computer accounts, and must carry every restriction an account needs to sign in.
- **Breaking: a matcher rule using `local` names its realm or requires pins.** `MatchRule` gains `domain`; a rule with
  `local` and neither is refused when the matcher is built. The default rules are the UPN and the email address, not
  the common name.
- `coqui-access-claims` holds the certificate claims `coqui_access_mtls` built alone (`of_certificate`,
  `public_key_hash`). `coqui_access_proxy` answers a forwarded certificate with them: attached to the lookup an
  `account` pick makes, and, when `account` is empty, as `Lookup { by: "claims", .. }`.
- **Behaviour: `coqui_access_password` answers `Unknown` for a name it does not hold.** It used to answer `Invalid`,
  which ends an ordered authenticator list, so a password provider listed before another (the operating system's, say)
  locked every other name out. A name it holds with a wrong password, and a disabled account, are still `Invalid`; the
  dummy hash still runs for an unknown name.
- **Breaking for struct literals:** `Lookup` has a new field `claims`; code that builds one without
  `..Default::default()` stops compiling. Reading is unchanged.
- **Breaking: `coqui_access_mtls::default_account()` is empty.** A CA-trusted certificate with no `account` picks is
  answered `Valid(Lookup { by: "claims", .. })` instead of by its fingerprint under `certificate`; a consumer sends
  it to a `Matcher`. Picks that are given answer as before and carry the claims too.
- `coqui_access_ldap::search::escaped` also escapes control characters and every byte of a non-ASCII character
  (`\xx`), as the matcher does; `LdapAccountsConfig` gains `object_filter` (default `(objectClass=user)`).
- **Breaking: `PeerRecord::certificate` is `Option<PeerId>`, and `put` with a pin for an existing mtls account adds
  it.** A record pinned only by key has none. A pin given for a name that exists used to move the account to that
  certificate and now adds one more pin up to `max_pins`; `remove:<pin>` takes the old one away. Files written before
  pins existed still read.
- **Breaking for struct literals:** `Attempt`, `PutOutcome` and `AccountPut` have a new field each, so code that builds
  one without `..Default::default()` stops compiling. Reading and the kinds' hashes are unchanged.

- **Breaking: a weakening is a non-default setting.** `coqui-access-acl`'s `Weakening` enum is `NonDefault` (variants
  unchanged) and `Options::weakened` and `ItemAcl::weakened` are `non_defaults`; `coqui-access-system`'s `Weakening` is
  `NonDefault` and `SystemAccountsConfig::weakenings` is `non_defaults`; `LdapAccounts::weakened` is `non_defaults` and
  returns coqui-peer-tls's `NonDefault`. The old names are gone; nothing keeps an alias before a release without a pre-release tag.
- **Breaking:** `SystemAccounts` refuses, with a bad value, a `min_uid` other than the default where accounts carry no
  uid (Windows): it used to be accepted and admit nothing.
- **Breaking: settings types derive `coqui_builder::Describe`.** `Limit`, `RecordLimits`, `RoleLimits`,
  `RolePolicy`, `Role`, `Rule`, `Pick`, `KeyHash`, `Argon2Params`, `CacheOptions`, `CacheSetting`, `Source`,
  `FileSource`, `SystemAccountsConfig`, the plugin configs (`LdapAccountsConfig`, `KeysConfig`,
  `PasswordAccountsConfig`, `MtlsAccountsConfig`, `ProxyWordConfig`) and `coqui-access-acl`'s `Acl`, `ItemAcl`, `Entry`,
  `Inherit` derive `Describe` (`Effect`, `Mode`, `TrustMode`, `CertificateEncoding` and the plugins' `Format` derive
  `Leaf`) in place of guatiao's `ToValue`, `FromValue` and `Schema`: they are filled through `coqui_builder::Partial`
  and nothing writes one out. A provider's configuration is `guatiao_builder::Described<Config>`, and each provider
  also builds from `Described<Config>` (`TryFrom`). Records and kind models keep guatiao's derives.
- **Breaking: the text of "no bound" is `none`.** `Limit` reads and writes a count or `none`; `null` in a document is
  a key that is not given, so it reads the default. A `Limit`'s schema is a string.
- **Breaking:** a duration setting (`CacheOptions::ttl`, `negative_ttl`) reads `5`, `1.5`, `5s` or `250ms`, not
  `[secs, nanos]`.
- **Breaking:** `Argon2Params` is not checked as it is read; `Argon2Params::new`, `PasswordHasher::new`,
  `KeyHash::hash` and building the key provider refuse a combination Argon2 refuses.
- `LdapAccountsConfig::bind_password` is `Option<coqui_builder::Secret<String>>` (coqui-builder's `zeroize` feature): wiped when
  dropped and never shown. A `Limit`'s schema is a string leaf (its default is `"4096"`); reads still accept a number.
- Pins: `coqui-peer-tls`, `coqui-peer` and `coqui-net-acl` at the revisions that moved onto coqui-builder, guatiao at
  the revision with `guatiao-builder`. LDAP builds its CA client with `ClientBuilder::new().server(..)`.

### Removed

- `FromValue`, `ToValue` and `Schema` of the settings types above, and `Limit`'s guatiao derives. A configuration
  is read, never written.

### Added

- `coqui-access`: `AuthorizationRequest::ancestors`, the resources a request's `resource`
  sits under in the host's hierarchy, nearest first; empty by default and not written then,
  so the pinned contract is unchanged. `coqui-access-kit`'s decision cache keys on it.
- `coqui-roles`: a rule also matches a request that names its scope among the request's
  `ancestors`, unless `Rule::propagate` is `false` (it defaults to `true`); first match
  still decides. `RoleLimits::ancestors` (64 by default) bounds the ancestors one request
  names; more is an error, never a denial.
- `coqui-access`: `Attempt::certificates`, the client's certificates as DER (leaf first, then
  the intermediates it sent) for a provider that decides trust or reads names from them.
- `coqui-access`: `Limit`, a count bound or none (`none` in configuration), for the resource
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
  network trusts the IPv4 addresses it maps; `any` is refused. A `certificate_header` carries the
  client certificate the proxy verified, as `pem-url` (nginx, AWS ALB), `der-base64`
  (Traefik) or `xfcc` (Envoy), within `max_certificate_bytes` (16 384); `account` picks over
  its fields, or over a `subject_header`'s attributes, name the account (default the subject's
  CN, by `name`). The order is the user header, the certificate, the subject.
- `coqui-roles`: a first-match role authorizer with configurable scope kinds, built with
  `RoleAuthorizer::builder()` or `RoleAuthorizer::new(RolePolicy)`. `RolePolicy`, `Role` and
  `Rule` are plain data with guatiao's value traits; its bounds (roles, actions per
  role, rules, scope kinds, name bytes) are `RoleLimits`, each a `coqui_access::Limit` a caller
  changes or lifts, in code or in the policy's `limits`. `RoleAuthorizer` is the `coqui_roles` provider, configured with
  a `RolePolicy` (`scope_kinds`, `roles`, `rules`); `coqui-roles-plugin` exports it.
