# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

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

- `coqui-access`: the kinds `coqui_authenticator`, `coqui_directory`, `coqui_authorizer` and
  the optional `coqui_accounts`, with their models. `Attempt::headers` is an ordered list of
  `(name, value)` pairs; `describe` has a default body. Floor hashes are pinned by a contract
  test and `kinds.json`: `0xfaa87428`, `0x737a3b19`, `0xa08d4555`, `0x3ac3bd3c`.
- `coqui-access-kit`: prefixed 256-bit secrets, SHA-256 with optional domain separation,
  constant-time comparison, atomic owner-only file writes, bounded reads, and `Store`, a TOML
  table that reloads when its file changes.
- `coqui-access-local`, `-key`, `-ldap`, `-proxy`, `-peer`: providers, each with a `-plugin`
  library crate. Local, key and peer also implement `coqui_accounts`. The key prefix is
  configurable (default `ck_`).
- `coqui-roles`: first-match role authorizer with configurable scope kinds, and its provider.
