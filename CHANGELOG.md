# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- `coqui-peer`: waiting entries record the address the handshake came from, and the
  per-source caps use it. `TrustStore::waiting` returns `WaitingEntry` (fingerprint and
  source), `record_waiting` takes a `SocketAddr`, and a waiting file may start with a
  `Source:` line (store format version 2; version 1 files still read). `accept` requires
  `PeerAddr` (TCP streams); other streams use the new `accept_from`, `asynch::accept_from`
  and `asynch::accept_with_from`. `with_source` scopes the address for hosts that drive
  rustls themselves.

### Fixed

- Waiting entries are recorded only after the peer proves it holds the certificate's key
  (`coqui-peer`, including a CA policy beside pins).

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
- `coqui-peer`: mutual-TLS peer identity. Fingerprints (`sha256:<hex>`, grouped base32),
  identity PEM files, pinned / CA / key-proof trust, a trust store with a bounded waiting
  queue, the rustls verifiers as values, TLS configurations with ALPN as a parameter, blocking
  and tokio `dial` / `accept`, and a `Policy` with `strict`, `compatible` and `legacy` presets
  and a versioned text form. Test vectors for the formats are committed.
- `coqui-net-acl`: ordered first-match access control lists over source networks, with
  destination, port and fingerprint rules, evaluated at accept time and after the handshake.
