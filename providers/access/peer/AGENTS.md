# `coqui-access-peer` — API header

Header-file-style reference for the `coqui-access-peer` crate: every public item with its
signature, contract and gotchas, so the crate can be used without reading its source. It
ships inside the package and is self-contained. Development documentation lives with the
source at <https://github.com/Boriken-Dev/coqui-access>.

MSRV Rust 1.89. No Cargo features. Depends on `coqui-access`, `coqui-access-kit`, `coqui-peer-tls`
(fingerprint parsing only), `serde` and `toml`. No `unsafe` code. The loadable library is the
separate crate `coqui-access-peer-plugin`.

```rust
pub struct PeersConfig { pub path: String }
pub struct Peers;                         // provider id "coqui_access_peer"
impl Peers { pub fn open(path: impl AsRef<Path>) -> Result<Self, String>; }
impl Authenticator for Peers { /* takes::REQUEST */ }
impl Directory for Peers { /* by "id", "name", "certificate", "email" */ }
impl Accounts for Peers { /* accounts, put, remove, waiting */ }
```

## Behaviour

- `authenticate` reads `Attempt::certificate` as a fingerprint of any accepted spelling; text
  that is not a SHA-256 fingerprint is `Unknown`. A known, enabled peer gives `Lookup { by:
  "id", value: id }`; a known, disabled one `Invalid`; an unknown one `Unknown`, and the
  fingerprint is recorded as waiting with `Attempt::peer`.
- Waiting list: at most 16 entries, one per source address (a second certificate from the same
  address replaces the first), the same certificate from the same address recorded at most
  every 60 seconds, in `<path>.waiting` (owner-only). `Accounts::waiting` lists them newest
  first with `shown` in canonical `sha256:<hex>` form.
- `put`: `secret` is the certificate fingerprint (SHA-256, any spelling) and is required for a
  new peer; giving it for an existing name moves the account to that certificate; a
  fingerprint already used by another peer is refused. `groups` and `disabled` change those
  fields; `expires_unix` is refused. Putting a fingerprint removes it from the waiting list.
- The file is created by the first `put`, mode `0600`.

File format (unknown keys are errors; at most 10 000 peers; certificates must be distinct
SHA-256 fingerprints):

```toml
[[peers]]
id = "service-1"
name = "site-a"
certificate = "sha256:..."
email = "..."          # optional
groups = ["site-a"]    # optional
disabled = false       # optional
made_unix = 1700000000 # optional
```

## Errors

Configuration problems are `GUATIAO_ERR_BAD_VALUE`; an unreadable or invalid file at call time
is `GUATIAO_ERR_INTERNAL`.
