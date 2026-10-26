# `coqui-access-peer` — API header

Header-file-style reference for the `coqui-access-peer` crate: every public item with its
signature, contract and gotchas, so the crate can be used without reading its source. It
ships inside the package and is self-contained. Development documentation lives with the
source at <https://github.com/Boriken-Dev/coqui-access>.

MSRV Rust 1.89. Feature `serde` (off by default): `Serialize`/`Deserialize` on the record
types. Depends on `coqui-access`, `coqui-access-kit` and `coqui-peer-tls` (fingerprint parsing
only), and `serde` when enabled. No `unsafe` code. It reads no file and no environment
variable. The loadable library is the separate crate `coqui-access-peer-plugin`.

```rust
pub const DEFAULT_MAX_PEERS: usize = 10_000;
pub const DEFAULT_WAITING_PLACES: usize = 16;
pub const DEFAULT_SEEN_EVERY_SECS: i64 = 60;
pub struct PeerRecord { pub id, pub name, pub certificate: String, pub email: Option<String>,
    pub groups: Vec<String>, pub disabled: bool, pub made_unix: Option<i64> }
                                          // non_exhaustive; Keyed by name; Debug redacts
impl PeerRecord { pub fn new(id: impl Into<String>, name: impl Into<String>, certificate: &PeerId) -> Self;
                  pub fn groups(self, ..) -> Self; pub fn email(self, ..) -> Self; pub fn disabled(self, bool) -> Self; }
pub struct Unaccepted { pub fingerprint: String, pub peer: Option<String>, pub seen_unix: i64 }
                                          // non_exhaustive; Keyed by fingerprint
impl Unaccepted { pub fn new(fingerprint: &PeerId, peer: Option<String>, seen_unix: i64) -> Self; }
pub struct PeersBuilder;                  // Debug
impl PeersBuilder {
    pub fn table(self, table: Arc<dyn Table<PeerRecord>>) -> Self;     // default: MemoryTable
    pub fn waiting(self, table: Arc<dyn Table<Unaccepted>>) -> Self;   // default: MemoryTable
    pub fn max_peers(self, max: usize) -> Self;                        // default 10 000
    pub fn waiting_places(self, places: usize) -> Self;                // default 16
    pub fn seen_every_secs(self, seconds: i64) -> Self;                // default 60
    pub fn build(self) -> Result<Peers, SourceError>;
}
pub struct Peers;
impl Peers { pub fn builder() -> PeersBuilder; }
impl Authenticator for Peers { /* takes::REQUEST */ }
impl Directory for Peers { /* by "id", "name", "certificate", "email" */ }
impl Accounts for Peers { /* accounts, put, remove, waiting */ }
```

## Behaviour

- `build` checks the peer table: at most `max_peers` records, unique names and ids, certificates
  that are distinct SHA-256 fingerprints.
- `authenticate` reads `Attempt::certificate` as a fingerprint of any accepted spelling; text
  that is not a SHA-256 fingerprint is `Unknown`. A known, enabled peer gives `Lookup { by:
  "id", value: id }`; a known, disabled one `Invalid`; an unknown one `Unknown`, and the
  fingerprint is recorded as waiting with `Attempt::peer`.
- Waiting list: at most `waiting_places` entries, one per source address (a second certificate
  from the same address replaces the first), the same certificate from the same address
  recorded at most every `seen_every_secs`. `Accounts::waiting` lists them newest first with
  `shown` in canonical `sha256:<hex>` form. A waiting table that cannot be read or written
  means nobody waits; the peer is never told.
- `put`: `secret` is the certificate fingerprint (SHA-256, any spelling) and is required for a
  new peer; giving it for an existing name moves the account to that certificate; a
  fingerprint already used by another peer is refused. `groups` and `disabled` change those
  fields; `expires_unix` is refused. Putting a fingerprint removes it from the waiting list.
  A read-only peer table answers `GUATIAO_ERR_UNSUPPORTED`.

## Errors

A table that cannot be read at call time is `GUATIAO_ERR_INTERNAL`; a refused change is
`GUATIAO_ERR_BAD_VALUE`.
