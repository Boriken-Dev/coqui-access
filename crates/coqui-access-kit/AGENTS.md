# `coqui-access-kit` — API header

Header-file-style reference for the `coqui-access-kit` crate: every public item with its
signature, contract and gotchas, so the crate can be used without reading its source. It
ships inside the package and is self-contained. Development documentation lives with the
source at <https://github.com/Boriken-Dev/coqui-access>.

MSRV Rust 1.89. No Cargo features. Depends on `argon2`, `getrandom`, `sha2` and `subtle`: no
serde and no format crate; the kit never parses a format. No `unsafe` code. Public modules:
`table`, `hash`, `secret`, `file`; the main items are re-exported at the root. Table errors are
`SourceError`; helpers elsewhere return plain `String`s. Neither contains file contents or
secrets.

## Secrets (`coqui_access_kit::secret`)

```rust
pub const SECRET_CHARS: usize = 43;
pub fn generate(prefix: &str) -> Result<String, String>;
pub fn identifier() -> Result<String, String>;
pub fn hash(secret: &str, domain: Option<&str>) -> String;
pub fn same(a: &str, b: &str) -> bool;
pub fn is_hash(value: &str) -> bool;
```

- `generate` returns `prefix` plus 32 random bytes as 43 base64url characters. Errors only
  when the OS random source is unavailable.
- `identifier` returns 128 random bits as 32 lowercase hex characters.
- `hash` is SHA-256 as 64 lowercase hex characters. With a `domain` the digest covers the
  domain, a zero byte, then the secret, so a digest kept for one purpose cannot be presented
  for another.
- `same` compares in time independent of where the strings differ. `is_hash` checks the
  64-lowercase-hex shape.

## Files (`coqui_access_kit::file`)

```rust
pub struct Stamp;                       // Debug, Clone, Copy, PartialEq, Eq
pub fn stamp(path: &Path) -> Result<Option<Stamp>, String>;
pub fn read_bounded(path: &Path, max_bytes: usize) -> Result<Option<String>, String>;
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String>;
```

- `stamp` identifies a writing of a file by modification time, length and (Unix) inode;
  `None` when the file is absent.
- `read_bounded` returns `None` for a missing file; errors for unreadable, longer than
  `max_bytes`, or non-UTF-8 content.
- `write_private` writes `bytes` to a fresh file beside `path` (created new, `0600` on Unix),
  syncs, and renames over `path`. The directory must exist.

## Tables (`coqui_access_kit::table`)

```rust
pub enum SourceError { ReadOnly, Invalid(String), Unavailable(String) }   // non_exhaustive, Error
pub struct Revision;                    // Copy, Eq, Ord, Default; Revision::new(u64), .get()
pub trait Keyed { fn key(&self) -> &str; }
pub struct Snapshot<T> { pub revision: Revision, pub records: Vec<T> }     // non_exhaustive; Snapshot::new
pub trait Table<T>: Send + Sync {
    fn load(&self) -> Result<Snapshot<T>, SourceError>;
    fn changes_since(&self, since: Revision) -> Result<Option<Snapshot<T>>, SourceError>;  // default: load + compare
    fn put(&self, record: T) -> Result<(), SourceError>;        // default Err(ReadOnly); same key replaces
    fn remove(&self, key: &str) -> Result<bool, SourceError>;   // default Err(ReadOnly); true when it was there
}
pub struct MemoryTable<T>;              // Table<T> for T: Keyed + Clone + Send
impl<T> MemoryTable<T> { pub fn new() -> Self; pub fn from_records(impl IntoIterator<Item = T>) -> Self; }
pub struct Reloading<T>;                // Debug
impl<T: Keyed + Clone> Reloading<T> {
    pub fn new(table: Arc<dyn Table<T>>, validate: impl Fn(&[T]) -> Result<(), SourceError> + Send + Sync + 'static) -> Result<Self, SourceError>;
    pub fn read<R>(&self, read: impl FnOnce(&[T]) -> R) -> Result<R, SourceError>;
    pub fn put_with<R>(&self, make: impl FnOnce(&[T]) -> Result<(T, R), SourceError>) -> Result<R, SourceError>;
    pub fn remove(&self, key: &str) -> Result<bool, SourceError>;
}
pub fn check_keys<T: Keyed>(records: &[T], max: usize) -> Result<(), SourceError>;
```

- A `Table` is any source: memory, a file with a codec, SQL, an HTTP API. The caller
  implements it for the storage it picks; the kit supplies no codec. A table that implements
  only `load` is a read-only source.
- `MemoryTable` revision counts its changes; `from_records` keeps the last of a repeated key.
- `Reloading` calls `changes_since` on every use, so it must be cheap. Every snapshot is
  checked with `validate`; a table that has become unreadable or invalid is an error, never a
  stale answer. `put_with` validates the records as they would be with the new one before
  putting it, so a refused change leaves the table alone. It is atomic within one process only.
- `check_keys` refuses more than `max` records or a repeated key; providers call it first.

## Hashing (`coqui_access_kit::hash`) - use these with your own data

```rust
pub const MAX_PASSWORD_BYTES: usize = 4096;
pub struct Argon2Params;                // Copy; Default = 19456 KiB, 2 passes, 1 lane
impl Argon2Params { pub fn new(memory_kib: u32, iterations: u32, parallelism: u32) -> Result<Self, String>;
                    pub fn memory_kib(&self) -> u32; pub fn iterations(&self) -> u32; pub fn parallelism(&self) -> u32; }
pub enum KeyHash { Sha256 /* default */, Argon2id(Argon2Params) }          // non_exhaustive
impl KeyHash { pub fn argon2id() -> Self; pub fn hash(&self, secret: &str) -> Result<String, String>; }
pub fn verify_key(stored: &str, presented: &[u8]) -> bool;
pub fn is_key_hash(stored: &str) -> bool;
pub fn generate_key(prefix: &str) -> Result<String, String>;
pub struct PasswordHasher;              // Clone; Default = default costs
impl PasswordHasher {
    pub fn new(params: Argon2Params) -> Result<Self, String>;
    pub fn params(&self) -> Argon2Params;
    pub fn hash(&self, password: &str) -> Result<String, String>;
    pub fn verify(&self, stored: Option<&str>, presented: &str) -> bool;
}
pub fn verify_password(stored: &str, presented: &str) -> bool;
pub fn is_password_hash(stored: &str) -> bool;
```

- Stored strings name their algorithm: `sha256:<64 lowercase hex>` or `$argon2id$v=19$...`
  (PHC). A table may mix both. A bare digest or any other prefix never verifies.
- `KeyHash::hash` is `Err` only for Argon2id (RNG or parameters). `verify_key` branches only on
  the stored prefix; SHA-256 digests are compared in constant time and Argon2id runs in full.
  Argon2id keys cost one verification per Argon2id record they are tried against.
- `Argon2Params::new` rejects what Argon2 refuses (memory under 8 KiB per lane, zero counts).
  Stored hashes verify with the costs they carry.
- `PasswordHasher::new` makes a dummy hash with the same costs; `verify(None, ..)` does the
  same work and answers `false`, so an unknown name costs what a wrong password does.
  `hash` rejects empty and over-long passwords; `verify_password` ignores them.

