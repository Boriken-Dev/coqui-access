# `coqui-access-kit` — API header

Header-file-style reference for the `coqui-access-kit` crate: every public item with its
signature, contract and gotchas, so the crate can be used without reading its source. It
ships inside the package and is self-contained. Development documentation lives with the
source at <https://github.com/Boriken-Dev/coqui-access>.

MSRV Rust 1.89. No Cargo features. A default build depends on `getrandom`, `serde`, `sha2`,
`subtle` and `toml`. No `unsafe` code. Public modules: `secret`, `file`, `store`; `Store` is
re-exported at the root. Errors are plain `String`s that never contain file contents or secrets.

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

## Tables (`coqui_access_kit::store`)

```rust
pub const MAX_TABLE_BYTES: usize = 1024 * 1024;
pub struct Store<T>;                    // Debug
impl<T: Serialize + DeserializeOwned + Default + Clone> Store<T> {
    pub fn open(path: impl AsRef<Path>, validate: fn(&T) -> Result<(), String>) -> Result<Self, String>;
    pub fn path(&self) -> &Path;
    pub fn read<R>(&self, read: impl FnOnce(&T) -> R) -> Result<R, String>;
    pub fn change<R>(&self, change: impl FnOnce(&mut T) -> Result<R, String>) -> Result<R, String>;
}
```

- A missing file is `T::default()`. Every `read`/`change` compares the file `Stamp` and loads
  again when it differs; a file that has become unreadable, over 1 MiB or invalid is an
  error, never a stale answer.
- `change` runs on a clone, validates the result, writes it with `write_private` and keeps it;
  when `change` or `validate` refuses nothing is written.
- Use `#[serde(deny_unknown_fields)]` on `T` so a misspelled key is an error.
