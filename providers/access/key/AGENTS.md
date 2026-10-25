# `coqui-access-key` — API header

Header-file-style reference for the `coqui-access-key` crate: every public item with its
signature, contract and gotchas, so the crate can be used without reading its source. It
ships inside the package and is self-contained. Development documentation lives with the
source at <https://github.com/Boriken-Dev/coqui-access>.

MSRV Rust 1.89. No Cargo features. Depends on `coqui-access`, `coqui-access-kit` and `serde`.
No `unsafe` code. The loadable library is the separate crate `coqui-access-key-plugin`.

```rust
pub const DEFAULT_PREFIX: &str = "ck_";
pub struct KeysConfig { pub path: String, pub prefix: String }   // prefix defaults to "ck_"
pub struct Keys;                          // provider id "coqui_access_key"
impl Keys {
    pub fn open(path: impl AsRef<Path>, prefix: &str) -> Result<Self, String>;
    pub fn new_key(&self) -> Result<String, String>;
}
impl Authenticator for Keys { /* takes::KEY */ }
impl Directory for Keys { /* by "id", "name", "email" */ }
impl Accounts for Keys { /* accounts, put, remove */ }
```

## Behaviour

- `authenticate` looks only at `secret` values that start with the prefix, hashes with plain
  SHA-256 and compares every record in constant time. Unknown key: `Unknown`; known but
  disabled or past `expires_unix`: `Invalid`; valid: `Lookup { by: "id", value: id }`.
- `lookup` finds taken (enabled, unexpired) records only.
- `put` never accepts a secret: a key is made here. A new account gets a key and a random id;
  an existing account with no `groups`, `disabled` or `expires_unix` said is given another key
  (the old one becomes `Unknown`); otherwise the fields change and the key stays. The key is
  answered once in `PutOutcome::secret`.
- The file is created by the first `put`, mode `0600`.

File format (unknown keys are errors; at most 10 000 keys; `hash` is 64 lowercase hex):

```toml
[[keys]]
id = "robot-1"          # unique
name = "relay"          # unique
hash = "..."            # SHA-256 of the key
email = "..."           # optional
groups = ["station"]    # optional
disabled = false        # optional
made_unix = 1700000000  # optional
expires_unix = 1800000000   # optional
```

## Errors

Configuration problems are `GUATIAO_ERR_BAD_VALUE`; an unreadable or invalid file at call time
is `GUATIAO_ERR_INTERNAL`. Messages never contain keys or hashes.
