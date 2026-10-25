# `coqui-access-local` — API header

Header-file-style reference for the `coqui-access-local` crate: every public item with its
signature, contract and gotchas, so the crate can be used without reading its source. It
ships inside the package and is self-contained. Development documentation lives with the
source at <https://github.com/Boriken-Dev/coqui-access>.

MSRV Rust 1.89. Feature `serde` (off by default): `Serialize`/`Deserialize` on `AccountRecord`.
Depends on `coqui-access` and `coqui-access-kit` (and `serde` when enabled). No `unsafe` code.
It reads no file and no environment variable. The loadable library is the separate crate
`coqui-access-local-plugin`.

```rust
pub const DEFAULT_MAX_ACCOUNTS: usize = 10_000;
pub struct AccountRecord { pub id, pub name, pub password_hash, pub display_name: Option<String>,
    pub email: Option<String>, pub groups: Vec<String>, pub disabled: bool, pub made_unix: Option<i64> }
                                          // non_exhaustive; Keyed by name; Debug redacts
impl AccountRecord {
    pub fn new(id: impl Into<String>, name: impl Into<String>, password_hash: impl Into<String>) -> Self;
    pub fn groups(self, ..) -> Self; pub fn display_name(self, ..) -> Self;
    pub fn email(self, ..) -> Self;  pub fn disabled(self, bool) -> Self;
}
pub struct LocalAccountsBuilder;          // Debug
impl LocalAccountsBuilder {
    pub fn table(self, table: Arc<dyn Table<AccountRecord>>) -> Self;   // default: MemoryTable
    pub fn max_accounts(self, max: usize) -> Self;                      // default 10 000
    pub fn argon2(self, params: Argon2Params) -> Self;                  // default Argon2Params::default()
    pub fn build(self) -> Result<LocalAccounts, SourceError>;
}
pub struct LocalAccounts;
impl LocalAccounts { pub fn builder() -> LocalAccountsBuilder; }
impl Authenticator for LocalAccounts { /* takes::PASSWORD */ }
impl Directory for LocalAccounts { /* by "id", "name", "email" */ }
impl Accounts for LocalAccounts { /* accounts, put, remove */ }
```

Hashing lives in `coqui_access_kit` (`PasswordHasher`, `Argon2Params`); make an account hash
with `PasswordHasher::hash`.

## Behaviour

- `build` loads the table and checks it: at most `max_accounts` records, unique names and ids,
  valid Argon2id hashes, at most 256 groups of 256 bytes each. A table that later becomes
  unreadable or invalid makes calls fail rather than serve stale accounts.
- `authenticate` needs `name` and `secret`; otherwise `Unknown`. Wrong password, unknown name
  and disabled account are all `Invalid`; the valid result is `Lookup { by: "id", value: id }`.
  An unknown name is verified against a dummy hash made with the same costs.
- `lookup` finds enabled accounts only.
- `put`: `name` required; `secret` is a password of 1 to 4096 bytes; a new account needs a
  password, an existing one keeps its hash unless a password is given; `groups` and
  `disabled` change those fields; `expires_unix` is refused. A new account gets a random id.
  Writing needs a writable table; a read-only one answers `GUATIAO_ERR_UNSUPPORTED`.

## Errors

A table that cannot be read at call time is `GUATIAO_ERR_INTERNAL` ("could not find out",
not a denial); a refused change is `GUATIAO_ERR_BAD_VALUE`. Messages never contain passwords
or hashes.

## Gotchas

- Read-modify-write is atomic within one process; two processes writing one source at once
  are the source's to arbitrate.
