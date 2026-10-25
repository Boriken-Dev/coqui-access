# `coqui-access-local` — API header

Header-file-style reference for the `coqui-access-local` crate: every public item with its
signature, contract and gotchas, so the crate can be used without reading its source. It
ships inside the package and is self-contained. Development documentation lives with the
source at <https://github.com/Boriken-Dev/coqui-access>.

MSRV Rust 1.89. No Cargo features. Depends on `coqui-access`, `coqui-access-kit`, `argon2`
and `serde`. No `unsafe` code. The loadable library is the separate crate
`coqui-access-local-plugin` (a `cdylib`, one `providers!` line).

```rust
pub struct LocalAccountsConfig { pub path: String }
pub struct LocalAccounts;                 // provider id "coqui_access_local"
impl LocalAccounts { pub fn open(path: impl AsRef<Path>) -> Result<Self, String>; }
impl Authenticator for LocalAccounts { /* takes::PASSWORD */ }
impl Directory for LocalAccounts { /* by "id", "name", "email" */ }
impl Accounts for LocalAccounts { /* accounts, put, remove */ }
pub fn hash_password(password: &str) -> Result<String, String>;
```

## Behaviour

- `authenticate` needs `name` and `secret`; otherwise `Unknown`. Wrong password, unknown name
  and disabled account are all `Invalid`; the valid result is `Lookup { by: "id", value: id }`.
- `lookup` finds enabled accounts only.
- `put`: `name` required; `secret` is a password of 1 to 4096 bytes; a new account needs a
  password, an existing one keeps its hash unless a password is given; `groups` and
  `disabled` change those fields; `expires_unix` is refused. A new account gets a random id.
- `hash_password` rejects empty or over-long passwords.
- A missing file is no accounts. The file is created by the first `put`, mode `0600`.

File format (unknown keys are errors; at most 10 000 accounts, 256 groups each):

```toml
[[accounts]]
id = "person-1"            # unique
name = "alice"             # unique
password_hash = "$argon2id$..."
display_name = "Alice"     # optional
email = "alice@example.invalid"   # optional
groups = ["staff"]         # optional
disabled = false           # optional
made_unix = 1700000000     # optional
```

## Errors

Configuration problems are `GUATIAO_ERR_BAD_VALUE`; an unreadable or invalid file at call time
is `GUATIAO_ERR_INTERNAL` ("could not find out", not a denial). Messages never contain
passwords or hashes.

## Gotchas

- Another process editing the file is seen on the next call; an invalid edit makes calls fail
  until it is fixed, rather than serving stale accounts.
