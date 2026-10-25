# `coqui-roles` — API header

Header-file-style reference for the `coqui-roles` crate: every public item with its
signature, contract and gotchas, so the crate can be used without reading its source. It
ships inside the package and is self-contained. Development documentation lives with the
source at <https://github.com/Boriken-Dev/coqui-access>.

MSRV Rust 1.89. No Cargo features. Depends on `coqui-access`, `serde` and `toml`. No `unsafe`
code. Everything is at the crate root. `coqui-roles-plugin` (a `cdylib`, one `providers!` line)
is the same provider as a loadable library.

## RoleAuthorizer

```rust
pub struct RoleAuthorizer;                      // Clone, Default, Debug (counts only)
impl RoleAuthorizer {
    pub fn from_toml(source: &str, scope_kinds: &[String]) -> Result<Self, RolePolicyError>;
    pub fn load(path: impl AsRef<Path>, scope_kinds: &[String]) -> Result<Self, RolePolicyError>;
}
impl Authorizer for RoleAuthorizer { /* authorize */ }
pub struct RolePolicyError;                     // Display, Error
```

Policy TOML (unknown keys are errors):

```toml
[role.viewer]
actions = ["document.read", "audit.read"]

[[rule]]
subject = "group:staff"        # account:<name> | person:<id> | group:<name>
scope = "site:north"           # "*" | "<kind>:<id>"
role = "viewer"                # must name a defined role
```

- `scope_kinds` lists the kinds a rule scope may use; an empty list allows any kind. `*` is
  always allowed.
- A request's `resource` is compared with a rule scope as an exact string; `*` matches every
  resource. Subjects match `Person::name` (`account`), `Person::id` (`person`) or membership
  in `Person::groups` (`group`).
- The first rule whose subject and scope match is decisive: if its role lacks the action the
  answer is deny. No matching rule is deny. `limits` is always empty.
- Bounds: 1 MiB source, 256 roles, 256 actions per role, 10 000 rules, 64 scope kinds, names
  of 1 to 256 characters without whitespace or control characters; duplicate actions in a role
  are errors. `load` reads at most 1 MiB.

## Provider

```rust
pub struct RoleAuthorizerConfig { pub policy_toml: String, pub scope_kinds: Vec<String> }  // scope_kinds default: empty
pub struct RoleAuthorizerProvider;              // provider id "coqui_roles", kind Authorizer
```

An invalid policy is `GUATIAO_ERR_BAD_VALUE` at build time.
