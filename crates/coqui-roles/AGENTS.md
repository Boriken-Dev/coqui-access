# `coqui-roles` — API header

Header-file-style reference for the `coqui-roles` crate: every public item with its
signature, contract and gotchas, so the crate can be used without reading its source. It
ships inside the package and is self-contained. Development documentation lives with the
source at <https://github.com/Boriken-Dev/coqui-access>.

MSRV Rust 1.89. Feature `serde` (off by default): `Serialize`/`Deserialize` on the policy
types. Depends on `coqui-access` (and `serde` when enabled). No format crate, no `unsafe` code.
Everything is at the crate root. `coqui-roles-plugin` (a `cdylib`) is the Guatiao provider
`coqui_roles`.

## RoleAuthorizer

```rust
pub const MAX_ROLES: usize = 256; pub const MAX_ROLE_ACTIONS: usize = 256;
pub const MAX_RULES: usize = 10_000; pub const MAX_SCOPE_KINDS: usize = 64;
pub struct Role { pub name: String, pub actions: Vec<String> }          // non_exhaustive
impl Role { pub fn new(name: impl Into<String>, actions: impl IntoIterator<Item = impl Into<String>>) -> Self; }
pub struct Rule { pub subject: String, pub scope: String, pub role: String }   // non_exhaustive
impl Rule { pub fn new(subject: impl Into<String>, scope: impl Into<String>, role: impl Into<String>) -> Self; }
pub struct RolePolicy { pub scope_kinds: Vec<String>, pub roles: Vec<Role>, pub rules: Vec<Rule> }
                                                // non_exhaustive, Default; RolePolicy::new()
pub struct RoleAuthorizerBuilder;               // Clone, Default
impl RoleAuthorizerBuilder {
    pub fn scope_kinds(self, kinds: impl IntoIterator<Item = impl Into<String>>) -> Self;
    pub fn role(self, name: impl Into<String>, actions: impl IntoIterator<Item = impl Into<String>>) -> Self;
    pub fn rule(self, rule: Rule) -> Self;       // rules are tried in the order added
    pub fn build(self) -> Result<RoleAuthorizer, RolePolicyError>;
}
pub struct RoleAuthorizer;                      // Clone, Default, Debug (counts only)
impl RoleAuthorizer {
    pub fn builder() -> RoleAuthorizerBuilder;
    pub fn new(policy: RolePolicy) -> Result<Self, RolePolicyError>;
}
impl Authorizer for RoleAuthorizer { /* authorize */ }
pub struct RolePolicyError;                     // Display, Error
```

- `subject` is `account:<name>` | `person:<id>` | `group:<name>`; `scope` is `*` or
  `<kind>:<id>`; `role` must name a defined role.
- `scope_kinds` lists the kinds a rule scope may use; an empty list allows any kind. `*` is
  always allowed.
- A request's `resource` is compared with a rule scope as an exact string; `*` matches every
  resource. Subjects match `Person::name` (`account`), `Person::id` (`person`) or membership
  in `Person::groups` (`group`).
- The first rule whose subject and scope match is decisive: if its role lacks the action the
  answer is deny. No matching rule is deny. `limits` is always empty.
- `build`/`new` refuse: more than the bounds above, a role with no actions, a repeated role or
  action, a malformed subject or scope, a scope kind not allowed, an unknown role in a rule.
  Names are 1 to 256 characters without whitespace or control characters.
- `RolePolicy` with the `serde` feature denies unknown fields.

## Provider (`coqui-roles-plugin`)

Provider id `coqui_roles`, kind `Authorizer`. Config: `scope_kinds: [string]`,
`roles: [{ name, actions: [string] }]`, `rules: [{ subject, scope, role }]`, all optional
(default: deny everything). An invalid policy is `GUATIAO_ERR_BAD_VALUE` at build time.
