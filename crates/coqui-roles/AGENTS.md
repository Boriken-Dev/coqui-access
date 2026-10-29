# `coqui-roles` — API header

Header-file-style reference for the `coqui-roles` crate: every public item with its
signature, contract and gotchas, so the crate can be used without reading its source. It
ships inside the package and is self-contained. Development documentation lives with the
source at <https://github.com/Boriken-Dev/coqui-access>.

MSRV Rust 1.89. No Cargo features. Depends on `coqui-access` only: no format crate, no `unsafe`
code. Everything is at the crate root. `RoleAuthorizer` is the Guatiao provider `coqui_roles`
(`#[derive(Provider)]`, configured with `RolePolicy`); `coqui-roles-plugin` (a `cdylib`) is its
one `providers!` line.

## RoleAuthorizer

```rust
pub struct RoleLimits { pub roles: Limit, pub actions_per_role: Limit, pub rules: Limit,
                        pub scope_kinds: Limit, pub name_bytes: Limit }
    // non_exhaustive, Copy; guatiao derives (each key defaulting); Default = 256, 256, 10 000, 64, 256
impl RoleLimits {
    pub const UNBOUNDED: Self;
    pub const fn roles(self, Limit) -> Self; pub const fn actions_per_role(self, Limit) -> Self;
    pub const fn rules(self, Limit) -> Self; pub const fn scope_kinds(self, Limit) -> Self;
    pub const fn name_bytes(self, Limit) -> Self;
}
pub struct Role { pub name: String, pub actions: Vec<String> }          // non_exhaustive
impl Role { pub fn new(name: impl Into<String>, actions: impl IntoIterator<Item = impl Into<String>>) -> Self; }
pub struct Rule { pub subject: String, pub scope: String, pub role: String }   // non_exhaustive
impl Rule { pub fn new(subject: impl Into<String>, scope: impl Into<String>, role: impl Into<String>) -> Self; }
pub struct RolePolicy { pub scope_kinds: Vec<String>, pub roles: Vec<Role>, pub rules: Vec<Rule>,
                        pub limits: RoleLimits }
                                                // non_exhaustive, Default; RolePolicy::new()
// Role, Rule and RolePolicy derive FromValue, ToValue, Schema (deny_unknown_fields; the
// policy's three lists default to empty).
pub struct RoleAuthorizerBuilder;               // Clone, Default
impl RoleAuthorizerBuilder {
    pub fn scope_kinds(self, kinds: impl IntoIterator<Item = impl Into<String>>) -> Self;
    pub fn role(self, name: impl Into<String>, actions: impl IntoIterator<Item = impl Into<String>>) -> Self;
    pub fn rule(self, rule: Rule) -> Self;       // rules are tried in the order added
    pub fn limits(self, limits: RoleLimits) -> Self;   // default RoleLimits::default()
    pub fn build(self) -> Result<RoleAuthorizer, RolePolicyError>;
}
pub struct RoleAuthorizer;                      // Clone, Default, Debug (counts only)
impl RoleAuthorizer {
    pub fn builder() -> RoleAuthorizerBuilder;
    pub fn new(policy: RolePolicy) -> Result<Self, RolePolicyError>;
}
impl Authorizer for RoleAuthorizer { /* authorize */ }
impl TryFrom<RolePolicy> for RoleAuthorizer { type Error = RolePolicyError; }   // = new
pub struct RolePolicyError;                     // Display, Error
impl From<RolePolicyError> for ProviderError;   // GUATIAO_ERR_BAD_VALUE
```

- `subject` is `account:<name>` | `person:<id>` | `group:<name>`, read as `coqui_access::Subject`
  (the value also has no whitespace and is at most 256 bytes); `scope` is `*` or
  `<kind>:<id>`; `role` must name a defined role.
- `scope_kinds` lists the kinds a rule scope may use; an empty list allows any kind. `*` is
  always allowed.
- A request's `resource` is compared with a rule scope as an exact string; `*` matches every
  resource. Subjects match `Person::name` (`account`), `Person::id` (`person`) or membership
  in `Person::groups` (`group`).
- The first rule whose subject and scope match is decisive: if its role lacks the action the
  answer is deny. No matching rule is deny. `limits` is always empty.
- `build`/`new` refuse: a policy past its `limits`, a role with no actions, a repeated role or
  action, a malformed subject or scope, a scope kind not allowed, an unknown role in a rule.
  Names are 1 to `name_bytes` bytes without whitespace or control characters.
- The limits bound work and memory (the rule scan per request, the tables built once), not
  trust: a caller lifts any of them with `Limit::UNBOUNDED`, and nothing reports that.
- Reading a `Role`, `Rule` or `RolePolicy` refuses a key it does not declare.

## Provider (`coqui_roles`)

`RoleAuthorizer` derives `Provider`: id `coqui_roles`, name `Role authorizer`, kind
`Authorizer`, config `RolePolicy`, built with `TryFrom`. `coqui-roles-plugin` exports it.
Config: `limits` (`{ roles, actions_per_role, rules, scope_kinds, name_bytes }`, each a
number or `null`, each defaulting), `scope_kinds: [string]`,
`roles: [{ name, actions: [string] }]`, `rules: [{ subject, scope, role }]`, all optional
(default: deny everything). An invalid policy is `GUATIAO_ERR_BAD_VALUE` at build time.
