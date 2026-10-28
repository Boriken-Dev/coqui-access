# `coqui-access-acl` — API header

Header-file-style reference for the `coqui-access-acl` crate: every public item with its
signature, contract and gotchas, so the crate can be used without reading its source. It
ships inside the package and is self-contained. Development documentation lives with the
source at <https://github.com/Boriken-Dev/coqui-access>.

No Cargo features. MSRV Rust 1.89. A default build depends on `coqui-access` alone (guatiao
through it); no format crate. Everything is re-exported at the root; the modules are
private. No `unsafe` code (`#![forbid(unsafe_code)]`).

The consumer stores items and their ACLs (any format, through guatiao's derives); this
crate evaluates them. It defines no plugin kind.

## Rights (`Rights`, `RightsSchema`)

```rust
pub struct Rights;                       // Clone, Default, Eq, Hash; Debug {bits}
impl Rights {
    pub const fn new() -> Self;
    pub fn contains(&self, bit: usize) -> bool;
    pub fn insert(&mut self, bit: usize) -> bool;     // true when new
    pub fn remove(&mut self, bit: usize) -> bool;     // true when it was there
    pub fn is_empty(&self) -> bool;  pub fn len(&self) -> usize;
    pub fn is_subset(&self, other: &Rights) -> bool;
    pub fn is_disjoint(&self, other: &Rights) -> bool;
    pub fn iter(&self) -> impl Iterator<Item = usize> + '_;   // lowest first
}
// FromIterator<usize>, Extend<usize>; &a | &b, &a & &b, &a - &b; |=, &=, -= with &Rights

pub struct RightsSchema;                 // Debug, Clone, Default
impl RightsSchema {
    pub fn builder() -> RightsSchemaBuilder;
    pub fn len(&self) -> usize;  pub fn is_empty(&self) -> bool;   // rights, not aliases
    pub fn bit(&self, name: &str) -> Option<usize>;               // rights only
    pub fn all(&self) -> Rights;
    pub fn cancels(&self, name: &str) -> bool;
    pub fn rights<I, S: AsRef<str>>(&self, names: I) -> Result<Rights, AclError>;  // union
    pub fn names<'a>(&'a self, rights: &Rights) -> Vec<&'a str>;
}
pub struct RightsSchemaBuilder;          // must_use
impl RightsSchemaBuilder {
    pub fn right(self, name) -> Self;  pub fn rights(self, names) -> Self;   // next bits, in order
    pub fn alias(self, name, members) -> Self;    // members: rights or earlier aliases
    pub fn cancel(self, name) -> Self;            // grants nothing, cancels everything
    pub fn limits(self, limits: Limits) -> Self;  // only `rights` applies
    pub fn build(self) -> Result<RightsSchema, AclError>;
}
```

- A right is one bit, numbered by definition order: keep the order stable, or stored
  bits change meaning. Entries store names, not bits, so they survive a reordering.
- An alias names rights and earlier aliases; it is a Windows generic right, an NFSv4 basic
  permission or a Proxmox role. An alias over a cancelling name cancels too.
- `build` refuses an empty or control-character name (`InvalidName`), a name defined twice
  (`DuplicateName`), an alias member not defined before it (`UnknownRight { entry: None,
  at }`), and more rights than `Limits::rights` (default 1 024; `None` lifts it).

## Entries and lists (`Principal`, `Entry`, `Acl`, `ItemAcl`)

```rust
#[non_exhaustive]
pub enum Principal { Subject(Subject), Everyone, Authenticated, Owner, OwnerGroup, Mask }
impl Principal { pub fn matches(&self, person: Option<&Person>, owner: Option<&Subject>, owner_group: Option<&Subject>) -> bool; }
// FromStr/Display: "everyone" "authenticated" "owner" "owner_group" "mask", or a Subject's text
// ("account:<name>", "person:<id>", "group:<name>"); From<Subject>. Err = PrincipalError.

pub enum Effect { Allow /* default */, Deny }                      // "allow" | "deny"
#[non_exhaustive]
pub struct Inherit { pub items: bool, pub containers: bool, pub no_propagate: bool, pub inherit_only: bool }
impl Inherit { pub const fn new(items: bool, containers: bool) -> Self;
               pub const fn no_propagate(self) -> Self; pub const fn inherit_only(self) -> Self;
               pub const fn passes(&self) -> bool; }               // items || containers

#[non_exhaustive]
pub struct Entry {
    pub principal: Principal,      // as text
    pub effect: Effect,            // default allow
    pub rights: Vec<String>,       // right and alias names
    pub inherit: Inherit,          // default none
    pub inherited: bool,           // default false
    pub condition: Option<String>,
}
impl Entry { pub fn allow(principal: impl Into<Principal>, rights) -> Self; pub fn deny(..) -> Self;
             pub fn inherit(self, Inherit) -> Self; pub fn inherited(self, bool) -> Self;
             pub fn condition(self, impl Into<String>) -> Self; }

#[non_exhaustive]
pub enum Mode { Ordered, DenyOverrides /* default */, Additive, Posix, MostSpecific }  // snake_case
#[non_exhaustive]
pub struct Acl { pub entries: Vec<Entry>, pub protected: bool, pub mode: Mode }   // Extend<Entry>
impl Acl {
    pub fn new(mode: Mode) -> Self;  pub fn entry(self, Entry) -> Self;  pub fn protected(self, bool) -> Self;
    pub fn canonicalize(&mut self);                     // explicit deny, explicit allow, inherited (stable)
    pub fn weakened(&self) -> Vec<Weakening>;           // every effective Everyone allow
    pub fn validate(&self, schema: &RightsSchema, options: &Options) -> Result<(), AclError>;
    pub fn check(&self, context: &Context<'_>, wanted: &Rights) -> Result<Decision, AclError>;
}
#[non_exhaustive]
pub struct ItemAcl { pub acl: Acl, pub owner: Option<Subject>, pub owner_group: Option<Subject> }
impl ItemAcl { pub fn new(Acl) -> Self; pub fn owner(self, Subject) -> Self; pub fn owner_group(self, Subject) -> Self;
               pub fn check(&self, context: &Context<'_>, wanted: &Rights) -> Result<Decision, AclError>; }
```

Every type above derives guatiao `ToValue`, `FromValue` and `Schema`; principals and
subjects cross as their text, structs refuse unknown keys. An ACL as configuration:

```json
{ "mode": "ordered", "protected": false,
  "entries": [ { "principal": "group:staff", "effect": "deny", "rights": ["write"],
                 "inherit": { "items": true, "containers": true } } ] }
```

## Checking (`Context`, `Decision`)

```rust
pub struct Context<'a>;                  // Clone; Debug shows no identity
impl<'a> Context<'a> {
    pub fn new(schema: &'a RightsSchema) -> Self;      // nobody signed in, no owner, defaults
    pub fn person(self, &'a Person) -> Self;
    pub fn owner(self, Option<&'a Subject>) -> Self;   pub fn owner_group(self, Option<&'a Subject>) -> Self;
    pub fn owner_rights(self, Rights) -> Self;         // standing owner rights, default none
    pub fn conditions(self, &'a dyn Conditions) -> Self;
    pub fn item(self, &'a str) -> Self;                // what conditions are told
    pub fn options(self, Options) -> Self;
}
#[non_exhaustive]
pub struct Decision { pub allowed: bool, pub wanted: Rights, pub granted: Rights,
                      pub denied: Rights, pub deciding: Option<usize>, pub cancelled: bool }
```

`check` first compiles every entry, refusing (`Err`, never a denial): more entries than
`Limits::entries` (default 1 024), a name the schema lacks (`UnknownRight { entry: Some(i),
at }`), a deny in `Additive`, `Posix` or `MostSpecific` (`DenyNotAllowed`), `Mask` outside
`Posix` or twice, or `Authenticated` in `Posix` (`PrincipalNotAllowed`). Then:

- An entry applies when its principal matches and it is not `inherit_only`. A condition
  must come to `Truth::True` for an allow and anything but `False` for a deny.
- An applicable entry naming a cancelling name refuses everything (`cancelled`, `granted`
  empty, `denied` = every right), in every mode; in `MostSpecific` only where its level
  is in force.
- `Ordered`: each right is decided by the first applicable entry naming it; an allow before
  a deny wins that right. `deciding` is the deny that refused a wanted right, or the allow
  that completed the grant.
- `DenyOverrides`: any applicable deny refuses its rights, whatever the order; the allows
  are unioned. `Additive`: the union of the allows.
- `Posix` (acl(5)): the owner gets the `Owner` entry; else the first matching named user
  (`account:`/`person:`) gets its entry capped by the mask; else, among `OwnerGroup` and
  matching `group:` entries, access needs ONE entry holding every wanted right after the
  mask (`granted` reports their union); else `Everyone`. The mask comes from the entries
  whoever asks.
- `MostSpecific` on one ACL: the requester's own entries (`account:`, `person:`, `Owner`)
  beat the rest, and the winning tier is unioned.
- Owner rights: `Context::owner_rights` go to the owner unless an entry names `Owner`; a
  deny does not take them back.
- `allowed` is `wanted ⊆ granted` (Posix: as above); an empty `wanted` is allowed.

## Options (`Options`, `Limits`, `OnMissing`, `Weakening`)

```rust
#[non_exhaustive]
pub struct Limits { pub entries: Option<usize>, pub rights: Option<usize>, pub depth: Option<usize> }
// Default Some(1024), Some(1024), Some(64); DEFAULT_ENTRIES, DEFAULT_RIGHTS, DEFAULT_DEPTH;
// const fn unbounded(); const fn entries(self, Option<usize>), rights(..), depth(..)
pub enum OnMissing { Deny /* default */, AllowAll }
#[non_exhaustive]
pub struct Options { pub limits: Limits, pub on_missing: OnMissing }
impl Options { pub fn new() -> Self; pub fn limits(self, Limits) -> Self;
               pub fn on_missing(self, OnMissing) -> Self; pub fn weakened(&self) -> Vec<Weakening>; }
#[non_exhaustive]
pub enum Weakening { MissingAllowsAll, EveryoneAllowed { entry: usize } }
```

The limits bound work and memory, not trust: lifting one is not a weakening.

## Conditions (`Conditions`, `Truth`)

```rust
pub enum Truth { True, False, Unknown }
pub trait Conditions: Send + Sync {
    fn holds(&self, condition: &str, item: &str, person: &Person) -> Truth;
}
```

The condition language is the consumer's. Without `Conditions`, or with nobody signed in,
every condition is `Unknown`: an allow is skipped, a deny applies.

## Errors

`AclError` (`#[non_exhaustive]`, `Error`): `InvalidName`, `DuplicateName`,
`UnknownRight { entry: Option<usize>, at: usize }`, `TooManyRights`, `TooManyEntries`,
`DenyNotAllowed { entry }`, `PrincipalNotAllowed { entry }`, `ModeMismatch`, `TooDeep`,
`Cycle`, `Store(ProviderError)` (its `source`). Messages give positions, never names.

## Gotchas

- Bits are positions in one schema: never compare `Rights` from two schemas.
- `Subject` and `Principal` `Debug` show the kind only; `Display` is the full text.
