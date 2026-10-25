# `coqui-net-acl` — API header

Header-file-style reference for the `coqui-net-acl` crate: every public item with its
signature, contract and gotchas, so the crate can be used without reading its source. It
ships inside the package and is self-contained. Development documentation lives with the
source at <https://github.com/Boriken-Dev/coqui-access>.

| Feature | Adds | Default |
| --- | --- | --- |
| `serde` | `Serialize`/`Deserialize` for `Acl`, `Rule`, `Action`, `IpNet`, `PortRange`, `Weakening` | off |

MSRV Rust 1.89. A default build has no dependencies. No `unsafe` code. Everything is at the
crate root. The crate decides nothing about what is public or private: a host chooses what to
listen on and writes the rules.

## Types

```rust
pub enum Action { Permit, Deny }                        // Default: Deny
pub enum IpNet { Any, V4(u32, u8), V6(u128, u8) }       // FromStr / Display: "any", "10.0.0.1", "10.0.0.0/8", "::1", "fd00::/8"
pub struct PortRange { pub start: u16, pub end: u16 }   // FromStr / Display: "443", "8000-8100"
pub struct Rule {
    pub action: Action,
    pub source: IpNet,                  // the connecting address; default any
    pub destination: Option<IpNet>,     // the local address connected to; None = any
    pub port: Option<PortRange>,        // the local port; None = any
    pub fingerprint: Option<String>,    // canonical peer fingerprint text; decided after the handshake
    pub log: bool,                      // a hint returned in the decision
}
impl Rule { pub fn new(action: Action, source: IpNet) -> Rule; }
pub struct Acl { pub rules: Vec<Rule>, pub default: Action }   // Default: no rules, Deny
pub enum Outcome { Permit, Deny, Deferred }
pub struct AclDecision { pub outcome: Outcome, pub rule_index: Option<usize>, pub log: bool }
pub struct BindDecision { pub permitted: bool, pub rule_index: Option<usize> }
pub struct Weakening { pub setting: String, pub value: String, pub strict: String }
pub struct ParseError;
```

An IPv4-mapped IPv6 address (`::ffff:10.0.0.9`) is the IPv4 address it maps, in rules and in
connections.

## Evaluation (`Acl`)

```rust
pub fn push(&mut self, rule: Rule);          // append, before the default
pub fn prepend(&mut self, rule: Rule);       // insert at the top
pub fn decide(&self, source: SocketAddr, local: SocketAddr) -> AclDecision;
pub fn decide_peer(&self, source: SocketAddr, local: SocketAddr, fingerprint: &str) -> AclDecision;
pub fn permits_bind(&self, local: SocketAddr) -> BindDecision;
pub fn weakened(&self) -> Vec<Weakening>;
```

- Rules are read top to bottom; the first whose source, destination and port match decides;
  with none, `default` applies (`rule_index: None`).
- `decide` is for accept time, before any byte is read. A first-matching rule that names a
  fingerprint cannot be decided yet: `Outcome::Deferred`; the connection may proceed to the
  handshake. `AclDecision::proceeds()` is true for anything but `Deny`.
- `decide_peer` finishes the decision with the verified fingerprint (compared
  case-insensitively); a fingerprint rule matches only that fingerprint; never `Deferred`.
- `permits_bind` is advisory and enforces nothing: walking the rules whose destination and
  port cover `local`, a `Permit` permits whatever its source (a routed setup may listen on an
  address that clients on other networks reach), and a `Deny` with source `any` and no
  fingerprint refuses. A wildcard address (`0.0.0.0`, `::`) is covered by every rule.
- `weakened` lists only a `permit` default: setting `acl.default`, value `permit`, strict
  `deny`.
- `Display` prints a router-style listing: `10 permit 10.6.0.0/16 destination 10.6.20.5 port
  7000-7100 log`, rules numbered in steps of ten, then `default deny`.

## Text form (`serde` feature)

```toml
default = "deny"            # optional; "permit" or "deny"

[[rule]]
action = "permit"
source = "10.9.0.0/16"      # optional; default "any"
destination = "10.6.20.5"   # optional
port = "7000-7100"          # optional
fingerprint = "sha256:..."  # optional
log = true                  # optional
```

Unknown keys are errors. Inside a `coqui-peer` policy the same table is `[acl]` with
`[[acl.rule]]` entries.
