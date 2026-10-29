# `coqui-access-proxy` — API header

Header-file-style reference for the `coqui-access-proxy` crate: every public item with its
signature, contract and gotchas, so the crate can be used without reading its source. It
ships inside the package and is self-contained. Development documentation lives with the
source at <https://github.com/Boriken-Dev/coqui-access>.

MSRV Rust 1.89. No Cargo features. Depends on `coqui-access` and `coqui-net-acl` (address lists). No `unsafe` code. The
loadable library is the separate crate `coqui-access-proxy-plugin`.

```rust
pub struct ProxyWordConfig {
    pub trusted: Vec<String>,            // addresses and CIDR networks (coqui-net-acl IpNet); empty trusts nobody; `any` refused
    pub user_header: Option<String>,     // account name header
    pub subject_header: Option<String>,  // client-certificate subject header
    pub subject_field: String,           // default "CN" when empty
}
pub struct ProxyWord;                    // provider id "coqui_access_proxy", kind Authenticator
impl ProxyWord { pub fn new(config: ProxyWordConfig) -> Result<Self, String>; }
pub fn field_of(subject: &str, field: &str) -> Option<String>;
```

## Behaviour

- `new` returns an invalid network entry verbatim as the error.
- `authenticate` looks at `Attempt::peer` (an address or `address:port`): not inside a
  trusted network gives `Unknown`. For a trusted peer the account comes from `user_header`
  (default `x-remote-user` unless `subject_header` is set), else from `subject_field` of
  `subject_header`. A header present more than once, in any case, is `Invalid`. No usable
  identity is `Unknown`; otherwise `Lookup { by: "name", value: name }` for the configured
  directory. Header names match case-insensitively over the ordered `headers` pairs.
- IPv4-mapped IPv6 peers match IPv4 networks, and a mapped network (`::ffff:10.0.0.0/120`)
  is the IPv4 network it maps (`10.0.0.0/24`). `any` is refused: trusting every address is
  not a reverse proxy. Groups are never read from headers.
- `field_of` honours escaped commas and also reads slash-separated subjects.
