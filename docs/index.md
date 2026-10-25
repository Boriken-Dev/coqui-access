# coqui-access

Who is asking, and may they: shared access building blocks for services that load providers
with [Guatiao](https://github.com/Boriken-Dev/guatiao).

## The kinds

| Kind | Answers |
| --- | --- |
| `coqui_authenticator` | Are these credentials valid, and which lookup do they name? |
| `coqui_directory` | Who is the person behind a lookup, and in which groups? |
| `coqui_authorizer` | May this person do this action on this resource? |
| `coqui_accounts` | Optional: list, put and remove accounts, and list unaccepted peers. |

A host asks authenticators in order until one knows the credentials, resolves the lookup
through a directory, and asks an authorizer. Kind names and the hashes of their required
methods are a pinned contract; providers are built against the host's Guatiao revision.

## Providers

| Provider id | Keeps | Takes |
| --- | --- | --- |
| `coqui_access_local` | Argon2id passwords in a TOML file | name and password |
| `coqui_access_key` | SHA-256 hashes of generated keys | a key |
| `coqui_access_ldap` | nothing; asks LDAP or Active Directory | name and password |
| `coqui_access_proxy` | nothing; trusts a reverse proxy | request headers |
| `coqui_access_peer` | peer certificate fingerprints | a verified certificate |
| `coqui_roles` | role rules (an authorizer) | person, action, resource |

Each is an ordinary library and a one-line `cdylib` (`coqui-access-<name>-plugin`).

## Peers and access lists

[`coqui-peer-tls`](https://github.com/Boriken-Dev/coqui-peer-tls) gives two services a
mutual-TLS connection that is trusted by certificate fingerprint, with strict defaults and
presets you can loosen. [`coqui-net-acl`](https://github.com/Boriken-Dev/coqui-net-acl) is an
ordered, first-match access control list for connecting addresses, usable with or without TLS.
Both live in their own repositories.

Source code, per-crate API headers and the changelog are in the
[repository](https://github.com/Boriken-Dev/coqui-access). The Rust API reference is under
[Rust API](https://boriken-dev.github.io/coqui-access/rust/index.html).
