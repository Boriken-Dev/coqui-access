# Binding to a directory: LDAP and Active Directory

`coqui_access_ldap` binds twice: its **search account** binds to find an account and read its groups,
and a **person's** password is checked by a bind of their own. Each has a method, and each method
asks something of the server, the build and the operator.

## The search account: `bind_method`

| `bind_method` | Settings | Stored secret | The server needs | The build needs |
| --- | --- | --- | --- | --- |
| `simple` (default) | `bind`, `bind_password`; neither binds anonymously | a password | a service account | nothing |
| `gssapi` | `server_fqdn` (default: the URL's host, which must be a name) | none: the process's own Kerberos credentials | a service principal `ldap/<server_fqdn>` and a client with a ticket or keytab | feature `gssapi` |
| `ntlm` | `bind` as `DOMAIN\user` or `user@domain`, `bind_password` | a password | NTLM enabled; Active Directory has it | feature `ntlm` |
| `external` | `client_cert` and `client_key` (PEM) over `ldaps://` or StartTLS, with `ca_file`; or an `ldapi://` URL | a private key, or none | the certificate mapped to an entry (OpenLDAP `authz-regexp`; Active Directory maps it to an account); or the socket's peer credentials mapped | nothing |

A method whose feature is not built is a configuration error that names the feature.

**GSSAPI.** On Windows the credentials are the process's own account (SSPI). On Unix they are
whatever libgssapi finds: `KRB5CCNAME` for a ticket cache, `KRB5_CLIENT_KTNAME` for a keytab and
`KRB5_CONFIG` for the realm; they are set in the environment the host starts the provider in, because
no setting of the provider can change them safely once threads run. Over plain `ldap://` the
connection is sealed (Kerberos encryption) after the bind, which satisfies a directory that requires
signing: Active Directory's "LDAP server signing requirements" and a server with `security
simple_bind=128`. Over `ldaps://` or StartTLS the certificate's hash goes along as the channel
binding, which satisfies the strictest channel binding policy. The calls block on the ticket cache
and the KDC, as the rest of the provider does. The server name is the one the Kerberos service
principal carries: a URL that names an address needs `server_fqdn`.

**Build.** On Windows nothing is needed. On Unix `libgssapi_krb5` is linked (MIT or Heimdal), and
its bindings are generated at build time, so the Kerberos development files (`krb5-devel`,
`libkrb5-dev`) and libclang are needed; the running host needs the library only. `ntlm` is pure
Rust; the feature holds two of its dependencies at the versions its `sspi` builds with.

**EXTERNAL.** The identity is whatever the TLS client certificate or the `ldapi://` socket's peer
already proved, so no password is stored. Over TLS `client_cert` needs `ca_file`, which is also what
the directory's own certificate is checked against.

## A person: `user_bind`

| `user_bind` | What is sent | Needs |
| --- | --- | --- |
| `simple` (default) | a simple bind as the account's distinguished name, on the search account's connection | a connection that protects a password (below) |
| `ntlm` | the name the person typed (`user`, `DOMAIN\user` or `user@domain`) and the password, as NTLM, on a connection of its own | feature `ntlm` |

Kerberos for people is the job of a Negotiate authenticator, not of this provider. A name that NTLM
cannot parse is an invalid sign-in, never a panic.

## Strict by default, and what weakening costs

A password may cross a plain `ldap://` connection to another machine only when
`allow_cleartext_password` is on. By default such a URL is refused unless StartTLS is on, the host
is the local machine, or no password would cross it: a `gssapi` search account seals the connection
and the person's simple bind rides that layer. `non_defaults()` lists, as data and never as a log line,
what is turned down, with any TLS option past the default policy (`Tls`):

| Non-default | When | Cost |
| --- | --- | --- |
| `CleartextPassword` | `allow_cleartext_password` is on | passwords are readable and replayable by anyone on the path |
| `UnprotectedNtlm` | NTLM binds with no TLS | no password crosses, but nothing after the bind is signed or sealed, so the session can be altered and read |

Nothing else about a bind method is checked behind the operator's back: a value that cannot work
(a bind DN with `gssapi`, `external` with no certificate, an address for a Kerberos name, a malformed
NTLM name) is a configuration error; the rest is the operator's choice.
