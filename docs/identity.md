# From a credential to an account

An authenticator that has more than a name (a client certificate, say) answers with what it
obtained, in full: its **claims**. A **matcher** ties those claims to an account in a directory.
The rule that holds throughout: **the directory, not the credential, decides the account and its
groups.** A claim is only a way to ask the directory a question.

## Claims

`Lookup` carries `claims` beside `by` and `value`. An authenticator that names no account itself
answers `by: "claims"`, and the consumer sends the lookup to a matcher; any other `by` is looked up
in the directory as it is.

For a certificate the claims are:

| Claim | Holds |
| --- | --- |
| `subject.dn`, `issuer.dn` | the distinguished names as text, in certificate order |
| `subject.cn`, `subject.o`, `subject.ou`, `subject.c`, ... | each attribute of the subject; `issuer.<attribute>` likewise |
| `serial.hex`, `serial.reversed` | the serial number in lowercase hex, and the same bytes last first |
| `san.upn`, `san.email`, `san.dns`, `san.uri`, `san.ip` | each subject alternative name of that kind |
| `fingerprint`, `spki` | `sha256:<hex>` of the whole certificate, and of its public key |
| `not_before`, `not_after` | Unix seconds |

and `Claims::certificate` holds the leaf as DER. A claim the certificate does not have is absent. A
claim may have several values (two email SANs), in certificate order.

## The matcher

A matcher is an ordered list of rules. Each rule is a template over the claims, and what the
rendered text is in the directory:

```toml
[[rule]]
by = "name"                     # name, email, id, or filter
template = "{san.upn|local}"    # claims and filters
```

- `{claim}` is a claim's value; `{claim|lower|local}` passes it through filters: `lower`, `upper`,
  `local` (the part before the last `@`) and `domain` (the part after it). `{{` and `}}` are braces.
  A template names at least one claim: a rule that looked up the same account for everybody is
  refused when the matcher is built.
- A claim that is missing, or empty, makes the rule not apply. A claim with several values renders
  one candidate per value (at most 16 in all).
- **The default rules** are the UPN as a name (`{san.upn}`), the email address as an email
  (`{san.email}`), and the subject's common name as a name (`{subject.cn}`).

### An LDAP filter

With `by = "filter"` the template is an LDAP filter, for a directory that can search by one
(`coqui_access_ldap`):

```toml
[[rule]]
by = "filter"
template = "(altSecurityIdentities=X509:<I>{issuer.dn}<SR>{serial.reversed})"

[[rule]]
by = "filter"
template = "(userPrincipalName={san.upn})"
```

**Every value a claim puts into a filter is escaped** (RFC 4515): `*`, `(`, `)`, `\`, NUL and every
other control character, and every byte of a non-ASCII character, become `\` and two hex digits, so a
certificate can never end the assertion, start another, or become a wildcard. The text of the
template itself is the filter's structure and is written as it stands. The filter must be one
parenthesised group; the directory ANDs it with its own account filter (`object_filter`, by default
`(objectClass=user)`), so it can only narrow what the provider is configured to read.

### Which account wins

Rules are tried in order, and for each rule every candidate is asked of the directory.

- **Exactly one account** (counted by identity, so two candidates that find the same account are one)
  is the match, and the walk ends.
- **More than one account** is refused as *ambiguous*, and the walk ends: a matcher never chooses. A
  directory says a single lookup found several by answering `error::ambiguous()`.
- **None** goes on to the next rule.
- A directory that **cannot answer** is an error, never a reason to try the next rule.

Order is the operator's tool: put the most specific rule first.

## Pins: a one-to-one map

A rule can also require that the account it found has *pinned* this certificate. A pin is the SHA-256
of the whole certificate (a fingerprint) or of its public key (which a renewed certificate on the same
key keeps):

```toml
[[rule]]
by = "name"
template = "{san.upn|local}"
pins = "files"          # the name of a pin source the consumer gave the matcher
```

The rule first names a candidate account by its template, and only then asks the pin source about
**that one account**; a source is never asked to scan. If the account holds a pin the rule finds it;
otherwise the matcher goes on to the next rule. A source that refuses (a file with the wrong
permissions) counts as no pins, and its reason is reported in the match's `notes`.

The library does not decide where pins live. The matcher takes sources from the consumer, by name, and
two ship:

- **A per-user file**, `AuthorizedFile`, in the manner of `~/.ssh/authorized_keys`.
- **A global table**, `TablePins`, over any table of `{ name, pin }`; `coqui-access-mtls` is also a
  source over its own records.

A consumer can implement `PinSource` itself.

### The per-user file

The path is a template the consumer sets, for example `{home}/.myapp/authorized_certificates`. `{home}`
is the account's `home` attribute from the directory (`coqui_access_system` provides it on Unix with
`uid`); `{name}` and `{id}` are each one safe path component, never one holding `/`, `\`, `..` or a
control character. The result must be absolute and hold no `..`.

The file has one pin per line:

```text
# my smartcard, renewed yearly
spki-sha256:8f1c...64 hex digits...   office smartcard
sha256:00ff...64 hex digits...        laptop certificate, this year only
```

`sha256:<hex>` is a certificate's fingerprint and `spki-sha256:<hex>` its public key, in any case,
followed by optional whitespace and a comment. Blank lines and lines starting `#` are ignored; a line
that is not a pin is skipped (and counted in the reason when no pin is held). A file may hold 1 024
lines and 64 KiB.

**Who reads it.** Reading is done by a `PinFileReader` the consumer may supply, for a service that
cannot open people's homes and reads through a helper running as root. The reader receives the
candidate account (with its `home` and `uid`) and the rendered path, and returns the text, "no such
file", or a refusal with a reason. The library parses what a reader returns and treats a refusal as no
pins, but does not repeat checks it cannot see: a custom reader makes the checks below wherever it has
access.

**The default reader** opens the file itself and makes the checks sshd makes of `authorized_keys`
(Unix only; on other platforms it refuses):

- the account has a `uid` and a `home`;
- the file's real path is inside the real home, and the file is not itself a symlink (a symlinked
  directory that stays inside the home is followed; one that leaves it is refused);
- the file is a regular file, at most 64 KiB;
- the file, and every directory from its parent up to and including the home, is **owned by the
  account's uid or by root**, and is **not writable by group or others**.

A file that fails any check counts as no pins, and the reason is reported. A file that is not there is
simply no pins.
