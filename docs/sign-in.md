# Sign-in policy

The `coqui_sign_in_policy` kind decides which methods a sign-in may use, from where and how
it is made, and what a sign-in still needs once a step has passed. A deployment writes the
policy as data (the `coqui_signin_rules` provider, below) or supplies a provider of its own, in
any language Guatiao loads. This page is the contract a consumer (a web portal, an API
gateway) follows so that every consumer behaves alike; the shared vectors under
`crates/coqui-access-signin/vectors/` prove it.

## Words

| Group | Words |
| --- | --- |
| Methods | `password`, `certificate`, `proxy`, `key`, `totp`, `recovery_code` |
| Purposes | `sign_in`, `resume` (a session that exists is checked again; `done` holds the steps it was opened with), `enrol` (a person sets up a second step of their own) |
| Clients | `browser`, `app`, `api` |

`totp` and `recovery_code` check a code against an account an earlier step already named, so a
policy never offers them before one has (`coqui_access::methods::NEEDS_ACCOUNT`). A policy may use
method words of its own.

## What the consumer asks

The consumer builds a `SignInContext` and calls `decide`:

| Field | Meaning |
| --- | --- |
| `purpose` | One of the purposes above. |
| `done` | The steps already passed, each `{ method, provider }`, the provider being the id that accepted it. Empty before the first. |
| `address` | The client's IP address as the consumer determined it, text, no port. **`None` when it could not be determined, never `0.0.0.0` or another placeholder.** |
| `client`, `service` | The kind of client, and the consumer's own word for what is signed in to (`portal`, `pages`). |
| `time_unix` | When it is asked. |
| `person` | Who the passed steps named, once one did. |
| `attributes` | Anything else the consumer says; a policy reads what it knows. |

The answer is a `SignInDecision`: `complete` (the steps passed are enough), `methods` (what may
be presented next, each `{ method, providers }`, an empty `providers` meaning any provider that
takes the method), and `rule`, the name of the rule that decided, for a log.

`decide` returns `Err` when it could not find out. The consumer then offers nothing and refuses;
it never falls back to allowing.

### Determining the address

The address is the peer of the connection, or, when the connection comes from a proxy the
consumer trusts by address, the address that proxy reports (the first untrusted hop of a
forwarding header, read from the right). If the header is missing, malformed, or every hop is
trusted, the address is unknown: pass `None`. A proxy inside a trusted network must not make
every client look like it is inside it.

## The contract

1. **The page's offer** is `decide` with `done = []` and no `person`. The consumer shows exactly
   those methods and no others.
2. **A presented method is decided again on its own request.** The consumer calls `decide`
   again, with the sign-in's pending state if any, and a method that is not offered is
   answered `403` ("not accepted from here"): no authenticator is asked and no throttle counts it.
3. **Only the offered providers are asked**, in the order the offer lists them; an empty list
   is every provider that takes the method, in the consumer's own order.
4. **A valid factor resolves to a person, and the policy decides again with that person.**
   `complete` opens the session, recording the steps passed. An offer opens a *pending* sign-in:
   kept on the server, short-lived, bound to the browser that began it, with a cap on tries
   of its own. No methods and not complete is refused exactly as a wrong password is (counted
   by the same throttle, the same answer, so nothing tells a wrong password from a policy
   refusal).
5. **The next factor must name the same person** (`Person::id`). A one-time code is presented
   with `name` set to that id. A factor that names someone else fails.
6. **A session is decided again when it resumes**, with `purpose = resume` and the steps it was
   opened with, wherever the consumer re-checks it (a token renewal, a page load, a new channel
   on an open session). A session that is no longer `complete` ends, and the page asks again.

The answer to the page is `{"methods": [...]}`, and `{"step": "next", "methods": [...]}` while a
sign-in is pending.

## The rules provider

`coqui_signin_rules` (the crate `coqui-access-signin`, a library, and `coqui-access-signin-plugin`,
its loadable form) takes ordered rules:

```toml
# From inside 10.0.0.0/8 a password or a certificate; from anywhere else, and when the
# address is not known, the certificate alone.
[[sign_in_policy.config.rule]]
networks = ["10.0.0.0/8"]
allow = [["password"], ["certificate"]]

[[sign_in_policy.config.rule]]
allow = [["certificate"]]
```

A rule has conditions (`purposes`, `networks`, `clients`, `services`, `subjects`) and `allow`, a list
of chains; a chain is a set of methods that must all succeed and name one account. Every
condition left out is true; `purposes` defaults to `sign_in` and `resume`, so a rule for `enrol` is
always written out. `providers` limits who is asked for the methods the rule offers.

**Evaluation order.** A rule is true, false or unknown; a false condition makes it false, and
`subjects` makes it unknown until a step has named someone.

- *Before anyone is named*, rules are walked in order. The chains of every unknown rule are
  collected, the first true rule's are collected and the walk stops. The offer is the methods
  of what was collected, minus `totp` and `recovery_code`.
- *Once someone is named*, the first true rule alone decides. The sign-in is complete when one of
  its chains is within the steps done. Otherwise the offer is what the chains that hold every step
  done still lack; none such is a refusal. No true rule is a refusal.

**An address that is not known never matches a network**, nor does text that is not an IP
address; an IPv4-mapped IPv6 address is the IPv4 address. Order is the operator's tool: the
strictest rule goes last, where an unknown address falls.

Growing it is data, not code: `["password", "totp"]` in a rule's `allow` asks for a code after the
password, a rule with `subjects = ["group:admins"]` above the others narrows it for a group, and
a rule with `purposes = ["enrol"]` says who may set up a second step.

With no policy configured, a consumer uses `SignInRules::single_factor(methods)`: each
configured method alone is enough, from anywhere, and enrolment is an administrator's only.

## Enrolment and recovery

`coqui_access_totp` (the crate `coqui-access-totp`) is the first second step: a one-time code from
an authenticator app, which works in a browser, a desktop app and a command line alike. It is an
`Authenticator` taking `takes::OTP` and an `Accounts` provider; the consumer manages it through the
`Accounts` kind.

- **Enrol.** `put` with a name (the `Person::id`) and no secret begins an enrolment and answers an
  `otpauth://` link, to show as a QR code, and the recovery codes, said once. Nothing is a factor
  yet. `put` again with `secret` set to a code from the app confirms it. A person who rotates
  enrols again: the old secret keeps working until the new one is confirmed.
- **Who may enrol.** The library does not decide; the consumer does. The recommended rule:
  a person may enrol themselves only after a fresh sign-in decided under `purpose = enrol`, which
  needs an `enrol` rule in the policy, so that a password accepted at the office cannot set up a
  factor that a stricter rule outside would later accept. With no `enrol` rule only an
  administrator enrols. An administrator can always enrol or reset anyone.
- **Sign in.** The consumer presents the code with `method = totp` and `name` set to the id of the
  person the first step named. A policy chain `["password", "totp"]` asks for it.
- **Recover.** Ten recovery codes are made at enrolment, shown once, each good once, and presented
  as `method = recovery_code`. The policy must name the method (`["password", "recovery_code"]`
  in a rule of its own, say), so a deployment can keep recovery inside its network. An
  administrator resets a person with `remove`, after which the person enrols again.
- **Guessing.** A code is one in a million, and the provider does not throttle: the consumer counts
  every wrong code in its throttle and caps the tries of a pending sign-in. A code is accepted
  once; a step used, and earlier ones, are refused.
- **Storage.** The secret is kept readable in the table (a time-based code needs it); a file
  source writes it with the owner's permissions only.

## The shared vectors

The `test-support` feature of `coqui-access-signin` exposes `vectors::POLICY` and `vectors::FLOWS`.

- `policy.json`: `{ "cases": [ { name, config, context, expect } ] }`. `config` is the rules
  provider's configuration, `context` a `SignInContext`, and `expect` is `{ methods: [names],
  complete, providers? }`. Any implementation of the policy passes them.
- `flows.json`: scripted sign-ins for a consumer's real endpoint, with stand-in authenticators
  (`password` valid for `alice` with `pw`, the stand-in provider `ldap` rejecting every password
  and `local` accepting; `certificate` naming `alice` or `bob`; `totp` accepting `123456` for the id of
  the person already named). Each step is `{ action: offer | present | resume, address, method?, name?,
  secret?, expect: { result, methods?, authenticator_calls, throttled, asked? } }` where `result` is
  `methods`, `refused_unasked`, `failed`, `next` or `signed_in`. There is a flow for each of the six
  points of the contract; the crate's own tests run them against a small stand-in consumer.
