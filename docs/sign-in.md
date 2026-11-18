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
| Purposes | `sign_in`, `resume` (a session that exists is checked again; `done` holds the steps it was opened with), `enrol` (a signed-in person sets up a second step of their own), `enrol_first` (a sign-in that has passed some steps, with no session yet, asks to set up the step it is waiting for) |
| Clients | `browser`, `app`, `api` |

`totp` and `recovery_code` check a code against an account an earlier step already named, so a
policy never offers them before one has (`coqui_access::methods::NEEDS_ACCOUNT`). A policy may use
method words of its own.

## What the consumer asks

The consumer builds a `SignInContext` and calls `decide`:

| Field | Meaning |
| --- | --- |
| `purpose` | One of the purposes above. |
| `done` | The steps already passed, each `{ method, provider, person }`: the provider is the id that accepted it and the person the `Person::id` it named. Empty before the first. |
| `address` | The client's IP address as the consumer determined it, text, no port. **`None` when it could not be determined, never `0.0.0.0` or another placeholder.** |
| `client`, `service` | The kind of client, and the consumer's own word for what is signed in to (`portal`, `pages`). `client` comes from how the consumer serves the request (the endpoint or listener it arrived on), never from anything the client says about itself. |
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
   refusal). **Wrong codes of a second factor are counted per `Person::id`**, whatever the
   address and whichever pending sign-in they were given to, and the count outlives the pending
   sign-in: a consumer that counts only per address, or only per pending sign-in, lets a guesser
   start over. After a few, further second-factor attempts for that person are refused without
   asking the authenticator. **The count decays**: it is forgotten after a quiet period the
   consumer sets (the stand-in consumer of the vectors uses 15 minutes), so a refusal is never
   forever and a person is not locked out for good by someone else's guesses. Reaching a code
   needs the first factor, so this guards a person whose password is already known; a throttle
   per address does not stop an attacker who spreads over many addresses, which is why the count
   is per person. The price is that anyone with the password can hold that person's second step
   shut for as long as they keep failing. (`coqui_access_totp` also delays an account under
   wrong codes by itself, and that delay decays too; it is a second line, not a replacement.)
5. **The next factor must name the same person** (`Person::id`). A one-time code is presented
   with `name` set to that id. A factor that names someone else fails. The consumer records the
   person in each `Factor`, and a policy refuses steps that name different people.
6. **A session is decided again when it resumes**, with `purpose = resume` and the steps it was
   opened with, wherever the consumer re-checks it (a token renewal, a page load, a new channel
   on an open session). The person is looked up again at resume, so an account that has been
   removed, disabled or moved to other groups is decided as it is now, not as it was at
   sign-in. A session that is no longer `complete` ends, and the page asks again.

### Throttling before anyone is named

When `password` (or any method that names the person only when it succeeds) is offered before
anyone is named, nothing yet says whose account a guess is against. The consumer therefore
throttles those attempts **per client address and per account name together** (and per address
alone), not per address only, so that one address cannot try every name and many addresses
cannot all try one name without the account's own count rising. The policy cannot do this: it
sees the context, not the attempts.

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
a rule with `purposes = ["enrol"]` says who may set up a second step. A group subject matches
without regard to case, so `group:Domain Users` reaches a person the directory reports in
`domain users`.

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
  enrols again, and the old secret keeps working until the new one is confirmed; the provider begins
  that only when `AccountPut::proved_current` says the consumer checked the current code (or a sign-in
  that just used it) in the same request, and refuses it otherwise.
- **Enrolling inside a sign-in.** A person who has no code yet cannot pass a chain that needs one, so a consumer
  may let the sign-in itself set one up, decided under `purpose = enrol_first` with the steps passed. Whoever holds
  those steps can then set up a code for that account, and the real person is shut out: so a policy allows it
  only by a rule that names `enrol_first`, and a deployment writes it for the networks it trusts with that
  (the first factor alone, from inside the office, say). A rule for `enrol` does not allow it.
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
- **Guessing.** A code is one in a million. The consumer counts every wrong code per person (see
  the contract) and caps the tries of a pending sign-in. The provider adds its own delay per
  account: after five wrong codes in a row (a recovery code counts too) the account takes no code
  for 30 s, twice as long with each further wrong one, up to an hour; a right code ends it and an
  administrator's `disabled` toggle resets it. The delay is a default a deployment can lift
  (`Lockout::OFF`, `lockout_after = 0`), and it lets anyone who can name an account keep its owner
  out for up to the longest delay at a time, which the consumer's per-address throttle limits. A
  code is accepted once; a step used, and earlier ones, are refused, also by another process
  sharing the file.
- **Storage.** The secret is kept readable in the table (a time-based code needs it); a file
  source writes it with the owner's permissions only, and holds an operating-system lock on
  `<path>.lock` around every read-modify-write, so processes sharing the file do not lose each
  other's updates.

## The shared vectors

The `test-support` feature of `coqui-access-signin` exposes `vectors::POLICY` and `vectors::FLOWS`.

- `policy.json`: `{ "cases": [ { name, config, context, expect } ] }`. `config` is the rules
  provider's configuration, `context` a `SignInContext`, and `expect` is `{ methods: [names],
  complete, providers? }`. Any implementation of the policy passes them.
- `flows.json`: scripted sign-ins for a consumer's real endpoint, with stand-in authenticators
  (`password` valid for `alice` with `pw`, the stand-in provider `ldap` rejecting every password
  and `local` accepting; `certificate` naming `alice` or `bob`; `totp` accepting `123456` for the id of
  the person already named). Each step is `{ action: offer | present | resume, address, method?, name?,
  secret?, after_seconds?, expect: { result, methods?, authenticator_calls, throttled, asked? } }` where `result` is
  `methods`, `refused_unasked`, `failed`, `next` or `signed_in`. There is a flow for each of the six
  points of the contract; the crate's own tests run them against a small stand-in consumer.
