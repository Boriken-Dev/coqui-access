# Access control lists on items

`coqui-access-acl` decides requests against access control lists the consumer keeps on its
own items: each item carries entries naming who may do what to it. The consumer stores items
and lists (any format, through guatiao's derives); the crate evaluates them. It is a library,
not a plugin: its `AclAuthorizer` answers the `coqui_authorizer` kind for a host that builds
it over its own store.

## Rights

A `RightsSchema` names the rights of one type of item, one bit each in the order they are
defined, and aliases that stand for several. A cancelling name grants nothing and refuses
everything where it is in force.

| Product | Rights | Aliases |
| --- | --- | --- |
| Windows | the 32-bit access mask (`read_data`, `write_dac`, …) | generic rights (`generic_read`) |
| NFSv4, TrueNAS | the 14 permissions | basic permissions (`FULL_CONTROL`) |
| Proxmox | privileges (`VM.Audit`) | roles (`PVEVMUser`); `NoAccess` cancels |
| NetBox | `view`, `add`, `change`, `delete` and custom actions | none needed |

## Entries

An entry is a principal, allow or deny, the right and alias names it covers, inheritance
flags, and an optional condition:

```json
{ "principal": "group:staff", "effect": "deny", "rights": ["write_data"],
  "inherit": { "items": true, "containers": true }, "condition": "@Device.managed == 0" }
```

Principals are `account:<name>`, `person:<id>`, `group:<name>`, `everyone`, `authenticated`,
`owner`, `owner_group`, and `mask` for POSIX. `owner` and `owner_group` resolve against the
item's owner and owning group, stored beside its list.

## Modes

| Mode | Products | How entries combine |
| --- | --- | --- |
| `ordered` | Windows, NFSv4 | in order, each right decided by the first entry naming it |
| `deny_overrides` (default) | | any applicable deny refuses its rights; allows are unioned |
| `additive` | NetBox, TrueNAS API roles | allows unioned; a deny entry is refused |
| `posix` | POSIX.1e ACLs | owner, else named user, else one group entry, capped by the mask, else everyone |
| `most_specific` | Proxmox | walked from the root down; a deeper level replaces, a user's entries beat its groups' |

A check answers with a `Decision`: whether every wanted right is granted, what was granted
and denied, and which entry decided, for an audit record.

## Inheritance

Two ways, chosen by the consumer:

- **Copied** when an item is made (Windows, NFSv4, POSIX default ACLs):
  `Acl::inherited_by` applies Windows' flag table to the parent's entries and the consumer
  stores the result. Nothing is walked at check time.
- **Walked** at check time (Proxmox): an `AclStore` answers an item's list and its parent,
  and the check walks from the root down within a depth bound, refusing a cycle.

## Conditions, tokens and pools

Conditions are the consumer's to decide (`Conditions::holds`): a NetBox constraint checked
against its database, a Windows conditional expression. An unknown answer skips an allow and
applies a deny. A token's own list narrows its person's decision with `Decision::intersect`;
a second parent such as a Proxmox pool adds rights the item's own walk left unset with
`Decision::union_where_unset`. A superuser bypass is the consumer's check before asking.

## Options

Every bound is an option with a default (1 024 entries, 1 024 rights, 64 levels; `None`
lifts it). What weakens a decision is reported as data, never refused: an item with no list
granting everything (`OnMissing::AllowAll`, a Windows NULL DACL) and an allow to `everyone`.
