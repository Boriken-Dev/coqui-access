//! Entries, ACLs and the ACL of one item, as data a consumer stores.

use alloc::string::String;
use alloc::vec::Vec;

use coqui_access::Subject;
use coqui_access::guatiao::{FromValue, Schema, ToValue};

use crate::options::Weakening;
use crate::principal::Principal;

/// Whether an entry grants or refuses its rights.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, FromValue, Schema, ToValue)]
#[map(crate = ::coqui_access::guatiao, rename_all = "lowercase")]
pub enum Effect {
    /// Grants. The default.
    #[default]
    Allow,
    /// Refuses.
    Deny,
}

/// How an entry passes to what an item contains, in Windows' terms (NFSv4 uses the same
/// four flags): `items` is OBJECT_INHERIT, `containers` CONTAINER_INHERIT, `no_propagate`
/// NO_PROPAGATE_INHERIT and `inherit_only` INHERIT_ONLY. In `MostSpecific` mode,
/// `containers` is Proxmox's `propagate`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, FromValue, Schema, ToValue)]
#[map(crate = ::coqui_access::guatiao, deny_unknown_fields)]
#[non_exhaustive]
pub struct Inherit {
    /// Passes to items (leaves) inside.
    #[map(default)]
    pub items: bool,
    /// Passes to containers inside, and on through them.
    #[map(default)]
    pub containers: bool,
    /// Passes one level only: the copy carries no inheritance of its own.
    #[map(default)]
    pub no_propagate: bool,
    /// Does not apply to the item that holds it, only to what inherits it.
    #[map(default)]
    pub inherit_only: bool,
}

impl Inherit {
    /// Passing to items, containers, both or neither.
    pub const fn new(items: bool, containers: bool) -> Self {
        Self {
            items,
            containers,
            no_propagate: false,
            inherit_only: false,
        }
    }

    /// The same, passing one level only.
    #[must_use]
    pub const fn no_propagate(mut self) -> Self {
        self.no_propagate = true;
        self
    }

    /// The same, not applying to the item that holds it.
    #[must_use]
    pub const fn inherit_only(mut self) -> Self {
        self.inherit_only = true;
        self
    }

    /// Whether it passes anywhere.
    pub const fn passes(&self) -> bool {
        self.items || self.containers
    }
}

/// One line of an ACL: who, allow or deny, which rights, and how it is inherited.
///
/// `rights` are names a [`RightsSchema`](crate::RightsSchema) defines (rights or aliases),
/// compiled when the ACL is checked. As configuration the principal is its text:
///
/// ```json
/// { "principal": "group:staff", "effect": "deny", "rights": ["write"],
///   "inherit": { "items": true, "containers": true } }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, FromValue, Schema, ToValue)]
#[map(crate = ::coqui_access::guatiao, deny_unknown_fields)]
#[non_exhaustive]
pub struct Entry {
    /// Who it applies to.
    #[map(as_text)]
    pub principal: Principal,
    /// Allow (the default) or deny.
    #[map(default)]
    pub effect: Effect,
    /// The rights and aliases it names.
    pub rights: Vec<String>,
    /// How it passes to what the item contains.
    #[map(default)]
    pub inherit: Inherit,
    /// Whether it was copied from a parent ([`Acl::inherited_by`]) rather than set here.
    #[map(default)]
    pub inherited: bool,
    /// A condition the consumer's [`Conditions`](crate::Conditions) decides; none means it
    /// always applies.
    pub condition: Option<String>,
}

impl Entry {
    /// An entry allowing `rights` to `principal`, inherited by nothing.
    pub fn allow(
        principal: impl Into<Principal>,
        rights: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            principal: principal.into(),
            effect: Effect::Allow,
            rights: rights.into_iter().map(Into::into).collect(),
            inherit: Inherit::default(),
            inherited: false,
            condition: None,
        }
    }

    /// An entry denying `rights` to `principal`, inherited by nothing.
    pub fn deny(
        principal: impl Into<Principal>,
        rights: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            effect: Effect::Deny,
            ..Self::allow(principal, rights)
        }
    }

    /// Sets how it is inherited.
    #[must_use]
    pub fn inherit(mut self, inherit: Inherit) -> Self {
        self.inherit = inherit;
        self
    }

    /// Marks it as copied from a parent.
    #[must_use]
    pub fn inherited(mut self, inherited: bool) -> Self {
        self.inherited = inherited;
        self
    }

    /// Sets its condition.
    #[must_use]
    pub fn condition(mut self, condition: impl Into<String>) -> Self {
        self.condition = Some(condition.into());
        self
    }
}

/// How an ACL's entries combine into a decision.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, FromValue, Schema, ToValue)]
#[map(crate = ::coqui_access::guatiao, rename_all = "snake_case")]
#[non_exhaustive]
pub enum Mode {
    /// Windows and NFSv4: entries in order, each right decided by the first entry that
    /// names it. An allow before a deny wins that right.
    Ordered,
    /// Order-free: any applicable deny of a right refuses it, else the union of the allows.
    /// The default, since no order can be got wrong.
    #[default]
    DenyOverrides,
    /// NetBox, TrueNAS RBAC: the union of the allows; a deny entry is refused.
    Additive,
    /// POSIX.1e: the requester's class decides (owner, then named user, then the owning
    /// and named groups, capped by the mask, then everyone); no deny.
    Posix,
    /// Proxmox: a walk from the root down, a deeper level replacing the one above, a
    /// level's subject entries beating its group entries; no deny, a cancelling name
    /// refuses everything.
    MostSpecific,
}

/// An access control list.
#[derive(Debug, Clone, Default, PartialEq, Eq, FromValue, Schema, ToValue)]
#[map(crate = ::coqui_access::guatiao, deny_unknown_fields)]
#[non_exhaustive]
pub struct Acl {
    /// The entries, in order.
    pub entries: Vec<Entry>,
    /// Whether it takes nothing from a parent ([`Acl::inherited_by`]): a protected DACL.
    #[map(default)]
    pub protected: bool,
    /// How the entries combine. Default `deny_overrides`.
    #[map(default)]
    pub mode: Mode,
}

impl Acl {
    /// An empty ACL in `mode`: it grants nothing.
    pub fn new(mode: Mode) -> Self {
        Self {
            entries: Vec::new(),
            protected: false,
            mode,
        }
    }

    /// Adds an entry after the others.
    #[must_use]
    pub fn entry(mut self, entry: Entry) -> Self {
        self.entries.push(entry);
        self
    }

    /// Sets whether it takes nothing from a parent.
    #[must_use]
    pub fn protected(mut self, protected: bool) -> Self {
        self.protected = protected;
        self
    }

    /// Sorts the entries into Windows' canonical order: explicit denies, explicit allows,
    /// then inherited entries in the order they were. The sort is stable.
    pub fn canonicalize(&mut self) {
        self.entries.sort_by_key(|entry| {
            (
                entry.inherited,
                !entry.inherited && entry.effect == Effect::Allow,
            )
        });
    }

    /// What this ACL grants more widely than a strict reading would, for the caller to
    /// report or refuse: every allow entry naming `Everyone`.
    pub fn weakened(&self) -> Vec<Weakening> {
        self.entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| {
                entry.effect == Effect::Allow
                    && entry.principal == Principal::Everyone
                    && !entry.inherit.inherit_only
            })
            .map(|(entry, _)| Weakening::EveryoneAllowed { entry })
            .collect()
    }
}

impl Extend<Entry> for Acl {
    fn extend<I: IntoIterator<Item = Entry>>(&mut self, entries: I) {
        self.entries.extend(entries);
    }
}

/// The ACL of one item, with the owner and owning group its `Owner` and `OwnerGroup`
/// entries resolve against. As configuration the subjects are their text.
#[derive(Debug, Clone, Default, PartialEq, Eq, FromValue, Schema, ToValue)]
#[map(crate = ::coqui_access::guatiao, deny_unknown_fields)]
#[non_exhaustive]
pub struct ItemAcl {
    /// The ACL.
    pub acl: Acl,
    /// Who owns the item.
    #[map(as_text)]
    pub owner: Option<Subject>,
    /// The item's owning group.
    #[map(as_text)]
    pub owner_group: Option<Subject>,
}

impl ItemAcl {
    /// The item's ACL, with no owner.
    pub fn new(acl: Acl) -> Self {
        Self {
            acl,
            owner: None,
            owner_group: None,
        }
    }

    /// Sets the owner.
    #[must_use]
    pub fn owner(mut self, owner: Subject) -> Self {
        self.owner = Some(owner);
        self
    }

    /// Sets the owning group.
    #[must_use]
    pub fn owner_group(mut self, group: Subject) -> Self {
        self.owner_group = Some(group);
        self
    }
}
