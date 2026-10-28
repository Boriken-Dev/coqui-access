//! Checking a request against one ACL.

use alloc::vec::Vec;
use core::fmt;

use coqui_access::{Person, Subject};

use crate::condition::{Conditions, Truth};
use crate::entry::{Acl, Effect, Entry, ItemAcl, Mode};
use crate::error::AclError;
use crate::options::Options;
use crate::principal::Principal;
use crate::rights::{Rights, RightsSchema};

/// Everything a check needs besides the ACL and the rights wanted: the schema, who asks,
/// the item's owner, the consumer's conditions and the options.
#[derive(Clone)]
pub struct Context<'a> {
    pub(crate) schema: &'a RightsSchema,
    pub(crate) person: Option<&'a Person>,
    pub(crate) owner: Option<&'a Subject>,
    pub(crate) owner_group: Option<&'a Subject>,
    pub(crate) owner_rights: Rights,
    pub(crate) conditions: Option<&'a dyn Conditions>,
    pub(crate) item: &'a str,
    pub(crate) options: Options,
}

impl fmt::Debug for Context<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Context")
            .field("signed_in", &self.person.is_some())
            .field("owner", &self.owner)
            .field("owner_group", &self.owner_group)
            .field("owner_rights", &self.owner_rights)
            .field("conditions", &self.conditions.is_some())
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

impl<'a> Context<'a> {
    /// A check by nobody signed in, of an item with no owner, with default options.
    pub fn new(schema: &'a RightsSchema) -> Self {
        Self {
            schema,
            person: None,
            owner: None,
            owner_group: None,
            owner_rights: Rights::new(),
            conditions: None,
            item: "",
            options: Options::default(),
        }
    }

    /// Who asks.
    #[must_use]
    pub fn person(mut self, person: &'a Person) -> Self {
        self.person = Some(person);
        self
    }

    /// The item's owner. [`ItemAcl::check`] sets it from the item.
    #[must_use]
    pub fn owner(mut self, owner: Option<&'a Subject>) -> Self {
        self.owner = owner;
        self
    }

    /// The item's owning group. [`ItemAcl::check`] sets it from the item.
    #[must_use]
    pub fn owner_group(mut self, group: Option<&'a Subject>) -> Self {
        self.owner_group = group;
        self
    }

    /// Rights the owner holds whatever the entries say, unless an entry names `Owner`
    /// (Windows grants READ_CONTROL and WRITE_DAC, dropped by an OWNER RIGHTS entry).
    /// Default none.
    #[must_use]
    pub fn owner_rights(mut self, rights: Rights) -> Self {
        self.owner_rights = rights;
        self
    }

    /// The consumer's conditions; without them every condition is unknown.
    #[must_use]
    pub fn conditions(mut self, conditions: &'a dyn Conditions) -> Self {
        self.conditions = Some(conditions);
        self
    }

    /// The item checked, as conditions are told it.
    #[must_use]
    pub fn item(mut self, item: &'a str) -> Self {
        self.item = item;
        self
    }

    /// The options.
    #[must_use]
    pub fn options(mut self, options: Options) -> Self {
        self.options = options;
        self
    }

    fn truth(&self, condition: &str) -> Truth {
        match (self.conditions, self.person) {
            (Some(conditions), Some(person)) => conditions.holds(condition, self.item, person),
            _ => Truth::Unknown,
        }
    }

    fn is(&self, principal: &Principal) -> bool {
        principal.matches(self.person, self.owner, self.owner_group)
    }

    /// Whether `entry` applies to this request at all: its principal matches and its
    /// condition lets it (an allow needs `True`, a deny anything but `False`).
    pub(crate) fn applies(&self, entry: &Entry) -> bool {
        self.is(&entry.principal)
            && entry.condition.as_deref().is_none_or(|condition| {
                match (entry.effect, self.truth(condition)) {
                    (_, Truth::True) => true,
                    (_, Truth::False) => false,
                    (Effect::Allow, Truth::Unknown) => false,
                    (Effect::Deny, Truth::Unknown) => true,
                }
            })
    }

    /// The owner's standing rights, unless an entry names the owner.
    pub(crate) fn owner_grant(&self, acl: &Acl) -> Rights {
        let named = acl
            .entries
            .iter()
            .any(|entry| entry.principal == Principal::Owner);
        if !named && self.is(&Principal::Owner) {
            self.owner_rights.clone()
        } else {
            Rights::new()
        }
    }
}

/// What a check came to.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Decision {
    /// Whether every wanted right is granted.
    pub allowed: bool,
    /// The rights asked for.
    pub wanted: Rights,
    /// The rights the ACL grants this requester, whether asked for or not.
    pub granted: Rights,
    /// The rights an entry refused this requester.
    pub denied: Rights,
    /// The entry that decided, for an audit record: the deny that refused, the allow that
    /// completed the grant, or the cancelling entry; `None` when no entry decided.
    pub deciding: Option<usize>,
    /// Whether a cancelling name refused everything.
    pub cancelled: bool,
}

impl Decision {
    pub(crate) fn nothing(wanted: &Rights) -> Self {
        Self::from_sets(wanted, Rights::new(), Rights::new(), None)
    }

    pub(crate) fn from_sets(
        wanted: &Rights,
        granted: Rights,
        denied: Rights,
        deciding: Option<usize>,
    ) -> Self {
        Self {
            allowed: wanted.is_subset(&granted),
            wanted: wanted.clone(),
            granted,
            denied,
            deciding,
            cancelled: false,
        }
    }

    pub(crate) fn cancelled(schema: &RightsSchema, wanted: &Rights, entry: usize) -> Self {
        Self {
            allowed: false,
            wanted: wanted.clone(),
            granted: Rights::new(),
            denied: schema.all(),
            deciding: Some(entry),
            cancelled: true,
        }
    }

    /// Both decisions at once, for a token with an ACL of its own or a read-only token
    /// (Proxmox privilege separation, NetBox `write_enabled`): granted only what both
    /// grant, denied what either denies, allowed only if both allow. `deciding` is the
    /// first refusing side's, else this one's.
    #[must_use]
    pub fn intersect(&self, other: &Decision) -> Decision {
        let deciding = if !self.allowed || other.allowed {
            self.deciding
        } else {
            other.deciding
        };
        Decision {
            allowed: self.allowed && other.allowed,
            wanted: &self.wanted | &other.wanted,
            granted: &self.granted & &other.granted,
            denied: &self.denied | &other.denied,
            deciding,
            cancelled: self.cancelled || other.cancelled,
        }
    }

    /// This decision, with `other` deciding the rights this one left unset (neither
    /// granted nor denied): a second parent such as a Proxmox pool. A cancelled side wins
    /// (this one first).
    #[must_use]
    pub fn union_where_unset(&self, other: &Decision) -> Decision {
        if self.cancelled {
            return self.clone();
        }
        if other.cancelled {
            return other.clone();
        }
        let set = &self.granted | &self.denied;
        let granted = &self.granted | &(&other.granted - &set);
        let denied = &self.denied | &(&other.denied - &set);
        let wanted = &self.wanted | &other.wanted;
        let deciding = if wanted.is_subset(&set) {
            self.deciding
        } else {
            other.deciding.or(self.deciding)
        };
        Decision::from_sets(&wanted, granted, denied, deciding)
    }
}

/// One entry compiled against the schema.
pub(crate) struct Compiled {
    pub(crate) rights: Rights,
    pub(crate) cancels: bool,
}

impl Acl {
    /// Checks this ACL against `schema` and `limits` without evaluating it.
    ///
    /// # Errors
    ///
    /// As [`check`](Acl::check).
    pub fn validate(&self, schema: &RightsSchema, options: &Options) -> Result<(), AclError> {
        self.compile(schema, options).map(drop)
    }

    pub(crate) fn compile(
        &self,
        schema: &RightsSchema,
        options: &Options,
    ) -> Result<Vec<Compiled>, AclError> {
        if options
            .limits
            .entries
            .is_some_and(|max| self.entries.len() > max)
        {
            return Err(AclError::TooManyEntries);
        }
        let mut masks = [0u8; 2];
        self.entries
            .iter()
            .enumerate()
            .map(|(at, entry)| {
                let denies = !matches!(self.mode, Mode::Ordered | Mode::DenyOverrides);
                if denies && entry.effect == Effect::Deny {
                    return Err(AclError::DenyNotAllowed { entry: at });
                }
                let posix = self.mode == Mode::Posix;
                let refused = match entry.principal {
                    // One mask in force and one passed to children (a POSIX default ACL).
                    Principal::Mask => {
                        let slot = usize::from(entry.inherit.inherit_only);
                        masks[slot] += 1;
                        !posix || masks[slot] > 1
                    }
                    Principal::Authenticated => posix,
                    _ => false,
                };
                if refused {
                    return Err(AclError::PrincipalNotAllowed { entry: at });
                }
                let (rights, cancels) =
                    schema
                        .compile(&entry.rights)
                        .map_err(|name| AclError::UnknownRight {
                            entry: Some(at),
                            at: name,
                        })?;
                Ok(Compiled { rights, cancels })
            })
            .collect()
    }

    /// Whether the requester in `context` holds every right in `wanted` on an item with this
    /// ACL. Entries marked `inherit_only` do not apply here. An applicable entry naming a
    /// cancelling name refuses everything, in every mode.
    ///
    /// An empty `wanted` is allowed: nothing was asked for.
    ///
    /// # Errors
    ///
    /// The ACL is not usable with this schema and these options: more entries than
    /// [`Limits::entries`](crate::Limits::entries), a name the schema lacks, a deny where
    /// the mode has none, a principal the mode does not take.
    pub fn check(&self, context: &Context<'_>, wanted: &Rights) -> Result<Decision, AclError> {
        let compiled = self.compile(context.schema, &context.options)?;
        let applicable: Vec<(usize, &Entry, &Compiled)> = self
            .entries
            .iter()
            .zip(&compiled)
            .enumerate()
            .filter(|(_, (entry, _))| !entry.inherit.inherit_only && context.applies(entry))
            .map(|(at, (entry, compiled))| (at, entry, compiled))
            .collect();
        if self.mode != Mode::MostSpecific
            && let Some((at, ..)) = applicable.iter().find(|(_, _, compiled)| compiled.cancels)
        {
            return Ok(Decision::cancelled(context.schema, wanted, *at));
        }
        let owner = context.owner_grant(self);
        Ok(match self.mode {
            Mode::Ordered => ordered(&applicable, owner, wanted),
            Mode::Posix => {
                let mask = self
                    .entries
                    .iter()
                    .zip(&compiled)
                    .find(|(entry, _)| {
                        entry.principal == Principal::Mask && !entry.inherit.inherit_only
                    })
                    .map(|(_, compiled)| &compiled.rights);
                posix(&applicable, mask, context, owner, wanted)
            }
            Mode::MostSpecific => match level(&applicable) {
                Some(Level {
                    cancel: Some(at), ..
                }) => Decision::cancelled(context.schema, wanted, at),
                Some(level) => Decision::from_sets(
                    wanted,
                    &level.rights | &owner,
                    Rights::new(),
                    level.deciding,
                ),
                None => Decision::from_sets(wanted, owner, Rights::new(), None),
            },
            Mode::DenyOverrides | Mode::Additive => deny_overrides(&applicable, owner, wanted),
        })
    }
}

impl ItemAcl {
    /// [`Acl::check`] with the context's owner and owning group taken from this item.
    ///
    /// # Errors
    ///
    /// As [`Acl::check`].
    pub fn check(&self, context: &Context<'_>, wanted: &Rights) -> Result<Decision, AclError> {
        self.acl.check(&context.for_item(self), wanted)
    }
}

type Applicable<'a> = [(usize, &'a Entry, &'a Compiled)];

/// Each right decided by the first applicable entry naming it.
fn ordered(applicable: &Applicable<'_>, owner: Rights, wanted: &Rights) -> Decision {
    let mut granted = owner;
    let mut denied = Rights::new();
    let mut deciding = None;
    for (at, entry, compiled) in applicable {
        let fresh = &compiled.rights - &(&granted | &denied);
        match entry.effect {
            Effect::Allow => granted |= &fresh,
            Effect::Deny => denied |= &fresh,
        }
        if deciding.is_none() && !fresh.is_disjoint(wanted) {
            let refused = entry.effect == Effect::Deny;
            if refused || wanted.is_subset(&granted) {
                deciding = Some(*at);
            }
        }
    }
    Decision::from_sets(wanted, granted, denied, deciding)
}

/// Any applicable deny refuses its rights; the allows are unioned. The owner's standing
/// rights are not refused by a deny.
fn deny_overrides(applicable: &Applicable<'_>, owner: Rights, wanted: &Rights) -> Decision {
    let mut denied = Rights::new();
    for (_, entry, compiled) in applicable {
        if entry.effect == Effect::Deny {
            denied |= &compiled.rights;
        }
    }
    let first_deny = applicable.iter().find(|(_, entry, compiled)| {
        entry.effect == Effect::Deny && !compiled.rights.is_disjoint(wanted)
    });
    let mut granted = owner.clone();
    let mut deciding = first_deny.map(|(at, ..)| *at);
    for (at, entry, compiled) in applicable {
        if entry.effect == Effect::Allow {
            granted |= &(&compiled.rights - &denied);
            if deciding.is_none() && wanted.is_subset(&granted) && !wanted.is_subset(&owner) {
                deciding = Some(*at);
            }
        }
    }
    Decision::from_sets(wanted, granted, &denied - &owner, deciding)
}

/// The requester's class decides: owner, named user, groups (one entry must hold every
/// wanted right, capped by the mask), everyone. The mask applies whoever asks, so it is
/// found among all the entries, not the applicable ones.
fn posix(
    applicable: &Applicable<'_>,
    mask: Option<&Rights>,
    context: &Context<'_>,
    owner: Rights,
    wanted: &Rights,
) -> Decision {
    let capped = |rights: &Rights| match mask {
        Some(mask) => rights & mask,
        None => rights.clone(),
    };
    let of = |want: fn(&Principal) -> bool| {
        applicable
            .iter()
            .filter(move |(_, entry, _)| want(&entry.principal))
    };
    if context.is(&Principal::Owner) {
        let entry = of(|principal| *principal == Principal::Owner).next();
        let rights = entry.map_or_else(Rights::new, |(_, _, compiled)| compiled.rights.clone());
        return Decision::from_sets(wanted, &rights | &owner, Rights::new(), entry.map(|e| e.0));
    }
    let named_user = |principal: &Principal| {
        matches!(
            principal,
            Principal::Subject(Subject::Account(_) | Subject::Person(_))
        )
    };
    if let Some((at, _, compiled)) = of(named_user).next() {
        return Decision::from_sets(wanted, capped(&compiled.rights), Rights::new(), Some(*at));
    }
    let group = |principal: &Principal| {
        matches!(
            principal,
            Principal::OwnerGroup | Principal::Subject(Subject::Group(_))
        )
    };
    let groups: Vec<_> = of(group).collect();
    if !groups.is_empty() {
        let granted = groups.iter().fold(Rights::new(), |all, (_, _, compiled)| {
            &all | &capped(&compiled.rights)
        });
        let holding = groups
            .iter()
            .find(|(_, _, compiled)| wanted.is_subset(&capped(&compiled.rights)));
        let mut decision = Decision::from_sets(
            wanted,
            granted,
            Rights::new(),
            holding.or(groups.first()).map(|(at, ..)| *at),
        );
        decision.allowed = holding.is_some();
        return decision;
    }
    match of(|principal| *principal == Principal::Everyone).next() {
        Some((at, _, compiled)) => {
            Decision::from_sets(wanted, compiled.rights.clone(), Rights::new(), Some(*at))
        }
        None => Decision::nothing(wanted),
    }
}

/// What one level of a most-specific walk says.
pub(crate) struct Level {
    pub(crate) rights: Rights,
    pub(crate) cancel: Option<usize>,
    pub(crate) deciding: Option<usize>,
}

/// The entries of the requester's highest tier at one level, unioned: the subjects naming
/// the requester (and `Owner`) beat groups, `Everyone` and `Authenticated`. `None` when no
/// entry applies, so the level leaves what came from above.
pub(crate) fn level(applicable: &Applicable<'_>) -> Option<Level> {
    let personal = |entry: &Entry| {
        matches!(
            entry.principal,
            Principal::Owner | Principal::Subject(Subject::Account(_) | Subject::Person(_))
        )
    };
    let tier: Vec<_> = if applicable.iter().any(|(_, entry, _)| personal(entry)) {
        applicable
            .iter()
            .filter(|(_, entry, _)| personal(entry))
            .collect()
    } else {
        applicable.iter().collect()
    };
    let first = tier.first()?;
    Some(Level {
        rights: tier.iter().fold(Rights::new(), |all, (_, _, compiled)| {
            &all | &compiled.rights
        }),
        cancel: tier
            .iter()
            .find(|(_, _, compiled)| compiled.cancels)
            .map(|(at, ..)| *at),
        deciding: Some(first.0),
    })
}

impl<'a> Context<'a> {
    pub(crate) fn for_item<'b>(&self, item: &'b ItemAcl) -> Context<'b>
    where
        'a: 'b,
    {
        let context: Context<'b> = self.clone();
        context
            .owner(item.owner.as_ref())
            .owner_group(item.owner_group.as_ref())
    }
}
