//! Walked inheritance: items in a tree, decided from the root down, as Proxmox does.

use alloc::collections::BTreeSet;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use coqui_access::guatiao::library::ProviderError;

use crate::check::{Context, Decision, Level, level};
use crate::entry::{Entry, ItemAcl, Mode};
use crate::error::AclError;
use crate::options::OnMissing;
use crate::rights::Rights;

/// Where items' ACLs and their places in a tree are kept: the consumer's storage.
///
/// An item with its own ACL in a mode other than `MostSpecific` is decided by that ACL
/// alone (inheritance was copied when it was made). Otherwise the item's ancestors are
/// walked: every ACL met must be `MostSpecific`, and an item with no ACL and no ACL above
/// it gets [`Options::on_missing`](crate::Options::on_missing).
pub trait AclStore {
    /// The ACL of `item`; `None` when it has none of its own.
    ///
    /// # Errors
    ///
    /// The store could not answer.
    fn acl(&self, item: &str) -> Result<Option<ItemAcl>, ProviderError>;

    /// The item `item` is inside; `None` at the root.
    ///
    /// # Errors
    ///
    /// The store could not answer.
    fn parent(&self, item: &str) -> Result<Option<String>, ProviderError>;

    /// Whether the requester in `context` holds `wanted` on `item`, its ACL or its
    /// ancestors' deciding. `context`'s owner is taken from each ACL met, and its item is
    /// set to `item`.
    ///
    /// The walk (Proxmox's): from the root down, a level's entries apply when they are at
    /// the item itself (not `inherit_only`) or pass to `containers`; the requester's own
    /// entries (`account:`, `person:`, `Owner`) beat the rest at that level, whose rights
    /// are unioned; a level where something applies replaces what came from above. A
    /// cancelling name refuses everything if its level is the one in force.
    ///
    /// # Errors
    ///
    /// [`AclError::Store`] when the store cannot answer, never a denial;
    /// [`AclError::Cycle`] when an item is its own ancestor, whatever the limits;
    /// [`AclError::TooDeep`] past [`Limits::depth`](crate::Limits::depth) levels;
    /// [`AclError::ModeMismatch`] for an ACL in another mode met on a walk; what
    /// [`Acl::check`](crate::Acl::check) refuses.
    fn check(
        &self,
        item: &str,
        context: &Context<'_>,
        wanted: &Rights,
    ) -> Result<Decision, AclError> {
        check_item(self, item, context, wanted)
    }
}

fn check_item<S: AclStore + ?Sized>(
    store: &S,
    item: &str,
    context: &Context<'_>,
    wanted: &Rights,
) -> Result<Decision, AclError> {
    let context = context.clone().item(item);
    let own = store.acl(item)?;
    if let Some(own) = &own
        && own.acl.mode != Mode::MostSpecific
    {
        return own.check(&context, wanted);
    }
    let limit = context.options.limits.depth;
    let mut chain = Vec::from([(item.to_string(), own)]);
    let mut seen = BTreeSet::from([item.to_string()]);
    while let Some(parent) = store.parent(&chain[chain.len() - 1].0)? {
        if !seen.insert(parent.clone()) {
            return Err(AclError::Cycle);
        }
        if limit.is_some_and(|max| chain.len() >= max) {
            return Err(AclError::TooDeep);
        }
        let acl = store.acl(&parent)?;
        chain.push((parent, acl));
    }
    if chain.iter().all(|(_, acl)| acl.is_none()) {
        return Ok(match context.options.on_missing {
            OnMissing::Deny => Decision::nothing(wanted),
            OnMissing::AllowAll => {
                Decision::from_sets(wanted, &context.schema.all() | wanted, Rights::new(), None)
            }
        });
    }
    let mut in_force: Option<Level> = None;
    for (depth, (_, acl)) in chain.iter().enumerate().rev() {
        let Some(acl) = acl else { continue };
        if acl.acl.mode != Mode::MostSpecific {
            return Err(AclError::ModeMismatch);
        }
        let compiled = acl.acl.compile(context.schema, &context.options)?;
        let here = context.for_item(acl);
        let at_item = depth == 0;
        let applicable: Vec<_> = acl
            .acl
            .entries
            .iter()
            .zip(&compiled)
            .enumerate()
            .filter(|(_, (entry, _))| applies_at(entry, at_item) && here.applies(entry))
            .map(|(at, (entry, compiled))| (at, entry, compiled))
            .collect();
        if let Some(found) = level(&applicable) {
            in_force = Some(found);
        }
    }
    let item_acl = chain[0].1.as_ref();
    let owner = item_acl.map_or_else(Rights::new, |acl| {
        context.for_item(acl).owner_grant(&acl.acl)
    });
    Ok(match in_force {
        Some(Level {
            cancel: Some(at), ..
        }) => Decision::cancelled(context.schema, wanted, at),
        Some(found) => Decision::from_sets(
            wanted,
            &found.rights | &owner,
            Rights::new(),
            found.deciding,
        ),
        None => Decision::from_sets(wanted, owner, Rights::new(), None),
    })
}

/// Whether an entry counts at its own item (`at_item`) or below it.
fn applies_at(entry: &Entry, at_item: bool) -> bool {
    if at_item {
        !entry.inherit.inherit_only
    } else {
        entry.inherit.containers
    }
}
