//! Copied inheritance: what a new item takes from its container, as Windows and NFSv4 do.

use alloc::vec::Vec;

use coqui_access::Subject;

use crate::entry::{Acl, Entry, Inherit};
use crate::principal::Principal;

/// What is made inside a container: a leaf, or a container of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Child {
    /// A leaf: a file, a document.
    Item,
    /// Something that holds items: a directory, a folder.
    Container,
}

impl Acl {
    /// The ACL a child of an item with this ACL gets: `explicit`'s own entries first, then
    /// the copies this ACL passes down, marked `inherited`, in `explicit`'s mode. A
    /// `protected` `explicit` takes nothing and comes back as it is; entries `explicit`
    /// had inherited before are replaced.
    ///
    /// The copies follow Windows' table (`items` is OI, `containers` CI):
    ///
    /// | parent entry | to an item | to a container |
    /// | --- | --- | --- |
    /// | `items` | applies, no flags | inherit-only, keeps `items` |
    /// | `containers` | nothing | applies, keeps `containers` |
    /// | both | applies, no flags | applies, keeps both |
    /// | with `no_propagate` | applies, no flags (if `items`) | applies with no flags (if `containers`), else nothing |
    ///
    /// A parent entry that is `inherit_only` is copied the same way; the copy applies.
    /// With a `creator`, an `Owner` entry (Windows CREATOR OWNER) is copied as an entry for
    /// the creator, and a container also keeps an inherit-only `Owner` entry to pass on.
    /// Nothing is walked at check time: store the result.
    pub fn inherited_by(&self, child: Child, explicit: &Acl, creator: Option<&Subject>) -> Acl {
        if explicit.protected {
            return explicit.clone();
        }
        let mut entries: Vec<Entry> = explicit
            .entries
            .iter()
            .filter(|entry| !entry.inherited)
            .cloned()
            .collect();
        for entry in &self.entries {
            let Some(flags) = passed(entry.inherit, child) else {
                continue;
            };
            let copy = |principal: Principal, inherit: Inherit| Entry {
                principal,
                inherit,
                inherited: true,
                ..entry.clone()
            };
            match (&entry.principal, creator) {
                (Principal::Owner, Some(creator)) => {
                    if !flags.inherit_only {
                        entries.push(copy(creator.clone().into(), Inherit::default()));
                    }
                    if flags.passes() {
                        entries.push(copy(Principal::Owner, flags.inherit_only()));
                    }
                }
                (principal, _) => entries.push(copy(principal.clone(), flags)),
            }
        }
        Acl {
            entries,
            protected: false,
            mode: explicit.mode,
        }
    }
}

/// The flags of the copy `child` gets of an entry with `inherit`, or `None` for no copy.
fn passed(inherit: Inherit, child: Child) -> Option<Inherit> {
    match child {
        Child::Item => inherit.items.then(Inherit::default),
        Child::Container if inherit.no_propagate => inherit.containers.then(Inherit::default),
        Child::Container if inherit.containers => Some(Inherit::new(inherit.items, true)),
        Child::Container if inherit.items => Some(Inherit::new(true, false).inherit_only()),
        Child::Container => None,
    }
}
