//! Conditions on entries, decided by the consumer.

use coqui_access::Person;

/// What a condition comes to for one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Truth {
    /// It holds: the entry applies.
    True,
    /// It does not: the entry does not apply.
    False,
    /// It cannot be told: an allow entry is skipped and a deny entry applies, as Windows
    /// treats conditional ACEs.
    Unknown,
}

/// Decides an entry's [`condition`](crate::Entry::condition), in whatever language the
/// consumer writes them in: a NetBox-style constraint checked against its database, a
/// Windows conditional expression, a time window.
///
/// With no `Conditions` given, or nobody signed in, every condition is [`Truth::Unknown`].
pub trait Conditions: Send + Sync {
    /// What `condition`, on an entry of `item`'s ACL, comes to for `person`.
    fn holds(&self, condition: &str, item: &str, person: &Person) -> Truth;
}
