//! Why a schema, an ACL or a walk could not be used.

use core::fmt;

use coqui_access::guatiao::library::ProviderError;

/// Why a schema, an ACL or a walk could not be used. Messages give positions, never the
/// names or values involved.
#[derive(Debug)]
#[non_exhaustive]
pub enum AclError {
    /// A right or alias name is empty or holds a control character.
    InvalidName,
    /// A schema defines a name twice.
    DuplicateName,
    /// A name the schema does not define: in entry `entry` (or in a list given directly,
    /// `None`), at position `at` of its names.
    UnknownRight {
        /// The entry that names it, when the names came from an entry.
        entry: Option<usize>,
        /// The position among the names.
        at: usize,
    },
    /// A schema defines more rights than [`Limits::rights`](crate::Limits::rights).
    TooManyRights,
    /// An ACL holds more entries than [`Limits::entries`](crate::Limits::entries).
    TooManyEntries,
    /// Entry `entry` is a deny in a mode that has none (`Additive`, `Posix`,
    /// `MostSpecific`).
    DenyNotAllowed {
        /// The entry.
        entry: usize,
    },
    /// Entry `entry` names a principal its mode does not take: `Mask` outside `Posix` or
    /// twice, `Authenticated` in `Posix`.
    PrincipalNotAllowed {
        /// The entry.
        entry: usize,
    },
    /// A walk met an ACL that is not in `MostSpecific` mode.
    ModeMismatch,
    /// A walk went past [`Limits::depth`](crate::Limits::depth) levels.
    TooDeep,
    /// An item is its own ancestor.
    Cycle,
    /// The store could not answer: "could not find out", never a denial.
    Store(ProviderError),
}

impl fmt::Display for AclError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidName => formatter.write_str("a right name is empty or not printable"),
            Self::DuplicateName => formatter.write_str("a right name is defined twice"),
            Self::UnknownRight {
                entry: Some(entry),
                at,
            } => {
                write!(formatter, "entry {entry} names an unknown right at {at}")
            }
            Self::UnknownRight { entry: None, at } => {
                write!(formatter, "unknown right at position {at}")
            }
            Self::TooManyRights => formatter.write_str("the schema defines too many rights"),
            Self::TooManyEntries => formatter.write_str("the acl holds too many entries"),
            Self::DenyNotAllowed { entry } => {
                write!(formatter, "entry {entry} denies in a mode without denies")
            }
            Self::PrincipalNotAllowed { entry } => {
                write!(
                    formatter,
                    "entry {entry} names a principal its mode does not take"
                )
            }
            Self::ModeMismatch => formatter.write_str("a walked acl is not in most-specific mode"),
            Self::TooDeep => formatter.write_str("the item is nested too deep"),
            Self::Cycle => formatter.write_str("the item is its own ancestor"),
            Self::Store(_) => formatter.write_str("the acl store could not answer"),
        }
    }
}

impl core::error::Error for AclError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ProviderError> for AclError {
    fn from(error: ProviderError) -> Self {
        Self::Store(error)
    }
}
