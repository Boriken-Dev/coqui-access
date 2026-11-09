//! Bounds and choices an evaluation runs with, and the non-default settings they amount to.

use alloc::vec::Vec;

/// Bounds on work and memory. Each is `Some(n)` by default and `None` lifts it; none is a
/// security property.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Limits {
    /// The most entries one ACL may hold. Default 1 024.
    pub entries: Option<usize>,
    /// The most rights (bits) a schema may define. Default 1 024.
    pub rights: Option<usize>,
    /// The most levels a walk goes through, the item included. Default 64.
    pub depth: Option<usize>,
}

impl Limits {
    /// The default entries bound.
    pub const DEFAULT_ENTRIES: usize = 1_024;
    /// The default rights bound.
    pub const DEFAULT_RIGHTS: usize = 1_024;
    /// The default depth bound.
    pub const DEFAULT_DEPTH: usize = 64;

    /// No bound at all.
    pub const fn unbounded() -> Self {
        Self {
            entries: None,
            rights: None,
            depth: None,
        }
    }

    /// Sets [`entries`](Limits::entries).
    #[must_use]
    pub const fn entries(mut self, max: Option<usize>) -> Self {
        self.entries = max;
        self
    }

    /// Sets [`rights`](Limits::rights).
    #[must_use]
    pub const fn rights(mut self, max: Option<usize>) -> Self {
        self.rights = max;
        self
    }

    /// Sets [`depth`](Limits::depth).
    #[must_use]
    pub const fn depth(mut self, max: Option<usize>) -> Self {
        self.depth = max;
        self
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            entries: Some(Self::DEFAULT_ENTRIES),
            rights: Some(Self::DEFAULT_RIGHTS),
            depth: Some(Self::DEFAULT_DEPTH),
        }
    }
}

/// What an item with no ACL at all gets.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OnMissing {
    /// Nothing. The default.
    #[default]
    Deny,
    /// Every right, as a Windows NULL DACL grants. A non-default setting ([`NonDefault::MissingAllowsAll`]).
    AllowAll,
}

/// The choices one evaluation runs with.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Options {
    /// The bounds.
    pub limits: Limits,
    /// What an item with no ACL gets. Default [`OnMissing::Deny`].
    pub on_missing: OnMissing,
}

impl Options {
    /// The defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the bounds.
    #[must_use]
    pub fn limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Sets what an item with no ACL gets.
    #[must_use]
    pub fn on_missing(mut self, on_missing: OnMissing) -> Self {
        self.on_missing = on_missing;
        self
    }

    /// What these choices set off the default, for the caller to report or refuse.
    pub fn non_defaults(&self) -> Vec<NonDefault> {
        match self.on_missing {
            OnMissing::AllowAll => alloc::vec![NonDefault::MissingAllowsAll],
            OnMissing::Deny => Vec::new(),
        }
    }
}

/// A choice that grants more than the default does, reported as data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NonDefault {
    /// [`OnMissing::AllowAll`]: an item with no ACL grants every right.
    MissingAllowsAll,
    /// The entry at this index allows something to `Everyone`, signed in or not.
    EveryoneAllowed {
        /// The entry.
        entry: usize,
    },
}

