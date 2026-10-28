//! Who an entry applies to.

use core::fmt;
use core::str::FromStr;

use coqui_access::{Person, Subject};

/// Who an entry applies to, written as text in an entry: a [`Subject`] (`account:<name>`,
/// `person:<id>`, `group:<name>`), or `everyone`, `authenticated`, `owner`, `owner_group`,
/// `mask`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Principal {
    /// One account, person or group.
    Subject(Subject),
    /// Anyone, signed in or not (Windows Everyone, NFSv4 `everyone@`, POSIX other).
    Everyone,
    /// Anyone signed in.
    Authenticated,
    /// The item's owner (Windows CREATOR OWNER and OWNER RIGHTS, NFSv4 `owner@`, POSIX
    /// user object).
    Owner,
    /// Members of the item's owning group (NFSv4 `group@`, POSIX group object).
    OwnerGroup,
    /// The POSIX mask, which caps named users and groups; only in `Posix` mode.
    Mask,
}

impl Principal {
    /// Whether `person` (`None` when nobody signed in) is this principal, given the item's
    /// owner and owning group.
    pub fn matches(
        &self,
        person: Option<&Person>,
        owner: Option<&Subject>,
        owner_group: Option<&Subject>,
    ) -> bool {
        match self {
            Self::Everyone => true,
            Self::Mask => false,
            Self::Authenticated => person.is_some(),
            Self::Subject(subject) => person.is_some_and(|person| subject.matches(person)),
            Self::Owner => matches_one(owner, person),
            Self::OwnerGroup => matches_one(owner_group, person),
        }
    }
}

fn matches_one(subject: Option<&Subject>, person: Option<&Person>) -> bool {
    subject
        .zip(person)
        .is_some_and(|(subject, person)| subject.matches(person))
}

impl From<Subject> for Principal {
    fn from(subject: Subject) -> Self {
        Self::Subject(subject)
    }
}

impl fmt::Display for Principal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Subject(subject) => fmt::Display::fmt(subject, formatter),
            Self::Everyone => formatter.write_str("everyone"),
            Self::Authenticated => formatter.write_str("authenticated"),
            Self::Owner => formatter.write_str("owner"),
            Self::OwnerGroup => formatter.write_str("owner_group"),
            Self::Mask => formatter.write_str("mask"),
        }
    }
}

/// Text that names no principal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct PrincipalError;

impl fmt::Display for PrincipalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "a principal is everyone, authenticated, owner, owner_group, mask or a subject",
        )
    }
}

impl core::error::Error for PrincipalError {}

impl FromStr for Principal {
    type Err = PrincipalError;

    fn from_str(text: &str) -> Result<Self, PrincipalError> {
        Ok(match text {
            "everyone" => Self::Everyone,
            "authenticated" => Self::Authenticated,
            "owner" => Self::Owner,
            "owner_group" => Self::OwnerGroup,
            "mask" => Self::Mask,
            _ => Self::Subject(text.parse().map_err(|_| PrincipalError)?),
        })
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    #[test]
    fn every_principal_reads_back_its_own_text() {
        for text in [
            "everyone",
            "authenticated",
            "owner",
            "owner_group",
            "mask",
            "group:staff",
            "account:alice",
            "person:p-1",
        ] {
            assert_eq!(text.parse::<Principal>().unwrap().to_string(), text);
        }
        assert!("nobody".parse::<Principal>().is_err());
    }

    #[test]
    fn owners_match_through_the_item_and_anonymous_only_matches_everyone() {
        let alice = Person {
            name: "alice".into(),
            groups: alloc::vec!["staff".into()],
            ..Person::default()
        };
        let owner: Subject = "account:alice".parse().unwrap();
        let group: Subject = "group:staff".parse().unwrap();
        assert!(Principal::Owner.matches(Some(&alice), Some(&owner), None));
        assert!(!Principal::Owner.matches(Some(&alice), None, None));
        assert!(Principal::OwnerGroup.matches(Some(&alice), None, Some(&group)));
        assert!(Principal::Everyone.matches(None, None, None));
        assert!(!Principal::Authenticated.matches(None, None, None));
        assert!(!Principal::Owner.matches(None, Some(&owner), None));
        assert!(!Principal::Mask.matches(Some(&alice), None, None));
    }
}
