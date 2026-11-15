//! Where the pins of an account are kept: the contract a matcher asks, and the two sources
//! that ship (a per-user file in `authorized`, and any [`Table`](crate::Table) of pins).
//!
//! A pin is what one account has said it is known by: the SHA-256 of a whole certificate (a
//! *fingerprint*) or of its public key (a *key*). The library never decides where pins live;
//! a consumer gives the [`Matcher`](crate::matcher::Matcher) a [`PinSource`] by name.

use coqui_access::guatiao::library::ProviderError;
use coqui_access::{Claims, Person};

/// The pins of the certificate a person presented: what a [`PinSource`] looks for. Each is
/// `sha256:<hex>`, lowercase.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PinSet {
    /// The SHA-256 of the whole certificate.
    pub fingerprint: Option<String>,
    /// The SHA-256 of its `SubjectPublicKeyInfo`.
    pub key: Option<String>,
}

impl PinSet {
    /// The pins the claims `fingerprint` and `spki` carry.
    pub fn from_claims(claims: &Claims) -> Self {
        let pick = |name: &str| {
            claims
                .get(name)
                .first()
                .map(|value| value.to_ascii_lowercase())
        };
        Self {
            fingerprint: pick("fingerprint"),
            key: pick("spki"),
        }
    }

    /// Whether there is nothing to look for.
    pub fn is_empty(&self) -> bool {
        self.fingerprint.is_none() && self.key.is_none()
    }
}

/// What a source found for one account.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PinCheck {
    /// The account holds one of the pins.
    Holds,
    /// The source was read and the account holds none of them.
    Absent,
    /// The source cannot be trusted for this account (a file with the wrong permissions, a
    /// home that is not known): counted as no pins, and the reason is reported. The reason
    /// never holds a pin.
    Refused(String),
}

/// A place pins are kept, asked about one account at a time.
///
/// `check` is called only for an account a rule already named, never to scan: a source
/// answers for `person` alone. `Err` is "could not find out" and ends the match with an
/// error; a source that can read what it needs but must not use it answers
/// [`PinCheck::Refused`].
pub trait PinSource: Send + Sync {
    /// Whether `person` holds one of `pins`.
    fn check(&self, person: &Person, pins: &PinSet) -> Result<PinCheck, ProviderError>;
}
