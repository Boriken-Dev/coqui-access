//! Maps peer certificates, verified by the transport, to directory identities.
//!
//! The transport (see `coqui-peer-tls`) proves a peer holds the key of its certificate and
//! hands the certificate's fingerprint in [`Attempt::certificate`]. This provider keeps the
//! fingerprints that were accepted in a [`Table`], each under a name and groups. A
//! certificate nobody accepted is not authenticated and is kept for a while as waiting, in a
//! second table, so whoever runs the service can accept it. Build the provider in code with
//! [`Peers::builder`].
#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
#![warn(missing_docs)]

use std::collections::BTreeSet;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use coqui_access::guatiao::library::ProviderError;
use coqui_access::guatiao::{FromValue, Schema, ToValue};
use coqui_access::{
    AccountInfo, AccountPut, Accounts, Attempt, Authenticator, Description, Directory, Lookup,
    Person, PutOutcome, Verdict, Waiting, error, takes,
};
use coqui_access_kit::{Keyed, MemoryTable, Reloading, SourceError, Table, check_keys, secret};
use coqui_peer_tls::{Digest, PeerId};

/// The most peers a table may hold unless the builder says otherwise.
pub const DEFAULT_MAX_PEERS: usize = 10_000;
/// How many unaccepted fingerprints are kept unless the builder says otherwise: the last ones
/// seen.
pub const DEFAULT_WAITING_PLACES: usize = 16;
/// How long a waiting fingerprint is not written down again for, in seconds, unless the
/// builder says otherwise.
pub const DEFAULT_SEEN_EVERY_SECS: i64 = 60;
const MAX_FIELD_BYTES: usize = 1024;

/// One accepted peer as a [`Table`] keeps it, keyed by [`name`](PeerRecord::name).
///
/// It derives guatiao's `ToValue`, `FromValue` and `Schema`, so a [`Table`] may keep it in
/// any format.
#[derive(Clone, PartialEq, Eq, FromValue, Schema, ToValue)]
#[map(crate = ::coqui_access::guatiao, deny_unknown_fields)]
#[non_exhaustive]
pub struct PeerRecord {
    /// Stable identity; what a [`Verdict::Valid`] lookup names.
    pub id: String,
    /// The peer's name; unique in the table.
    pub name: String,
    /// The SHA-256 fingerprint of its certificate, in any spelling `coqui-peer-tls` reads.
    pub certificate: String,
    /// Email address.
    pub email: Option<String>,
    /// Directory groups.
    #[map(default, skip_serializing_if = Vec::is_empty)]
    pub groups: Vec<String>,
    /// A disabled peer is refused.
    #[map(default, skip_serializing_if = core::ops::Not::not)]
    pub disabled: bool,
    /// When it was accepted, in seconds since the Unix epoch.
    pub made_unix: Option<i64>,
}

impl PeerRecord {
    /// An enabled peer with no groups, accepted by this fingerprint.
    pub fn new(id: impl Into<String>, name: impl Into<String>, certificate: &PeerId) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            certificate: certificate.to_string(),
            email: None,
            groups: Vec::new(),
            disabled: false,
            made_unix: None,
        }
    }

    /// Sets the directory groups.
    #[must_use]
    pub fn groups(mut self, groups: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.groups = groups.into_iter().map(Into::into).collect();
        self
    }

    /// Sets the email address.
    #[must_use]
    pub fn email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
        self
    }

    /// Sets whether the peer is disabled.
    #[must_use]
    pub fn disabled(mut self, disabled: bool) -> Self {
        self.disabled = disabled;
        self
    }

    fn is(&self, fingerprint: &PeerId) -> bool {
        self.certificate
            .parse::<PeerId>()
            .is_ok_and(|own| own == *fingerprint)
    }
}

impl Keyed for PeerRecord {
    fn key(&self) -> &str {
        &self.name
    }
}

impl fmt::Debug for PeerRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PeerRecord")
            .field("id", &"[REDACTED]")
            .field("name", &"[REDACTED]")
            .field("certificate", &"[REDACTED]")
            .field("email", &self.email.as_ref().map(|_| "[REDACTED]"))
            .field("groups", &self.groups.len())
            .field("disabled", &self.disabled)
            .finish()
    }
}

/// A fingerprint shown to the service that nobody has accepted, keyed by
/// [`fingerprint`](Unaccepted::fingerprint).
///
/// It derives guatiao's `ToValue`, `FromValue` and `Schema`, so a [`Table`] may keep it in
/// any format.
#[derive(Debug, Clone, PartialEq, Eq, FromValue, Schema, ToValue)]
#[map(crate = ::coqui_access::guatiao, deny_unknown_fields)]
#[non_exhaustive]
pub struct Unaccepted {
    /// The canonical fingerprint.
    pub fingerprint: String,
    /// The address it was shown from, when known.
    pub peer: Option<String>,
    /// When it was last written down, in seconds since the Unix epoch.
    pub seen_unix: i64,
}

impl Unaccepted {
    /// A fingerprint seen at `seen_unix`, from `peer`.
    pub fn new(fingerprint: &PeerId, peer: Option<String>, seen_unix: i64) -> Self {
        Self {
            fingerprint: fingerprint.canonical(),
            peer,
            seen_unix,
        }
    }
}

impl Keyed for Unaccepted {
    fn key(&self) -> &str {
        &self.fingerprint
    }
}

/// Options for [`Peers`]; every one has a default.
pub struct PeersBuilder {
    table: Option<Arc<dyn Table<PeerRecord>>>,
    waiting: Option<Arc<dyn Table<Unaccepted>>>,
    max_peers: usize,
    waiting_places: usize,
    seen_every_secs: i64,
}

impl fmt::Debug for PeersBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PeersBuilder")
            .field("max_peers", &self.max_peers)
            .field("waiting_places", &self.waiting_places)
            .field("seen_every_secs", &self.seen_every_secs)
            .finish_non_exhaustive()
    }
}

impl PeersBuilder {
    /// Keeps the accepted peers in `table` instead of in memory.
    #[must_use]
    pub fn table(mut self, table: Arc<dyn Table<PeerRecord>>) -> Self {
        self.table = Some(table);
        self
    }

    /// Keeps the waiting fingerprints in `table` instead of in memory. A table that cannot be
    /// written means nobody waits.
    #[must_use]
    pub fn waiting(mut self, table: Arc<dyn Table<Unaccepted>>) -> Self {
        self.waiting = Some(table);
        self
    }

    /// The most peers the table may hold. Default [`DEFAULT_MAX_PEERS`].
    #[must_use]
    pub fn max_peers(mut self, max: usize) -> Self {
        self.max_peers = max;
        self
    }

    /// How many unaccepted fingerprints are kept. Default [`DEFAULT_WAITING_PLACES`].
    #[must_use]
    pub fn waiting_places(mut self, places: usize) -> Self {
        self.waiting_places = places;
        self
    }

    /// How long, in seconds, a waiting fingerprint from one address is not written down
    /// again. Default [`DEFAULT_SEEN_EVERY_SECS`].
    #[must_use]
    pub fn seen_every_secs(mut self, seconds: i64) -> Self {
        self.seen_every_secs = seconds;
        self
    }

    /// Loads the table and makes the provider.
    ///
    /// # Errors
    ///
    /// Returns an error when the table cannot be loaded or holds an invalid or duplicated
    /// peer.
    pub fn build(self) -> Result<Peers, SourceError> {
        let table = self
            .table
            .unwrap_or_else(|| Arc::new(MemoryTable::<PeerRecord>::new()));
        let max = self.max_peers;
        Ok(Peers {
            peers: Reloading::new(table, move |records| validate(records, max))?,
            waiting_table: self
                .waiting
                .unwrap_or_else(|| Arc::new(MemoryTable::<Unaccepted>::new())),
            waiting: Mutex::new(()),
            waiting_places: self.waiting_places,
            seen_every_secs: self.seen_every_secs,
        })
    }
}

/// Peers as an Authenticator, Directory and Accounts implementation.
///
/// The table is read again whenever it reports a change.
///
/// ```
/// use coqui_access::{Attempt, Authenticator, Verdict};
/// use coqui_access_peer::Peers;
///
/// let peers = Peers::builder().build().unwrap();
/// let seen = peers
///     .authenticate(Attempt {
///         certificate: Some(
///             "sha256:0000000000000000000000000000000000000000000000000000000000000000".into(),
///         ),
///         ..Attempt::default()
///     })
///     .unwrap();
/// // Nobody accepted it: not authenticated, and kept as waiting.
/// assert_eq!(seen, Verdict::Unknown);
/// ```
pub struct Peers {
    peers: Reloading<PeerRecord>,
    waiting_table: Arc<dyn Table<Unaccepted>>,
    /// Held while the waiting table is read and written.
    waiting: Mutex<()>,
    waiting_places: usize,
    seen_every_secs: i64,
}

impl fmt::Debug for Peers {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Peers")
            .field("waiting_places", &self.waiting_places)
            .field("seen_every_secs", &self.seen_every_secs)
            .finish_non_exhaustive()
    }
}

impl Peers {
    /// Options for a peer table, kept in memory unless [`table`](PeersBuilder::table) says
    /// otherwise.
    pub fn builder() -> PeersBuilder {
        PeersBuilder {
            table: None,
            waiting: None,
            max_peers: DEFAULT_MAX_PEERS,
            waiting_places: DEFAULT_WAITING_PLACES,
            seen_every_secs: DEFAULT_SEEN_EVERY_SECS,
        }
    }

    /// Keeps a fingerprint nobody accepted as waiting: the last few seen, one to an
    /// address, and not more often than once in a while. An address that shows another
    /// certificate takes its single place, so it cannot push everybody else out.
    fn wait(&self, fingerprint: &PeerId, from: Option<String>) {
        let _one = self.waiting.lock().unwrap_or_else(PoisonError::into_inner);
        let shown = fingerprint.canonical();
        let old = self.waits();
        let host = |peer: &Option<String>| peer.as_deref().and_then(host_of);
        let here = host(&from);
        let now = now();
        if old.iter().any(|had| {
            had.fingerprint == shown
                && host(&had.peer) == here
                && now - had.seen_unix < self.seen_every_secs
        }) {
            return;
        }
        let mut waits = old.clone();
        waits.retain(|had| had.fingerprint != shown && (here.is_none() || host(&had.peer) != here));
        waits.push(Unaccepted::new(fingerprint, from, now));
        let over = waits.len().saturating_sub(self.waiting_places);
        waits.drain(..over);
        self.keep_waits(&old, waits);
    }

    /// Peers that are accepted wait no more.
    fn waited(&self, accepted: &[PeerId]) {
        let _one = self.waiting.lock().unwrap_or_else(PoisonError::into_inner);
        let old = self.waits();
        let still: Vec<Unaccepted> = old
            .iter()
            .filter(|had| {
                had.fingerprint
                    .parse::<PeerId>()
                    .map_or(true, |own| !accepted.contains(&own))
            })
            .cloned()
            .collect();
        if still.len() < old.len() {
            self.keep_waits(&old, still);
        }
    }

    /// The waiting entries, oldest first. A table that cannot be read is nobody waiting.
    fn waits(&self) -> Vec<Unaccepted> {
        self.waiting_table
            .load()
            .map(|snapshot| snapshot.records)
            .unwrap_or_default()
    }

    /// Makes the waiting table hold `new`, in order, touching only what differs.
    fn keep_waits(&self, old: &[Unaccepted], new: Vec<Unaccepted>) {
        // Whether it could be written is not the peer's to be told.
        for had in old {
            if !new.contains(had) {
                let _ = self.waiting_table.remove(&had.fingerprint);
            }
        }
        for wait in new {
            if !old.contains(&wait) {
                let _ = self.waiting_table.put(wait);
            }
        }
    }
}

fn unreadable(reason: SourceError) -> ProviderError {
    error::internal(&format!("peer table: {reason}"))
}

fn refused(reason: SourceError) -> ProviderError {
    match reason {
        SourceError::ReadOnly => error::unsupported("the peer table is read only"),
        SourceError::Invalid(reason) => error::bad_value(&format!("peer table: {reason}")),
        other => unreadable(other),
    }
}

impl Authenticator for Peers {
    fn authenticate(&self, attempt: Attempt) -> Result<Verdict, ProviderError> {
        let Some(fingerprint) = attempt
            .certificate
            .as_deref()
            .and_then(|text| text.parse::<PeerId>().ok())
            .filter(|fingerprint| fingerprint.digest() == Digest::Sha256)
        else {
            return Ok(Verdict::Unknown);
        };
        let found = self
            .peers
            .read(|records| {
                records
                    .iter()
                    .find(|peer| peer.is(&fingerprint))
                    .map(|peer| (peer.id.clone(), peer.disabled))
            })
            .map_err(unreadable)?;
        Ok(match found {
            None => {
                self.wait(&fingerprint, attempt.peer);
                Verdict::Unknown
            }
            Some((_, true)) => Verdict::Invalid,
            Some((id, false)) => Verdict::Valid(Lookup {
                by: "id".to_owned(),
                value: id,
            }),
        })
    }

    fn describe(&self) -> Result<Description, ProviderError> {
        Ok(Description {
            name: Some("Verified peers".to_owned()),
            takes: Some(takes::REQUEST.to_owned()),
        })
    }
}

impl Directory for Peers {
    fn lookup(&self, lookup: Lookup) -> Result<Option<Person>, ProviderError> {
        let by_certificate = if lookup.by == "certificate" {
            lookup.value.parse::<PeerId>().ok()
        } else {
            None
        };
        self.peers
            .read(|records| {
                records
                    .iter()
                    .find(|peer| {
                        !peer.disabled
                            && match lookup.by.as_str() {
                                "id" => peer.id == lookup.value,
                                "name" => peer.name == lookup.value,
                                "certificate" => {
                                    by_certificate.as_ref().is_some_and(|own| peer.is(own))
                                }
                                "email" => peer.email.as_deref() == Some(&lookup.value),
                                _ => false,
                            }
                    })
                    .map(|peer| Person {
                        id: peer.id.clone(),
                        name: peer.name.clone(),
                        display_name: None,
                        email: peer.email.clone(),
                        groups: peer.groups.clone(),
                        attributes: Default::default(),
                    })
            })
            .map_err(unreadable)
    }
}

impl Accounts for Peers {
    fn accounts(&self) -> Result<Vec<AccountInfo>, ProviderError> {
        self.peers
            .read(|records| {
                records
                    .iter()
                    .map(|peer| AccountInfo {
                        id: peer.id.clone(),
                        name: peer.name.clone(),
                        groups: peer.groups.clone(),
                        disabled: Some(peer.disabled),
                        made_unix: peer.made_unix,
                        expires_unix: None,
                    })
                    .collect()
            })
            .map_err(unreadable)
    }

    /// Accepts a fingerprint under a name, or changes what is said of a peer there is. The
    /// secret of a peer is its certificate fingerprint in any spelling `coqui-peer-tls` reads;
    /// saying it again moves the account to another certificate.
    fn put(&self, account: AccountPut) -> Result<PutOutcome, ProviderError> {
        if !valid_field(&account.name) {
            return Err(error::bad_value("a peer has a name"));
        }
        if account.expires_unix.is_some() {
            return Err(error::bad_value("peers do not expire"));
        }
        let fingerprint = account
            .secret
            .as_deref()
            .map(str::parse::<PeerId>)
            .transpose()
            .map_err(|_| error::bad_value("that is not a certificate fingerprint"))?
            .filter(|fingerprint| fingerprint.digest() == Digest::Sha256);
        if account.secret.is_some() && fingerprint.is_none() {
            return Err(error::bad_value(
                "a peer is identified by a SHA-256 fingerprint",
            ));
        }
        let accepted = self
            .peers
            .put_with(|records| {
                if let Some(fingerprint) = &fingerprint
                    && records
                        .iter()
                        .any(|peer| peer.is(fingerprint) && peer.name != account.name)
                {
                    return Err(SourceError::invalid(
                        "that certificate belongs to another peer",
                    ));
                }
                let mut peer = match (
                    records.iter().find(|peer| peer.name == account.name),
                    &fingerprint,
                ) {
                    (Some(peer), _) => peer.clone(),
                    (None, Some(fingerprint)) => {
                        let mut peer = PeerRecord::new(
                            secret::identifier().map_err(SourceError::unavailable)?,
                            account.name.clone(),
                            fingerprint,
                        );
                        peer.made_unix = Some(now());
                        peer
                    }
                    (None, None) => {
                        return Err(SourceError::invalid(
                            "a new peer is accepted by its certificate fingerprint",
                        ));
                    }
                };
                if let Some(fingerprint) = &fingerprint {
                    peer.certificate = fingerprint.to_string();
                }
                if let Some(groups) = account.groups {
                    peer.groups = groups;
                }
                if let Some(disabled) = account.disabled {
                    peer.disabled = disabled;
                }
                let accepted = records
                    .iter()
                    .filter(|other| other.name != peer.name)
                    .chain(std::iter::once(&peer))
                    .filter_map(|other| other.certificate.parse::<PeerId>().ok())
                    .collect::<Vec<_>>();
                Ok((peer, accepted))
            })
            .map_err(refused)?;
        self.waited(&accepted);
        Ok(PutOutcome::default())
    }

    fn remove(&self, name: String) -> Result<(), ProviderError> {
        self.peers
            .remove(&name)
            .map_err(refused)
            .and_then(|removed| {
                removed
                    .then_some(())
                    .ok_or_else(|| error::not_found("there is no such peer"))
            })
    }

    fn waiting(&self) -> Result<Vec<Waiting>, ProviderError> {
        let _one = self.waiting.lock().unwrap_or_else(PoisonError::into_inner);
        Ok(self
            .waits()
            .into_iter()
            .rev()
            .map(|waits| Waiting {
                shown: waits.fingerprint,
                peer: waits.peer,
                seen_unix: Some(waits.seen_unix),
            })
            .collect())
    }
}

/// The address of `address:port`, whichever kind of address it is.
fn host_of(peer: &str) -> Option<IpAddr> {
    peer.parse::<SocketAddr>()
        .map(|socket| socket.ip())
        .ok()
        .or_else(|| peer.parse().ok())
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|since| i64::try_from(since.as_secs()).ok())
        .unwrap_or_default()
}

fn validate(peers: &[PeerRecord], max: usize) -> Result<(), SourceError> {
    check_keys(peers, max)?;
    let mut ids = BTreeSet::new();
    let mut certificates = BTreeSet::new();
    for peer in peers {
        let Ok(fingerprint) = peer.certificate.parse::<PeerId>() else {
            return Err(SourceError::invalid(
                "a peer entry has an invalid certificate",
            ));
        };
        if fingerprint.digest() != Digest::Sha256 {
            return Err(SourceError::invalid(
                "a peer certificate is identified by its SHA-256 fingerprint",
            ));
        }
        if !valid_field(&peer.id)
            || !valid_field(&peer.name)
            || !ids.insert(&peer.id)
            || !certificates.insert(fingerprint)
            || peer.groups.len() > 256
            || peer.groups.iter().any(|group| !valid_field(group))
            || peer
                .email
                .as_ref()
                .is_some_and(|email| email.is_empty() || email.len() > 320)
        {
            return Err(SourceError::invalid(
                "a peer entry is invalid or duplicated",
            ));
        }
    }
    Ok(())
}

fn valid_field(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_FIELD_BYTES && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use coqui_peer_tls::Identity;

    use super::*;

    fn attempt(certificate: Option<&str>) -> Attempt {
        Attempt {
            name: Some("ignored".to_owned()),
            secret: Some("ignored".to_owned()),
            secure: Some(true),
            certificate: certificate.map(str::to_owned),
            peer: Some("192.0.2.7:4000".to_owned()),
            ..Attempt::default()
        }
    }

    fn fingerprint() -> PeerId {
        Identity::generate().unwrap().fingerprint()
    }

    #[test]
    fn authenticates_only_known_certificates_and_resolves_groups() {
        let known = fingerprint();
        let certificate = known.to_string();
        let peers = Peers::builder()
            .table(Arc::new(MemoryTable::from_records([PeerRecord::new(
                "service-1",
                "site-a",
                &known,
            )
            .groups(["site-a"])])))
            .build()
            .unwrap();
        let Verdict::Valid(lookup) = peers.authenticate(attempt(Some(&certificate))).unwrap()
        else {
            panic!("known certificate was rejected");
        };
        let person = peers.lookup(lookup).unwrap().unwrap();
        assert_eq!(person.id, "service-1");
        assert_eq!(person.groups, vec!["site-a"]);
        // Any spelling of the fingerprint is the same certificate.
        let hex = known.canonical();
        assert!(matches!(
            peers.authenticate(attempt(Some(&hex))).unwrap(),
            Verdict::Valid(_)
        ));
        assert_eq!(peers.authenticate(attempt(None)).unwrap(), Verdict::Unknown);
        assert_eq!(
            peers
                .authenticate(attempt(Some("not-a-fingerprint")))
                .unwrap(),
            Verdict::Unknown
        );
        assert!(!format!("{peers:?}").contains(&certificate));
    }

    #[test]
    fn disabled_peers_and_malformed_tables_are_refused() {
        let known = fingerprint();
        let certificate = known.to_string();
        let build = |records: Vec<PeerRecord>| {
            Peers::builder()
                .table(Arc::new(MemoryTable::from_records(records)))
                .build()
        };
        let peers = build(vec![
            PeerRecord::new("service-1", "site-a", &known).disabled(true),
        ])
        .unwrap();
        assert_eq!(
            peers.authenticate(attempt(Some(&certificate))).unwrap(),
            Verdict::Invalid
        );
        assert!(
            peers
                .lookup(Lookup {
                    by: "id".to_owned(),
                    value: "service-1".to_owned()
                })
                .unwrap()
                .is_none()
        );
        let mut bad = PeerRecord::new("service-1", "site-a", &known);
        bad.certificate = "bad".to_owned();
        assert!(build(vec![bad]).is_err());
        let twice = vec![
            PeerRecord::new("1", "a", &known),
            PeerRecord::new("2", "b", &known),
        ];
        assert!(build(twice).is_err(), "one certificate is one peer");
    }

    #[test]
    fn an_unknown_certificate_waits_and_is_accepted_by_putting_it() {
        let peers = Peers::builder().build().unwrap();
        let fingerprint = fingerprint();
        let shown = fingerprint.to_string();
        assert_eq!(
            peers.authenticate(attempt(Some(&shown))).unwrap(),
            Verdict::Unknown
        );
        // Asking again from the same address does not write it again.
        peers.authenticate(attempt(Some(&shown))).unwrap();
        let waiting = peers.waiting().unwrap();
        assert_eq!(waiting.len(), 1);
        assert_eq!(waiting[0].shown, fingerprint.canonical());
        assert_eq!(waiting[0].peer.as_deref(), Some("192.0.2.7:4000"));

        peers
            .put(AccountPut {
                name: "site-b".to_owned(),
                secret: Some(waiting[0].shown.clone()),
                groups: Some(vec!["site-b".to_owned()]),
                ..AccountPut::default()
            })
            .unwrap();
        assert!(peers.waiting().unwrap().is_empty());
        assert!(matches!(
            peers.authenticate(attempt(Some(&shown))).unwrap(),
            Verdict::Valid(_)
        ));
        assert_eq!(peers.accounts().unwrap()[0].name, "site-b");
        // The same certificate cannot be two peers; a new peer needs a certificate.
        assert!(
            peers
                .put(AccountPut {
                    name: "site-c".to_owned(),
                    secret: Some(shown),
                    ..AccountPut::default()
                })
                .is_err()
        );
        assert!(
            peers
                .put(AccountPut {
                    name: "site-c".to_owned(),
                    ..AccountPut::default()
                })
                .is_err()
        );
        peers.remove("site-b".to_owned()).unwrap();
        assert!(peers.remove("site-b".to_owned()).is_err());
    }

    #[test]
    fn one_address_holds_one_waiting_place() {
        let peers = Peers::builder().build().unwrap();
        for _ in 0..3 {
            let shown = fingerprint().to_string();
            peers.authenticate(attempt(Some(&shown))).unwrap();
        }
        assert_eq!(peers.waiting().unwrap().len(), 1);
    }

    #[test]
    fn the_waiting_places_and_the_waiting_table_are_the_callers() {
        let waiting = Arc::new(MemoryTable::<Unaccepted>::new());
        let peers = Peers::builder()
            .waiting(waiting.clone())
            .waiting_places(2)
            .build()
            .unwrap();
        for last in 1..=3 {
            let from = Attempt {
                peer: Some(format!("192.0.2.{last}:4000")),
                certificate: Some(fingerprint().to_string()),
                ..Attempt::default()
            };
            peers.authenticate(from).unwrap();
        }
        let kept = waiting.load().unwrap().records;
        assert_eq!(kept.len(), 2);
        assert_eq!(kept[0].peer.as_deref(), Some("192.0.2.2:4000"));
        assert_eq!(peers.waiting().unwrap().len(), 2);
    }

    #[test]
    fn a_waiting_table_that_cannot_be_written_means_nobody_waits() {
        struct Fixed;
        impl Table<Unaccepted> for Fixed {
            fn load(&self) -> Result<coqui_access_kit::Snapshot<Unaccepted>, SourceError> {
                Ok(coqui_access_kit::Snapshot::new(
                    coqui_access_kit::Revision::default(),
                    Vec::new(),
                ))
            }
        }
        let peers = Peers::builder().waiting(Arc::new(Fixed)).build().unwrap();
        assert_eq!(
            peers
                .authenticate(attempt(Some(&fingerprint().to_string())))
                .unwrap(),
            Verdict::Unknown
        );
        assert!(peers.waiting().unwrap().is_empty());
    }
}
