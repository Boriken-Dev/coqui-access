//! Maps peer certificates, verified by the transport, to directory identities.
//!
//! The transport (see `coqui-peer`) proves a peer holds the key of its certificate and
//! hands the certificate's fingerprint in [`Attempt::certificate`]. This provider keeps the
//! fingerprints that were accepted, each under a name and groups. A certificate nobody
//! accepted is not authenticated and is kept for a while as waiting, so whoever runs the
//! service can accept it.
#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
#![warn(missing_docs)]

use std::collections::BTreeSet;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use coqui_access::guatiao::library::ProviderError;
use coqui_access::guatiao::{FromValue, Provider, Schema, ToValue};
use coqui_access::{
    AccountInfo, AccountPut, Accounts, Attempt, Authenticator, Description, Directory, Lookup,
    Person, PutOutcome, Verdict, Waiting, error, takes,
};
use coqui_access_kit::{Store, file, secret};
use coqui_peer::{Digest, Fingerprint};
use serde::{Deserialize, Serialize};

const MAX_PEERS: usize = 10_000;
const MAX_FIELD_BYTES: usize = 1024;
/// How many unaccepted fingerprints are kept: the last ones seen.
const WAITING: usize = 16;
/// How long a waiting fingerprint is not written down again for, in seconds.
const SEEN_EVERY: i64 = 60;
const MAX_WAITING_BYTES: usize = 64 * 1024;

/// Guatiao configuration for the verified peer table.
#[derive(Debug, Clone, FromValue, Schema, ToValue)]
#[map(crate = ::coqui_access::guatiao)]
#[non_exhaustive]
pub struct PeersConfig {
    /// TOML file mapping certificate fingerprints to directory people. Fingerprints that
    /// wait are kept beside it in `<path>.waiting`.
    pub path: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    #[serde(default)]
    peers: Vec<PeerRecord>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerRecord {
    id: String,
    name: String,
    certificate: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    groups: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    disabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    made_unix: Option<i64>,
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

impl PeerRecord {
    fn is(&self, fingerprint: &Fingerprint) -> bool {
        self.certificate
            .parse::<Fingerprint>()
            .is_ok_and(|own| own == *fingerprint)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Waits {
    #[serde(default)]
    waiting: Vec<Unaccepted>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Unaccepted {
    fingerprint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    peer: Option<String>,
    seen_unix: i64,
}

/// Peers as an Authenticator, Directory and Accounts provider.
///
/// The file is read again whenever another process writes it.
#[derive(Debug, Provider)]
#[provider(
    Authenticator,
    Directory,
    Accounts,
    id = "coqui_access_peer",
    name = "Verified peers",
    config = PeersConfig,
    crate = ::coqui_access::guatiao
)]
pub struct Peers {
    store: Store<Document>,
    waiting_path: PathBuf,
    /// Held while the waiting file is read and written.
    waiting: Mutex<()>,
}

impl Peers {
    /// Opens the peer table; a missing file means no peers are configured.
    ///
    /// # Errors
    ///
    /// Returns an error when the file is unreadable, malformed or out of bounds.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref();
        let mut waiting_path = path.as_os_str().to_owned();
        waiting_path.push(".waiting");
        Ok(Self {
            store: Store::open(path, validate)?,
            waiting_path: PathBuf::from(waiting_path),
            waiting: Mutex::new(()),
        })
    }

    /// Keeps a fingerprint nobody accepted as waiting: the last few seen, one to an
    /// address, and not more often than once in a while. An address that shows another
    /// certificate takes its single place, so it cannot push everybody else out.
    fn wait(&self, fingerprint: &Fingerprint, from: Option<String>) {
        let _one = self.waiting.lock().unwrap_or_else(PoisonError::into_inner);
        let shown = fingerprint.canonical();
        let mut waits = self.waits();
        let host = |peer: &Option<String>| peer.as_deref().and_then(host_of);
        let here = host(&from);
        let now = now();
        if waits.iter().any(|had| {
            had.fingerprint == shown && host(&had.peer) == here && now - had.seen_unix < SEEN_EVERY
        }) {
            return;
        }
        waits.retain(|had| had.fingerprint != shown && (here.is_none() || host(&had.peer) != here));
        waits.push(Unaccepted {
            fingerprint: shown,
            peer: from,
            seen_unix: now,
        });
        let over = waits.len().saturating_sub(WAITING);
        waits.drain(..over);
        self.keep_waits(waits);
    }

    /// Fingerprints that are accepted wait no more.
    fn waited(&self, accepted: &[Fingerprint]) {
        let _one = self.waiting.lock().unwrap_or_else(PoisonError::into_inner);
        let waits = self.waits();
        let still: Vec<Unaccepted> = waits
            .iter()
            .filter(|had| {
                had.fingerprint
                    .parse::<Fingerprint>()
                    .map_or(true, |own| !accepted.contains(&own))
            })
            .cloned()
            .collect();
        if still.len() < waits.len() {
            self.keep_waits(still);
        }
    }

    /// The waiting entries, oldest first. A file that cannot be read is nobody waiting.
    fn waits(&self) -> Vec<Unaccepted> {
        file::read_bounded(&self.waiting_path, MAX_WAITING_BYTES)
            .ok()
            .flatten()
            .and_then(|text| toml::from_str::<Waits>(&text).ok())
            .map(|waits| waits.waiting)
            .unwrap_or_default()
    }

    fn keep_waits(&self, waiting: Vec<Unaccepted>) {
        // Whether it could be written is not the peer's to be told.
        if let Ok(text) = toml::to_string(&Waits { waiting }) {
            let _ = file::write_private(&self.waiting_path, text.as_bytes());
        }
    }
}

impl TryFrom<PeersConfig> for Peers {
    type Error = ProviderError;

    fn try_from(config: PeersConfig) -> Result<Self, Self::Error> {
        if config.path.trim().is_empty() {
            return Err(error::bad_value("path must name the peer table"));
        }
        Self::open(config.path).map_err(|reason| error::bad_value(&format!("peer table: {reason}")))
    }
}

fn unreadable(reason: String) -> ProviderError {
    error::internal(&format!("peer table: {reason}"))
}

impl Authenticator for Peers {
    fn authenticate(&self, attempt: Attempt) -> Result<Verdict, ProviderError> {
        let Some(fingerprint) = attempt
            .certificate
            .as_deref()
            .and_then(|text| text.parse::<Fingerprint>().ok())
            .filter(|fingerprint| fingerprint.digest() == Digest::Sha256)
        else {
            return Ok(Verdict::Unknown);
        };
        let found = self
            .store
            .read(|document| {
                document
                    .peers
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
            lookup.value.parse::<Fingerprint>().ok()
        } else {
            None
        };
        self.store
            .read(|document| {
                document
                    .peers
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
        self.store
            .read(|document| {
                document
                    .peers
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
    /// secret of a peer is its certificate fingerprint in any spelling `coqui-peer` reads;
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
            .map(str::parse::<Fingerprint>)
            .transpose()
            .map_err(|_| error::bad_value("that is not a certificate fingerprint"))?
            .filter(|fingerprint| fingerprint.digest() == Digest::Sha256);
        if account.secret.is_some() && fingerprint.is_none() {
            return Err(error::bad_value(
                "a peer is identified by a SHA-256 fingerprint",
            ));
        }
        let accepted = self
            .store
            .change(|document| {
                if let Some(fingerprint) = &fingerprint
                    && let Some(other) = document
                        .peers
                        .iter()
                        .find(|peer| peer.is(fingerprint) && peer.name != account.name)
                {
                    let _ = other;
                    return Err("that certificate belongs to another peer".to_owned());
                }
                let at = document
                    .peers
                    .iter()
                    .position(|peer| peer.name == account.name);
                let peer = match (at, &fingerprint) {
                    (Some(at), _) => &mut document.peers[at],
                    (None, Some(fingerprint)) => {
                        document.peers.push(PeerRecord {
                            id: secret::identifier()?,
                            name: account.name.clone(),
                            certificate: fingerprint.to_string(),
                            email: None,
                            groups: Vec::new(),
                            disabled: false,
                            made_unix: Some(now()),
                        });
                        document.peers.last_mut().expect("it was just pushed")
                    }
                    (None, None) => {
                        return Err(
                            "a new peer is accepted by its certificate fingerprint".to_owned()
                        );
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
                Ok(document
                    .peers
                    .iter()
                    .filter_map(|peer| peer.certificate.parse::<Fingerprint>().ok())
                    .collect::<Vec<_>>())
            })
            .map_err(|reason| error::bad_value(&format!("peer table: {reason}")))?;
        self.waited(&accepted);
        Ok(PutOutcome::default())
    }

    fn remove(&self, name: String) -> Result<(), ProviderError> {
        self.store
            .change(|document| {
                let before = document.peers.len();
                document.peers.retain(|peer| peer.name != name);
                Ok(document.peers.len() < before)
            })
            .map_err(unreadable)
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

fn validate(document: &Document) -> Result<(), String> {
    if document.peers.len() > MAX_PEERS {
        return Err("too many peers".to_owned());
    }
    let mut ids = BTreeSet::new();
    let mut names = BTreeSet::new();
    let mut certificates = BTreeSet::new();
    for peer in &document.peers {
        let Ok(fingerprint) = peer.certificate.parse::<Fingerprint>() else {
            return Err("a peer entry has an invalid certificate".to_owned());
        };
        if fingerprint.digest() != Digest::Sha256 {
            return Err("a peer certificate is identified by its SHA-256 fingerprint".to_owned());
        }
        if !valid_field(&peer.id)
            || !valid_field(&peer.name)
            || !ids.insert(&peer.id)
            || !names.insert(&peer.name)
            || !certificates.insert(fingerprint)
            || peer.groups.len() > 256
            || peer.groups.iter().any(|group| !valid_field(group))
            || peer
                .email
                .as_ref()
                .is_some_and(|email| email.is_empty() || email.len() > 320)
        {
            return Err("a peer entry is invalid or duplicated".to_owned());
        }
    }
    Ok(())
}

fn valid_field(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_FIELD_BYTES && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use coqui_peer::Identity;

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

    #[test]
    fn authenticates_only_known_certificates_and_resolves_groups() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("peers.toml");
        let certificate = Identity::generate().unwrap().fingerprint().to_string();
        fs::write(
            &path,
            format!("[[peers]]\nid='service-1'\nname='site-a'\ncertificate='{certificate}'\ngroups=['site-a']\n"),
        )
        .unwrap();
        let peers = Peers::open(&path).unwrap();
        let Verdict::Valid(lookup) = peers.authenticate(attempt(Some(&certificate))).unwrap()
        else {
            panic!("known certificate was rejected");
        };
        let person = peers.lookup(lookup).unwrap().unwrap();
        assert_eq!(person.id, "service-1");
        assert_eq!(person.groups, vec!["site-a"]);
        // Any spelling of the fingerprint is the same certificate.
        let hex = certificate.parse::<Fingerprint>().unwrap().canonical();
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
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("peers.toml");
        let certificate = Identity::generate().unwrap().fingerprint().to_string();
        fs::write(
            &path,
            format!("[[peers]]\nid='service-1'\nname='site-a'\ncertificate='{certificate}'\ndisabled=true\n"),
        )
        .unwrap();
        let peers = Peers::open(&path).unwrap();
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
        fs::write(
            &path,
            "[[peers]]\nid='service-1'\nname='site-a'\ncertificate='bad'\n",
        )
        .unwrap();
        assert!(Peers::open(&path).is_err());
    }

    #[test]
    fn an_unknown_certificate_waits_and_is_accepted_by_putting_it() {
        let directory = tempfile::tempdir().unwrap();
        let peers = Peers::open(directory.path().join("peers.toml")).unwrap();
        let fingerprint = Identity::generate().unwrap().fingerprint();
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
        let directory = tempfile::tempdir().unwrap();
        let peers = Peers::open(directory.path().join("peers.toml")).unwrap();
        for _ in 0..3 {
            let shown = Identity::generate().unwrap().fingerprint().to_string();
            peers.authenticate(attempt(Some(&shown))).unwrap();
        }
        assert_eq!(peers.waiting().unwrap().len(), 1);
    }
}
