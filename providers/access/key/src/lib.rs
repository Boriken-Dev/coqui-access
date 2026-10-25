//! Hashed bearer keys for clients that have nobody to type a password.
//!
//! A key is 256 random bits made here, said once, and kept only as its SHA-256. Each key
//! can be disabled or removed alone and may have a time it stops being taken.
#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
#![warn(missing_docs)]

use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use coqui_access::guatiao::library::ProviderError;
use coqui_access::guatiao::{FromValue, Provider, Schema, ToValue};
use coqui_access::{
    AccountInfo, AccountPut, Accounts, Attempt, Authenticator, Description, Directory, Lookup,
    Person, PutOutcome, Verdict, error, takes,
};
use coqui_access_kit::{Store, secret};
use serde::{Deserialize, Serialize};

const MAX_KEYS: usize = 10_000;
const MAX_FIELD_BYTES: usize = 1024;

/// The prefix of keys made when the configuration names none.
pub const DEFAULT_PREFIX: &str = "ck_";

/// Guatiao configuration for the key table.
#[derive(Debug, Clone, FromValue, Schema, ToValue)]
#[map(crate = ::coqui_access::guatiao)]
#[non_exhaustive]
pub struct KeysConfig {
    /// TOML file containing key hashes and account metadata. Created, owner readable only,
    /// when the first key is made.
    pub path: String,
    /// What every key made here begins with, so a key is recognized where it turns up and
    /// nothing else is looked up among them.
    #[map(default = String::from(DEFAULT_PREFIX))]
    pub prefix: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    #[serde(default)]
    keys: Vec<KeyRecord>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyRecord {
    id: String,
    name: String,
    hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    groups: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    disabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    made_unix: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires_unix: Option<i64>,
}

impl fmt::Debug for KeyRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeyRecord")
            .field("id", &"[REDACTED]")
            .field("name", &"[REDACTED]")
            .field("hash", &"[REDACTED]")
            .field("email", &self.email.as_ref().map(|_| "[REDACTED]"))
            .field("groups", &self.groups.len())
            .field("disabled", &self.disabled)
            .finish()
    }
}

impl KeyRecord {
    /// Whether it is taken now: not disabled and not past its time.
    fn taken(&self) -> bool {
        !self.disabled && self.expires_unix.is_none_or(|expires| now() < expires)
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|since| i64::try_from(since.as_secs()).ok())
        .unwrap_or_default()
}

/// A key table as an Authenticator, Directory and Accounts provider.
///
/// The file is read again whenever another process writes it.
#[derive(Debug, Provider)]
#[provider(
    Authenticator,
    Directory,
    Accounts,
    id = "coqui_access_key",
    name = "Bearer keys",
    config = KeysConfig,
    crate = ::coqui_access::guatiao
)]
pub struct Keys {
    prefix: String,
    store: Store<Document>,
}

impl Keys {
    /// Opens the key table with keys prefixed `prefix`; a missing file means no keys.
    ///
    /// # Errors
    ///
    /// Returns an error when the prefix is empty or the file is unreadable, malformed or out
    /// of bounds.
    pub fn open(path: impl AsRef<Path>, prefix: &str) -> Result<Self, String> {
        if prefix.is_empty() || prefix.chars().any(char::is_control) {
            return Err("prefix must be a non-empty printable string".to_owned());
        }
        Ok(Self {
            prefix: prefix.to_owned(),
            store: Store::open(path, validate)?,
        })
    }

    /// Makes a fresh 256-bit key with this table's prefix.
    ///
    /// # Errors
    ///
    /// Returns an error when the operating system random source is unavailable.
    pub fn new_key(&self) -> Result<String, String> {
        secret::generate(&self.prefix)
    }
}

impl TryFrom<KeysConfig> for Keys {
    type Error = ProviderError;

    fn try_from(config: KeysConfig) -> Result<Self, Self::Error> {
        if config.path.trim().is_empty() {
            return Err(error::bad_value("path must name the key table"));
        }
        Self::open(config.path, &config.prefix)
            .map_err(|reason| error::bad_value(&format!("key table: {reason}")))
    }
}

fn unreadable(reason: String) -> ProviderError {
    error::internal(&format!("key table: {reason}"))
}

impl Authenticator for Keys {
    fn authenticate(&self, attempt: Attempt) -> Result<Verdict, ProviderError> {
        let Some(presented) = attempt.secret.filter(|key| key.starts_with(&self.prefix)) else {
            return Ok(Verdict::Unknown);
        };
        let digest = secret::hash(&presented, None);
        let found = self
            .store
            .read(|document| {
                // Every record is compared, each in the same time whatever it is.
                let mut found = None;
                for record in &document.keys {
                    if secret::same(&record.hash, &digest) {
                        found = Some(record.clone());
                    }
                }
                found
            })
            .map_err(unreadable)?;
        Ok(match found {
            None => Verdict::Unknown,
            Some(record) if record.taken() => Verdict::Valid(Lookup {
                by: "id".to_owned(),
                value: record.id,
            }),
            Some(_) => Verdict::Invalid,
        })
    }

    fn describe(&self) -> Result<Description, ProviderError> {
        Ok(Description {
            name: Some("Bearer keys".to_owned()),
            takes: Some(takes::KEY.to_owned()),
        })
    }
}

impl Directory for Keys {
    fn lookup(&self, lookup: Lookup) -> Result<Option<Person>, ProviderError> {
        self.store
            .read(|document| {
                document
                    .keys
                    .iter()
                    .find(|record| {
                        record.taken()
                            && match lookup.by.as_str() {
                                "id" => record.id == lookup.value,
                                "name" => record.name == lookup.value,
                                "email" => record.email.as_deref() == Some(&lookup.value),
                                _ => false,
                            }
                    })
                    .map(|record| Person {
                        id: record.id.clone(),
                        name: record.name.clone(),
                        display_name: None,
                        email: record.email.clone(),
                        groups: record.groups.clone(),
                        attributes: Default::default(),
                    })
            })
            .map_err(unreadable)
    }
}

impl Accounts for Keys {
    fn accounts(&self) -> Result<Vec<AccountInfo>, ProviderError> {
        self.store
            .read(|document| {
                document
                    .keys
                    .iter()
                    .map(|record| AccountInfo {
                        id: record.id.clone(),
                        name: record.name.clone(),
                        groups: record.groups.clone(),
                        disabled: Some(record.disabled),
                        made_unix: record.made_unix,
                        expires_unix: record.expires_unix,
                    })
                    .collect()
            })
            .map_err(unreadable)
    }

    /// Makes an account and its key, or changes what is said of one there is. An account
    /// that is there and has nothing said to change is given another key, and the one it had
    /// stops being taken. A key is never given: it is made here and answered once.
    fn put(&self, account: AccountPut) -> Result<PutOutcome, ProviderError> {
        if !valid_field(&account.name) {
            return Err(error::bad_value("an account has a name"));
        }
        if account.secret.is_some() {
            return Err(error::bad_value("a key is made here, not given"));
        }
        let unchanged = account.groups.is_none()
            && account.disabled.is_none()
            && account.expires_unix.is_none();
        self.store
            .change(|document| {
                let at = document
                    .keys
                    .iter()
                    .position(|record| record.name == account.name);
                if at.is_none() {
                    document.keys.push(KeyRecord {
                        id: secret::identifier()?,
                        name: account.name.clone(),
                        hash: String::new(),
                        email: None,
                        groups: Vec::new(),
                        disabled: false,
                        made_unix: None,
                        expires_unix: None,
                    });
                }
                let at = at.unwrap_or(document.keys.len() - 1);
                let is_new = document.keys[at].hash.is_empty();
                let record = &mut document.keys[at];
                let mut made = None;
                if is_new || unchanged {
                    let key = secret::generate(&self.prefix)?;
                    record.hash = secret::hash(&key, None);
                    record.made_unix = Some(now());
                    made = Some(key);
                }
                if let Some(groups) = account.groups {
                    record.groups = groups;
                }
                if let Some(disabled) = account.disabled {
                    record.disabled = disabled;
                }
                if let Some(expires) = account.expires_unix {
                    record.expires_unix = Some(expires);
                }
                Ok(PutOutcome { secret: made })
            })
            .map_err(|reason| error::bad_value(&format!("key table: {reason}")))
    }

    fn remove(&self, name: String) -> Result<(), ProviderError> {
        self.store
            .change(|document| {
                let before = document.keys.len();
                document.keys.retain(|record| record.name != name);
                Ok(document.keys.len() < before)
            })
            .map_err(unreadable)
            .and_then(|removed| {
                removed
                    .then_some(())
                    .ok_or_else(|| error::not_found("there is no such account"))
            })
    }
}

fn validate(document: &Document) -> Result<(), String> {
    if document.keys.len() > MAX_KEYS {
        return Err("too many keys".to_owned());
    }
    let mut ids = BTreeSet::new();
    let mut names = BTreeSet::new();
    let mut hashes = BTreeSet::new();
    for record in &document.keys {
        if !valid_field(&record.id)
            || !valid_field(&record.name)
            || !secret::is_hash(&record.hash)
            || !ids.insert(&record.id)
            || !names.insert(&record.name)
            || !hashes.insert(&record.hash)
            || record.groups.len() > 256
            || record.groups.iter().any(|group| !valid_field(group))
            || record
                .email
                .as_ref()
                .is_some_and(|email| email.is_empty() || email.len() > 320)
        {
            return Err("a key entry is invalid or duplicated".to_owned());
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

    use super::*;

    fn presented(key: &str) -> Attempt {
        Attempt {
            secret: Some(key.to_owned()),
            ..Attempt::default()
        }
    }

    fn named(name: &str) -> AccountPut {
        AccountPut {
            name: name.to_owned(),
            ..AccountPut::default()
        }
    }

    #[test]
    fn a_hand_written_table_authenticates_and_resolves() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("keys.toml");
        let keys = Keys::open(&path, "ck_").unwrap();
        let secret = keys.new_key().unwrap();
        let digest = secret::hash(&secret, None);
        fs::write(
            &path,
            format!("[[keys]]\nid='robot-1'\nname='relay'\nhash='{digest}'\ngroups=['station']\n"),
        )
        .unwrap();
        let Verdict::Valid(lookup) = keys.authenticate(presented(&secret)).unwrap() else {
            panic!("valid key was rejected");
        };
        let person = keys.lookup(lookup).unwrap().unwrap();
        assert_eq!(person.id, "robot-1");
        assert_eq!(person.groups, vec!["station"]);
        assert!(!format!("{keys:?}").contains(&secret));
    }

    #[test]
    fn unknown_disabled_and_foreign_keys_are_told_apart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("keys.toml");
        let keys = Keys::open(&path, "ck_").unwrap();
        let key = keys.put(named("relay")).unwrap().secret.unwrap();
        keys.put(AccountPut {
            disabled: Some(true),
            ..named("relay")
        })
        .unwrap();
        assert_eq!(
            keys.authenticate(presented(&key)).unwrap(),
            Verdict::Invalid
        );
        assert_eq!(
            keys.authenticate(presented(&keys.new_key().unwrap()))
                .unwrap(),
            Verdict::Unknown
        );
        assert_eq!(
            keys.authenticate(presented("password")).unwrap(),
            Verdict::Unknown
        );
        assert!(
            keys.lookup(Lookup {
                by: "name".to_owned(),
                value: "relay".to_owned()
            })
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn keys_are_made_rotated_expired_and_removed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("keys.toml");
        let keys = Keys::open(&path, "ck_").unwrap();
        let first = keys.put(named("cabin")).unwrap().secret.unwrap();
        assert!(first.starts_with("ck_"));
        let kept = fs::read_to_string(&path).unwrap();
        assert!(!kept.contains(first.trim_start_matches("ck_")));
        assert!(kept.contains(&secret::hash(&first, None)));
        // Changing what is said of it keeps the key; saying nothing makes another.
        let moved = keys
            .put(AccountPut {
                groups: Some(vec!["guests".to_owned()]),
                ..named("cabin")
            })
            .unwrap();
        assert_eq!(moved.secret, None);
        assert!(matches!(
            keys.authenticate(presented(&first)).unwrap(),
            Verdict::Valid(_)
        ));
        let second = keys.put(named("cabin")).unwrap().secret.unwrap();
        assert_ne!(first, second);
        assert_eq!(
            keys.authenticate(presented(&first)).unwrap(),
            Verdict::Unknown
        );
        assert!(
            keys.put(AccountPut {
                secret: Some("ck_mine".to_owned()),
                ..named("attic")
            })
            .is_err()
        );
        keys.put(AccountPut {
            expires_unix: Some(now() - 1),
            ..named("cabin")
        })
        .unwrap();
        assert_eq!(
            keys.authenticate(presented(&second)).unwrap(),
            Verdict::Invalid
        );
        assert!(keys.accounts().unwrap()[0].expires_unix.is_some());
        keys.remove("cabin".to_owned()).unwrap();
        assert!(keys.remove("cabin".to_owned()).is_err());
        assert_eq!(
            keys.authenticate(presented(&second)).unwrap(),
            Verdict::Unknown
        );
    }

    #[test]
    fn a_key_made_by_another_open_table_is_known_without_reopening() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("keys.toml");
        let daemon = Keys::open(&path, "ck_").unwrap();
        let command = Keys::open(&path, "ck_").unwrap();
        let key = command.put(named("cabin")).unwrap().secret.unwrap();
        assert!(matches!(
            daemon.authenticate(presented(&key)).unwrap(),
            Verdict::Valid(_)
        ));
    }

    #[test]
    fn a_malformed_table_or_prefix_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("keys.toml");
        assert!(Keys::open(&path, "").is_err());
        fs::write(&path, "[[keys]]\nid='a'\nname='a'\nhash='short'\n").unwrap();
        assert!(Keys::open(&path, "ck_").is_err());
    }
}
