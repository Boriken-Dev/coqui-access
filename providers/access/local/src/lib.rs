//! Local accounts backed by a bounded TOML file.
//!
//! Passwords are stored only as Argon2id hashes. The provider authenticates accounts,
//! resolves the same records as a directory, and manages them through [`Accounts`].
#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
#![warn(missing_docs)]

use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use argon2::Argon2;
use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use coqui_access::guatiao::library::ProviderError;
use coqui_access::guatiao::{FromValue, Provider, Schema, ToValue};
use coqui_access::{
    AccountInfo, AccountPut, Accounts, Attempt, Authenticator, Description, Directory, Lookup,
    Person, PutOutcome, Verdict, error, takes,
};
use coqui_access_kit::{Store, secret};
use serde::{Deserialize, Serialize};

const MAX_ACCOUNTS: usize = 10_000;
const MAX_PASSWORD_BYTES: usize = 4096;
const MAX_NAME_BYTES: usize = 256;

/// Guatiao configuration for the local account file.
#[derive(Debug, Clone, FromValue, Schema, ToValue)]
#[map(crate = ::coqui_access::guatiao)]
#[non_exhaustive]
pub struct LocalAccountsConfig {
    /// TOML file containing account IDs, names, password hashes and groups. Created, owner
    /// readable only, when the first account is put.
    pub path: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    #[serde(default)]
    accounts: Vec<AccountRecord>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountRecord {
    id: String,
    name: String,
    password_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    groups: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    disabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    made_unix: Option<i64>,
}

impl fmt::Debug for AccountRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccountRecord")
            .field("id", &"[REDACTED]")
            .field("name", &"[REDACTED]")
            .field("password_hash", &"[REDACTED]")
            .field(
                "display_name",
                &self.display_name.as_ref().map(|_| "[REDACTED]"),
            )
            .field("email", &self.email.as_ref().map(|_| "[REDACTED]"))
            .field("groups", &self.groups.len())
            .field("disabled", &self.disabled)
            .finish()
    }
}

/// Local accounts as an Authenticator, Directory and Accounts provider.
///
/// The file is read again whenever another process writes it. A name that is not kept is
/// verified against a dummy hash, so an unknown name costs the same time as a wrong password.
#[derive(Debug, Provider)]
#[provider(
    Authenticator,
    Directory,
    Accounts,
    id = "coqui_access_local",
    name = "Local accounts",
    config = LocalAccountsConfig,
    crate = ::coqui_access::guatiao
)]
pub struct LocalAccounts {
    store: Store<Document>,
    dummy_hash: String,
}

impl LocalAccounts {
    /// Opens the account file; a missing file means that no accounts are configured.
    ///
    /// # Errors
    ///
    /// Returns an error when the file is unreadable, malformed or exceeds its bounds.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, String> {
        Ok(Self {
            store: Store::open(path, validate)?,
            dummy_hash: hash_password("unknown account password")?,
        })
    }
}

impl TryFrom<LocalAccountsConfig> for LocalAccounts {
    type Error = ProviderError;

    fn try_from(config: LocalAccountsConfig) -> Result<Self, Self::Error> {
        if config.path.trim().is_empty() {
            return Err(error::bad_value("path must name the local account file"));
        }
        Self::open(&config.path)
            .map_err(|reason| error::bad_value(&format!("account file: {reason}")))
    }
}

fn unreadable(reason: String) -> ProviderError {
    error::internal(&format!("account file: {reason}"))
}

impl Authenticator for LocalAccounts {
    fn authenticate(&self, attempt: Attempt) -> Result<Verdict, ProviderError> {
        let (Some(name), Some(password)) = (attempt.name, attempt.secret) else {
            return Ok(Verdict::Unknown);
        };
        let account = self
            .store
            .read(|document| {
                document
                    .accounts
                    .iter()
                    .find(|account| account.name == name)
                    .cloned()
            })
            .map_err(unreadable)?;
        let hash = account
            .as_ref()
            .map_or(self.dummy_hash.as_str(), |account| {
                account.password_hash.as_str()
            });
        let verified = verify_password(&password, hash);
        Ok(match account {
            Some(account) if verified && !account.disabled => Verdict::Valid(Lookup {
                by: "id".to_owned(),
                value: account.id,
            }),
            _ => Verdict::Invalid,
        })
    }

    fn describe(&self) -> Result<Description, ProviderError> {
        Ok(Description {
            name: Some("Local accounts".to_owned()),
            takes: Some(takes::PASSWORD.to_owned()),
        })
    }
}

impl Directory for LocalAccounts {
    fn lookup(&self, lookup: Lookup) -> Result<Option<Person>, ProviderError> {
        self.store
            .read(|document| {
                document
                    .accounts
                    .iter()
                    .find(|account| {
                        !account.disabled
                            && match lookup.by.as_str() {
                                "id" => account.id == lookup.value,
                                "name" => account.name == lookup.value,
                                "email" => account.email.as_deref() == Some(&lookup.value),
                                _ => false,
                            }
                    })
                    .map(|account| Person {
                        id: account.id.clone(),
                        name: account.name.clone(),
                        display_name: account.display_name.clone(),
                        email: account.email.clone(),
                        groups: account.groups.clone(),
                        attributes: Default::default(),
                    })
            })
            .map_err(unreadable)
    }
}

impl Accounts for LocalAccounts {
    fn accounts(&self) -> Result<Vec<AccountInfo>, ProviderError> {
        self.store
            .read(|document| {
                document
                    .accounts
                    .iter()
                    .map(|account| AccountInfo {
                        id: account.id.clone(),
                        name: account.name.clone(),
                        groups: account.groups.clone(),
                        disabled: Some(account.disabled),
                        made_unix: account.made_unix,
                        expires_unix: None,
                    })
                    .collect()
            })
            .map_err(unreadable)
    }

    /// A new account needs a password; an existing one keeps its password unless one is
    /// given.
    fn put(&self, account: AccountPut) -> Result<PutOutcome, ProviderError> {
        if !valid_field(&account.name, MAX_NAME_BYTES) {
            return Err(error::bad_value("an account has a name"));
        }
        if account.expires_unix.is_some() {
            return Err(error::bad_value("local accounts do not expire"));
        }
        let password = account
            .secret
            .as_deref()
            .map(hash_password)
            .transpose()
            .map_err(|reason| error::bad_value(&reason))?;
        self.store
            .change(|document| {
                let at = document
                    .accounts
                    .iter()
                    .position(|entry| entry.name == account.name);
                let entry = match (at, password) {
                    (Some(at), password) => {
                        let entry = &mut document.accounts[at];
                        if let Some(password) = password {
                            entry.password_hash = password;
                        }
                        entry
                    }
                    (None, Some(password)) => {
                        document.accounts.push(AccountRecord {
                            id: secret::identifier()?,
                            name: account.name.clone(),
                            password_hash: password,
                            display_name: None,
                            email: None,
                            groups: Vec::new(),
                            disabled: false,
                            made_unix: now(),
                        });
                        document.accounts.last_mut().expect("it was just pushed")
                    }
                    (None, None) => return Err("a new account needs a password".to_owned()),
                };
                if let Some(groups) = account.groups {
                    entry.groups = groups;
                }
                if let Some(disabled) = account.disabled {
                    entry.disabled = disabled;
                }
                Ok(())
            })
            .map(|()| PutOutcome::default())
            .map_err(|reason| error::bad_value(&format!("account file: {reason}")))
    }

    fn remove(&self, name: String) -> Result<(), ProviderError> {
        self.store
            .change(|document| {
                let before = document.accounts.len();
                document.accounts.retain(|entry| entry.name != name);
                Ok(document.accounts.len() < before)
            })
            .map_err(unreadable)
            .and_then(|removed| {
                removed
                    .then_some(())
                    .ok_or_else(|| error::not_found("there is no such account"))
            })
    }
}

/// Hashes a password with a fresh random Argon2id salt for an account record.
///
/// # Errors
///
/// Returns an error when the password is empty, exceeds 4096 bytes, or hashing fails.
pub fn hash_password(password: &str) -> Result<String, String> {
    if password.is_empty() || password.len() > MAX_PASSWORD_BYTES {
        return Err("password must be between 1 and 4096 bytes".to_owned());
    }
    Argon2::default()
        .hash_password(password.as_bytes())
        .map(|hash| hash.to_string())
        .map_err(|_| "password hash could not be created".to_owned())
}

fn verify_password(password: &str, encoded: &str) -> bool {
    if password.len() > MAX_PASSWORD_BYTES {
        return false;
    }
    PasswordHash::new(encoded).ok().is_some_and(|hash| {
        Argon2::default()
            .verify_password(password.as_bytes(), &hash)
            .is_ok()
    })
}

fn now() -> Option<i64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|since| i64::try_from(since.as_secs()).ok())
}

fn validate(document: &Document) -> Result<(), String> {
    if document.accounts.len() > MAX_ACCOUNTS {
        return Err("too many accounts".to_owned());
    }
    let mut ids = BTreeSet::new();
    let mut names = BTreeSet::new();
    for account in &document.accounts {
        if !valid_field(&account.id, MAX_NAME_BYTES)
            || !valid_field(&account.name, MAX_NAME_BYTES)
            || account.name.trim().is_empty()
            || account.password_hash.len() > 1024
            || PasswordHash::new(&account.password_hash).is_err()
            || !ids.insert(&account.id)
            || !names.insert(&account.name)
            || account.groups.len() > 256
            || account
                .groups
                .iter()
                .any(|group| !valid_field(group, MAX_NAME_BYTES))
            || account
                .display_name
                .as_ref()
                .is_some_and(|value| !valid_field(value, 1024))
            || account
                .email
                .as_ref()
                .is_some_and(|value| !valid_field(value, 320))
        {
            return Err("an account entry is invalid or duplicated".to_owned());
        }
    }
    Ok(())
}

fn valid_field(value: &str, max_bytes: usize) -> bool {
    !value.is_empty() && value.len() <= max_bytes && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write;

    use super::*;

    fn attempt(name: &str, password: &str) -> Attempt {
        Attempt {
            name: Some(name.to_owned()),
            secret: Some(password.to_owned()),
            ..Attempt::default()
        }
    }

    #[test]
    fn authenticates_and_resolves_accounts_without_exposing_password_hashes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("accounts.toml");
        let password_hash = hash_password("correct horse battery staple").unwrap();
        let mut file = fs::File::create(&path).unwrap();
        writeln!(file, "[[accounts]]\nid='person-a'\nname='alice'\npassword_hash='{password_hash}'\ngroups=['field']").unwrap();
        let accounts = LocalAccounts::open(&path).unwrap();
        let Verdict::Valid(lookup) = accounts
            .authenticate(attempt("alice", "correct horse battery staple"))
            .unwrap()
        else {
            panic!("password should be valid");
        };
        assert_eq!(lookup.by, "id");
        let person = accounts.lookup(lookup).unwrap().unwrap();
        assert_eq!(person.id, "person-a");
        assert_eq!(person.groups, vec!["field".to_owned()]);
        assert!(!format!("{accounts:?}").contains(&password_hash));
    }

    #[test]
    fn wrong_unknown_and_disabled_credentials_do_not_authenticate() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("accounts.toml");
        let password_hash = hash_password("password").unwrap();
        fs::write(&path, format!("[[accounts]]\nid='person-a'\nname='a'\npassword_hash='{password_hash}'\ndisabled=true\n")).unwrap();
        let accounts = LocalAccounts::open(&path).unwrap();
        assert!(
            accounts
                .lookup(Lookup {
                    by: "id".to_owned(),
                    value: "person-a".to_owned(),
                })
                .unwrap()
                .is_none()
        );
        for name in ["a", "missing"] {
            assert_eq!(
                accounts.authenticate(attempt(name, "password")).unwrap(),
                Verdict::Invalid
            );
        }
        assert_eq!(
            accounts.authenticate(Attempt::default()).unwrap(),
            Verdict::Unknown
        );
    }

    #[test]
    fn rejects_oversized_and_malformed_account_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("accounts.toml");
        fs::write(&path, "accounts = [ { unknown = true } ]").unwrap();
        assert!(LocalAccounts::open(&path).is_err());
        fs::write(&path, vec![b' '; 1024 * 1024 + 1]).unwrap();
        assert!(LocalAccounts::open(&path).is_err());
    }

    #[test]
    fn accounts_are_made_changed_and_removed_through_the_kind() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("accounts.toml");
        let accounts = LocalAccounts::open(&path).unwrap();
        let named = |name: &str| AccountPut {
            name: name.to_owned(),
            ..AccountPut::default()
        };
        assert!(
            accounts.put(named("alice")).is_err(),
            "a new account needs a password"
        );
        accounts
            .put(AccountPut {
                secret: Some("pw one".to_owned()),
                groups: Some(vec!["staff".to_owned()]),
                ..named("alice")
            })
            .unwrap();
        assert!(matches!(
            accounts.authenticate(attempt("alice", "pw one")).unwrap(),
            Verdict::Valid(_)
        ));
        // Changing groups leaves the password; giving a password replaces it.
        accounts
            .put(AccountPut {
                groups: Some(vec!["admin".to_owned()]),
                ..named("alice")
            })
            .unwrap();
        assert!(matches!(
            accounts.authenticate(attempt("alice", "pw one")).unwrap(),
            Verdict::Valid(_)
        ));
        accounts
            .put(AccountPut {
                secret: Some("pw two".to_owned()),
                ..named("alice")
            })
            .unwrap();
        assert_eq!(
            accounts.authenticate(attempt("alice", "pw one")).unwrap(),
            Verdict::Invalid
        );
        let listed = accounts.accounts().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].groups, ["admin"]);
        assert!(!fs::read_to_string(&path).unwrap().contains("pw two"));
        assert!(
            accounts
                .put(AccountPut {
                    expires_unix: Some(1),
                    ..named("alice")
                })
                .is_err()
        );
        accounts.remove("alice".to_owned()).unwrap();
        assert!(accounts.remove("alice".to_owned()).is_err());
        // Another process's write is seen without reopening.
        let other = LocalAccounts::open(&path).unwrap();
        other
            .put(AccountPut {
                secret: Some("x".to_owned()),
                ..named("bob")
            })
            .unwrap();
        assert_eq!(accounts.accounts().unwrap().len(), 1);
    }
}
