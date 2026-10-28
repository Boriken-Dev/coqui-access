//! `coqui-access-local` as a library a host loads: the Guatiao entry point and the config that
//! builds the provider.
//!
//! The config names where accounts come from in `source`, a file in `toml` or `json`:
//!
//! ```json
//! { "source": { "file": { "path": "accounts.toml", "format": "toml" } },
//!   "max_accounts": 10000,
//!   "argon2": { "memory_kib": 19456, "iterations": 2, "parallelism": 1 } }
//! ```
//!
//! Every key is optional. With no `source` the accounts live in memory.

mod format;

use std::sync::Arc;

use coqui_access::guatiao::library::ProviderError;
use coqui_access::guatiao::{FromValue, Provider, Schema, ToValue};
use coqui_access::{
    AccountInfo, AccountPut, Accounts, Attempt, Authenticator, Description, Directory, Lookup,
    Person, PutOutcome, Verdict, error,
};
use coqui_access_kit::file::Source;
use coqui_access_kit::{Argon2Params, MemoryTable, SourceError, Table};
use coqui_access_local::{AccountRecord, LocalAccounts};

pub use format::Format;

/// Guatiao configuration for the local accounts provider.
#[derive(Debug, Clone, Default, FromValue, Schema, ToValue)]
#[map(crate = ::coqui_access::guatiao)]
pub struct LocalAccountsConfig {
    /// Where the accounts are kept; memory when absent.
    pub source: Option<Source<Format>>,
    /// The most accounts the table may hold; the library default when absent.
    pub max_accounts: Option<u32>,
    /// Argon2id costs for new passwords; the library default for each one absent.
    pub argon2: Option<Argon2Params>,
}

fn refused(reason: &SourceError) -> ProviderError {
    error::bad_value(&format!("account table: {reason}"))
}

/// The local accounts provider a host loads.
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
pub struct LocalAccountsProvider(LocalAccounts);

impl TryFrom<LocalAccountsConfig> for LocalAccountsProvider {
    type Error = ProviderError;

    fn try_from(config: LocalAccountsConfig) -> Result<Self, Self::Error> {
        let table: Arc<dyn Table<AccountRecord>> = match &config.source {
            Some(source) => source.open("accounts").map_err(|reason| refused(&reason))?,
            None => Arc::new(MemoryTable::new()),
        };
        let mut builder = LocalAccounts::builder().table(table);
        if let Some(max) = config.max_accounts {
            builder = builder.max_accounts(max as usize);
        }
        if let Some(argon2) = config.argon2 {
            builder = builder.argon2(argon2);
        }
        builder.build().map(Self).map_err(|reason| refused(&reason))
    }
}

impl Authenticator for LocalAccountsProvider {
    fn authenticate(&self, attempt: Attempt) -> Result<Verdict, ProviderError> {
        self.0.authenticate(attempt)
    }

    fn describe(&self) -> Result<Description, ProviderError> {
        Authenticator::describe(&self.0)
    }
}

impl Directory for LocalAccountsProvider {
    fn lookup(&self, lookup: Lookup) -> Result<Option<Person>, ProviderError> {
        self.0.lookup(lookup)
    }

    fn describe(&self) -> Result<Description, ProviderError> {
        Directory::describe(&self.0)
    }
}

impl Accounts for LocalAccountsProvider {
    fn accounts(&self) -> Result<Vec<AccountInfo>, ProviderError> {
        self.0.accounts()
    }

    fn put(&self, account: AccountPut) -> Result<PutOutcome, ProviderError> {
        self.0.put(account)
    }

    fn remove(&self, name: String) -> Result<(), ProviderError> {
        self.0.remove(name)
    }
}

coqui_access::guatiao::providers!(LocalAccountsProvider);

#[cfg(test)]
mod tests {
    use coqui_access_kit::PasswordHasher;

    use super::*;

    fn cheap() -> Argon2Params {
        Argon2Params::new(64, 1, 1).unwrap()
    }

    fn config(path: &std::path::Path) -> LocalAccountsConfig {
        config_in(path, Format::Toml)
    }

    fn config_in(path: &std::path::Path, format: Format) -> LocalAccountsConfig {
        LocalAccountsConfig {
            source: Some(Source::file(path.to_str().unwrap(), format)),
            argon2: Some(cheap()),
            ..LocalAccountsConfig::default()
        }
    }

    fn attempt(name: &str, password: &str) -> Attempt {
        Attempt {
            name: Some(name.to_owned()),
            secret: Some(password.to_owned()),
            ..Attempt::default()
        }
    }

    #[test]
    fn a_file_source_is_read_written_and_followed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("accounts.toml");
        let hash = PasswordHasher::new(cheap())
            .unwrap()
            .hash("correct horse")
            .unwrap();
        std::fs::write(
            &path,
            format!(
                "[[accounts]]\nid='person-a'\nname='alice'\npassword_hash='{hash}'\ngroups=['field']\n"
            ),
        )
        .unwrap();
        let provider = LocalAccountsProvider::try_from(config(&path)).unwrap();
        let Verdict::Valid(lookup) = provider
            .authenticate(attempt("alice", "correct horse"))
            .unwrap()
        else {
            panic!("the account in the file should authenticate");
        };
        assert_eq!(provider.lookup(lookup).unwrap().unwrap().groups, ["field"]);

        // A put goes to the file, and another provider over the file sees it.
        provider
            .put(AccountPut {
                name: "bob".to_owned(),
                secret: Some("pw".to_owned()),
                ..AccountPut::default()
            })
            .unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("name = \"bob\"") && !text.contains("\"pw\""));
        let other = LocalAccountsProvider::try_from(config(&path)).unwrap();
        assert!(matches!(
            other.authenticate(attempt("bob", "pw")).unwrap(),
            Verdict::Valid(_)
        ));
        other.remove("bob".to_owned()).unwrap();
        assert_eq!(provider.accounts().unwrap().len(), 1);
    }

    #[test]
    fn a_bad_file_or_source_is_refused_and_no_source_is_memory() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("accounts.toml");
        std::fs::write(&path, "accounts = [ { unknown = true } ]").unwrap();
        assert!(LocalAccountsProvider::try_from(config(&path)).is_err());
        std::fs::write(&path, vec![b' '; 1024 * 1024 + 1]).unwrap();
        assert!(LocalAccountsProvider::try_from(config(&path)).is_err());
        let empty = LocalAccountsConfig {
            source: Some(Source { file: None }),
            ..LocalAccountsConfig::default()
        };
        assert!(LocalAccountsProvider::try_from(empty).is_err());
        let memory = LocalAccountsProvider::try_from(LocalAccountsConfig {
            argon2: Some(cheap()),
            ..LocalAccountsConfig::default()
        })
        .unwrap();
        assert!(memory.accounts().unwrap().is_empty());
    }

    #[test]
    fn the_config_reads_from_a_guatiao_value() {
        let config = LocalAccountsConfig::from_value(
            &LocalAccountsConfig {
                source: Some(Source::file("accounts.toml", Format::Toml)),
                max_accounts: Some(5),
                argon2: None,
            }
            .to_value()
            .unwrap(),
        )
        .unwrap();
        assert_eq!(config.max_accounts, Some(5));
        assert_eq!(config.source.unwrap().file.unwrap().path, "accounts.toml");
    }

    #[test]
    fn a_json_source_holds_the_same_accounts() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("accounts.json");
        let provider = LocalAccountsProvider::try_from(config_in(&path, Format::Json)).unwrap();
        provider
            .put(AccountPut {
                name: "carol".to_owned(),
                secret: Some("pw".to_owned()),
                groups: Some(vec!["staff".to_owned()]),
                ..AccountPut::default()
            })
            .unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.trim_start().starts_with('{') && text.contains("\"carol\""));
        let other = LocalAccountsProvider::try_from(config_in(&path, Format::Json)).unwrap();
        assert!(matches!(
            other.authenticate(attempt("carol", "pw")).unwrap(),
            Verdict::Valid(_)
        ));
        assert!(
            LocalAccountsProvider::try_from(config(&path)).is_err(),
            "JSON is not TOML"
        );
    }
}
