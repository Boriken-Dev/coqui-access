//! `coqui-access-local` as a library a host loads: the Guatiao entry point and the config that
//! builds the provider.
//!
//! The config names where accounts come from in `source` (see `coqui-access-plugin-support`):
//!
//! ```json
//! { "source": { "file": { "path": "accounts.toml", "format": "toml" } },
//!   "max_accounts": 10000,
//!   "argon2": { "memory_kib": 19456, "iterations": 2, "parallelism": 1 } }
//! ```
//!
//! Every key is optional. With no `source` the accounts live in memory.

use coqui_access::guatiao::library::ProviderError;
use coqui_access::guatiao::{FromValue, Provider, Schema, ToValue};
use coqui_access::{
    AccountInfo, AccountPut, Accounts, Attempt, Authenticator, Description, Directory, Lookup,
    Person, PutOutcome, Verdict,
};
use coqui_access_local::{AccountRecord, LocalAccounts};
use coqui_access_plugin_support::{Argon2Config, SourceConfig, build_failed, open_table};

/// Guatiao configuration for the local accounts provider.
#[derive(Debug, Clone, Default, FromValue, Schema, ToValue)]
#[map(crate = ::coqui_access::guatiao)]
pub struct LocalAccountsConfig {
    /// Where the accounts are kept; memory when absent.
    pub source: Option<SourceConfig>,
    /// The most accounts the table may hold; the library default when absent.
    pub max_accounts: Option<u32>,
    /// Argon2id costs for new passwords; the library default for each one absent.
    pub argon2: Option<Argon2Config>,
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
        let mut builder = LocalAccounts::builder().table(open_table::<AccountRecord>(
            config.source.as_ref(),
            "accounts",
        )?);
        if let Some(max) = config.max_accounts {
            builder = builder.max_accounts(max as usize);
        }
        if let Some(argon2) = &config.argon2 {
            builder = builder.argon2(argon2.params()?);
        }
        builder
            .build()
            .map(Self)
            .map_err(|reason| build_failed("account table", &reason))
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
    use coqui_access_kit::{Argon2Params, PasswordHasher};

    use super::*;

    fn cheap() -> Argon2Config {
        Argon2Config {
            memory_kib: Some(64),
            iterations: Some(1),
            ..Argon2Config::default()
        }
    }

    fn config(path: &std::path::Path) -> LocalAccountsConfig {
        LocalAccountsConfig {
            source: Some(SourceConfig::toml_file(path.to_str().unwrap())),
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
        let hash = PasswordHasher::new(Argon2Params::new(64, 1, 1).unwrap())
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
            source: Some(SourceConfig::default()),
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
                source: Some(SourceConfig::toml_file("accounts.toml")),
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
}
