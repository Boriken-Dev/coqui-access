//! `coqui-access-key` as a library a host loads: the Guatiao entry point and the config that
//! builds the provider.
//!
//! The config names where keys come from in `source`, a file in `toml` or `json`:
//!
//! ```json
//! { "source": { "file": { "path": "keys.toml", "format": "toml" } },
//!   "prefix": "ck_",
//!   "key_hash": "sha256",
//!   "argon2": { "memory_kib": 19456, "iterations": 2, "parallelism": 1 },
//!   "max_keys": 10000 }
//! ```
//!
//! Every key is optional. With no `source` the keys live in memory. `key_hash` (`sha256`, the
//! default, or `argon2id`) is how keys made from now on are kept; `argon2` sets the Argon2id
//! costs. Keys already in the table keep the algorithm their stored string names.

mod format;

use std::sync::Arc;

use coqui_access::guatiao::library::ProviderError;
use coqui_access::guatiao::{FromValue, Provider, Schema, ToValue};
use coqui_access::{
    AccountInfo, AccountPut, Accounts, Attempt, Authenticator, Description, Directory, Lookup,
    Person, PutOutcome, Verdict, error,
};
use coqui_access_key::{DEFAULT_PREFIX, KeyRecord, Keys};
use coqui_access_kit::file::Source;
use coqui_access_kit::{Argon2Params, KeyHash, MemoryTable, SourceError, Table};

pub use format::Format;

/// Which algorithm new keys are kept with.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, FromValue, Schema, ToValue)]
#[map(crate = ::coqui_access::guatiao, rename_all = "lowercase")]
pub enum KeyHashKind {
    /// `sha256:<hex>`, for keys of 256 random bits.
    #[default]
    Sha256,
    /// Argon2id, with the `argon2` costs.
    Argon2id,
}

/// Guatiao configuration for the key provider.
#[derive(Debug, Clone, Default, FromValue, Schema, ToValue)]
#[map(crate = ::coqui_access::guatiao)]
pub struct KeysConfig {
    /// Where the keys are kept; memory when absent.
    pub source: Option<Source<Format>>,
    /// What every key made here begins with.
    #[map(default = String::from(DEFAULT_PREFIX))]
    pub prefix: String,
    /// How keys made from now on are kept.
    #[map(default)]
    pub key_hash: KeyHashKind,
    /// Argon2id costs for `key_hash = "argon2id"`.
    pub argon2: Option<Argon2Params>,
    /// The most keys the table may hold; the library default when absent.
    pub max_keys: Option<u32>,
}

fn refused(reason: &SourceError) -> ProviderError {
    error::bad_value(&format!("key table: {reason}"))
}

/// The key provider a host loads.
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
pub struct KeysProvider(Keys);

impl TryFrom<KeysConfig> for KeysProvider {
    type Error = ProviderError;

    fn try_from(config: KeysConfig) -> Result<Self, Self::Error> {
        let hash = match config.key_hash {
            KeyHashKind::Sha256 => KeyHash::Sha256,
            KeyHashKind::Argon2id => KeyHash::Argon2id(config.argon2.unwrap_or_default()),
        };
        let table: Arc<dyn Table<KeyRecord>> = match &config.source {
            Some(source) => source.open("keys").map_err(|reason| refused(&reason))?,
            None => Arc::new(MemoryTable::new()),
        };
        let mut builder = Keys::builder()
            .table(table)
            .prefix(config.prefix)
            .key_hash(hash);
        if let Some(max) = config.max_keys {
            builder = builder.max_keys(max as usize);
        }
        builder.build().map(Self).map_err(|reason| refused(&reason))
    }
}

impl Authenticator for KeysProvider {
    fn authenticate(&self, attempt: Attempt) -> Result<Verdict, ProviderError> {
        self.0.authenticate(attempt)
    }

    fn describe(&self) -> Result<Description, ProviderError> {
        Authenticator::describe(&self.0)
    }
}

impl Directory for KeysProvider {
    fn lookup(&self, lookup: Lookup) -> Result<Option<Person>, ProviderError> {
        self.0.lookup(lookup)
    }

    fn describe(&self) -> Result<Description, ProviderError> {
        Directory::describe(&self.0)
    }
}

impl Accounts for KeysProvider {
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

coqui_access::guatiao::providers!(KeysProvider);

#[cfg(test)]
mod tests {
    use super::*;

    fn config(path: &std::path::Path) -> KeysConfig {
        KeysConfig {
            source: Some(Source::file(path.to_str().unwrap(), Format::Toml)),
            prefix: DEFAULT_PREFIX.to_owned(),
            ..KeysConfig::default()
        }
    }

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
    fn a_file_source_keeps_keys_and_a_hand_written_file_is_read() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("keys.toml");
        let provider = KeysProvider::try_from(config(&path)).unwrap();
        let key = provider.put(named("cabin")).unwrap().secret.unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("[[keys]]") && text.contains("hash = \"sha256:"));
        assert!(!text.contains(key.trim_start_matches("ck_")));
        // A second provider over the same file knows the key, and a hand-written
        // record is taken too.
        let other = KeysProvider::try_from(config(&path)).unwrap();
        assert!(matches!(
            other.authenticate(presented(&key)).unwrap(),
            Verdict::Valid(_)
        ));
        let relay = other.0.new_key().unwrap();
        let digest = KeyHash::Sha256.hash(&relay).unwrap();
        let mut kept = std::fs::read_to_string(&path).unwrap();
        kept.push_str(&format!(
            "\n[[keys]]\nid = 'robot-1'\nname = 'relay'\nhash = '{digest}'\n"
        ));
        std::fs::write(&path, kept).unwrap();
        assert!(matches!(
            provider.authenticate(presented(&relay)).unwrap(),
            Verdict::Valid(_)
        ));
    }

    #[test]
    fn argon2id_keys_are_chosen_in_the_config_and_mix_with_sha256() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("keys.toml");
        let fast = KeysProvider::try_from(config(&path)).unwrap();
        let slow = KeysProvider::try_from(KeysConfig {
            key_hash: KeyHashKind::Argon2id,
            argon2: Some(Argon2Params::new(64, 1, 1).unwrap()),
            ..config(&path)
        })
        .unwrap();
        let sha_key = fast.put(named("fast")).unwrap().secret.unwrap();
        let argon_key = slow.put(named("slow")).unwrap().secret.unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("sha256:") && text.contains("$argon2id$v=19$m=64,t=1,p=1$"));
        for key in [&sha_key, &argon_key] {
            assert!(matches!(
                fast.authenticate(presented(key)).unwrap(),
                Verdict::Valid(_)
            ));
        }
    }

    #[test]
    fn a_bad_file_prefix_or_costs_are_refused() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("keys.toml");
        std::fs::write(&path, "[[keys]]\nid='a'\nname='a'\nhash='short'\n").unwrap();
        assert!(KeysProvider::try_from(config(&path)).is_err());
        let memory = KeysConfig::default();
        assert!(KeysProvider::try_from(memory).is_err(), "an empty prefix");
        let costs = r#"{"prefix": "ck_", "key_hash": "argon2id", "argon2": {"iterations": 0}}"#;
        let costs = guatiao_serde::from_serde(&mut serde_json::Deserializer::from_str(costs));
        assert!(
            KeysConfig::from_value(&costs.unwrap()).is_err(),
            "Argon2 refuses the costs"
        );
    }

    #[test]
    fn no_source_is_memory_and_the_prefix_defaults_when_read() {
        let provider = KeysProvider::try_from(KeysConfig {
            prefix: DEFAULT_PREFIX.to_owned(),
            ..KeysConfig::default()
        })
        .unwrap();
        let key = provider.put(named("cabin")).unwrap().secret.unwrap();
        assert!(key.starts_with("ck_"));
        let bare = coqui_access::guatiao::Map::new();
        assert!(KeysConfig::from_value(&bare.into()).is_ok_and(|c| c.prefix == "ck_"));
    }
}
