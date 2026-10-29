//! `coqui-access-peer` as a library a host loads: the Guatiao entry point and the config that
//! builds the provider.
//!
//! The config names where peers come from in `source`, a file in `toml` or `json`:
//!
//! ```json
//! { "source": { "file": { "path": "peers.toml", "format": "toml" } },
//!   "waiting": { "file": { "path": "peers.toml.waiting", "format": "toml" } },
//!   "max_peers": 10000, "waiting_places": 16, "seen_every_secs": 60 }
//! ```
//!
//! Every key is optional. With no `source` the peers live in memory. `waiting`, where the
//! fingerprints nobody accepted are kept, defaults to a file beside a file source
//! (`<path>.waiting`) and to memory otherwise.

mod format;

use std::sync::Arc;

use coqui_access::guatiao::library::ProviderError;
use coqui_access::guatiao::{FromValue, FromWalk, Provider, Schema, ToValue, Walk};
use coqui_access::{
    AccountInfo, AccountPut, Accounts, Attempt, Authenticator, Description, Directory, Lookup,
    Person, PutOutcome, Verdict, Waiting,
};
use coqui_access_kit::file::Source;
use coqui_access_kit::{Keyed, MemoryTable, Table};
use coqui_access_peer::{PeerRecord, Peers, Unaccepted};

pub use format::Format;

/// Guatiao configuration for the verified peer provider.
#[derive(Debug, Clone, Default, FromValue, Schema, ToValue)]
#[map(crate = ::coqui_access::guatiao)]
pub struct PeersConfig {
    /// Where the accepted peers are kept; memory when absent.
    pub source: Option<Source<Format>>,
    /// Where the fingerprints waiting to be accepted are kept.
    pub waiting: Option<Source<Format>>,
    /// The most peers the table may hold; the library default when absent.
    pub max_peers: Option<u32>,
    /// How many unaccepted fingerprints are kept; the library default when absent.
    pub waiting_places: Option<u32>,
    /// Seconds before a waiting fingerprint from one address is written down again; the
    /// library default when absent.
    pub seen_every_secs: Option<i64>,
}

/// The table `source` names, or one in memory.
fn open<T>(
    source: Option<&Source<Format>>,
    section: &str,
) -> Result<Arc<dyn Table<T>>, ProviderError>
where
    T: Keyed + Clone + Send + Walk + FromWalk + 'static,
{
    match source {
        Some(source) => source
            .open(section)
            .map_err(|reason| reason.writing("peer table")),
        None => Ok(Arc::new(MemoryTable::new())),
    }
}

/// The peer provider a host loads.
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
pub struct PeersProvider(Peers);

impl TryFrom<PeersConfig> for PeersProvider {
    type Error = ProviderError;

    fn try_from(config: PeersConfig) -> Result<Self, Self::Error> {
        let waiting_source = config.waiting.clone().or_else(|| {
            config
                .source
                .as_ref()
                .map(|source| source.sibling("waiting"))
        });
        let mut builder = Peers::builder()
            .table(open::<PeerRecord>(config.source.as_ref(), "peers")?)
            .waiting(open::<Unaccepted>(waiting_source.as_ref(), "waiting")?);
        if let Some(max) = config.max_peers {
            builder = builder.max_peers(max as usize);
        }
        if let Some(places) = config.waiting_places {
            builder = builder.waiting_places(places as usize);
        }
        if let Some(seconds) = config.seen_every_secs {
            builder = builder.seen_every_secs(seconds);
        }
        builder
            .build()
            .map(Self)
            .map_err(|reason| reason.writing("peer table"))
    }
}

impl Authenticator for PeersProvider {
    fn authenticate(&self, attempt: Attempt) -> Result<Verdict, ProviderError> {
        self.0.authenticate(attempt)
    }

    fn describe(&self) -> Result<Description, ProviderError> {
        Authenticator::describe(&self.0)
    }
}

impl Directory for PeersProvider {
    fn lookup(&self, lookup: Lookup) -> Result<Option<Person>, ProviderError> {
        self.0.lookup(lookup)
    }

    fn describe(&self) -> Result<Description, ProviderError> {
        Directory::describe(&self.0)
    }
}

impl Accounts for PeersProvider {
    fn accounts(&self) -> Result<Vec<AccountInfo>, ProviderError> {
        self.0.accounts()
    }

    fn put(&self, account: AccountPut) -> Result<PutOutcome, ProviderError> {
        self.0.put(account)
    }

    fn remove(&self, name: String) -> Result<(), ProviderError> {
        self.0.remove(name)
    }

    fn waiting(&self) -> Result<Vec<Waiting>, ProviderError> {
        self.0.waiting()
    }
}

coqui_access::guatiao::providers!(PeersProvider);

#[cfg(test)]
mod tests {
    use coqui_peer_tls::Identity;

    use super::*;

    fn config(path: &std::path::Path) -> PeersConfig {
        PeersConfig {
            source: Some(Source::file(path.to_str().unwrap(), Format::Toml)),
            ..PeersConfig::default()
        }
    }

    fn shown(certificate: &str) -> Attempt {
        Attempt {
            certificate: Some(certificate.to_owned()),
            peer: Some("192.0.2.7:4000".to_owned()),
            ..Attempt::default()
        }
    }

    #[test]
    fn a_file_source_keeps_peers_and_the_waiting_list_beside_it() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("peers.toml");
        let provider = PeersProvider::try_from(config(&path)).unwrap();
        let certificate = Identity::generate().unwrap().fingerprint();
        let text = certificate.to_string();
        assert_eq!(
            provider.authenticate(shown(&text)).unwrap(),
            Verdict::Unknown
        );
        let waiting_file = directory.path().join("peers.toml.waiting");
        assert!(
            std::fs::read_to_string(&waiting_file)
                .unwrap()
                .contains("[[waiting]]")
        );
        let waiting = provider.waiting().unwrap();
        assert_eq!(waiting.len(), 1);

        provider
            .put(AccountPut {
                name: "site-a".to_owned(),
                secret: Some(waiting[0].shown.clone()),
                ..AccountPut::default()
            })
            .unwrap();
        assert!(provider.waiting().unwrap().is_empty());
        assert!(
            std::fs::read_to_string(&path)
                .unwrap()
                .contains("[[peers]]")
        );
        let other = PeersProvider::try_from(config(&path)).unwrap();
        assert!(matches!(
            other.authenticate(shown(&text)).unwrap(),
            Verdict::Valid(_)
        ));
    }

    #[test]
    fn a_hand_written_file_is_read_and_a_bad_one_refused() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("peers.toml");
        let certificate = Identity::generate().unwrap().fingerprint().to_string();
        std::fs::write(
            &path,
            format!(
                "[[peers]]\nid='service-1'\nname='site-a'\ncertificate='{certificate}'\ngroups=['site-a']\n"
            ),
        )
        .unwrap();
        let provider = PeersProvider::try_from(config(&path)).unwrap();
        assert!(matches!(
            provider.authenticate(shown(&certificate)).unwrap(),
            Verdict::Valid(_)
        ));
        std::fs::write(
            &path,
            "[[peers]]\nid='service-1'\nname='site-a'\ncertificate='bad'\n",
        )
        .unwrap();
        assert!(PeersProvider::try_from(config(&path)).is_err());
    }

    #[test]
    fn waiting_can_be_a_separate_source_or_memory() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("peers.toml");
        let apart = directory.path().join("seen.toml");
        let provider = PeersProvider::try_from(PeersConfig {
            waiting: Some(Source::file(apart.to_str().unwrap(), Format::Toml)),
            ..config(&path)
        })
        .unwrap();
        let text = Identity::generate().unwrap().fingerprint().to_string();
        provider.authenticate(shown(&text)).unwrap();
        assert!(apart.exists());
        assert!(!directory.path().join("peers.toml.waiting").exists());
        // No source at all: both in memory.
        let memory = PeersProvider::try_from(PeersConfig::default()).unwrap();
        memory.authenticate(shown(&text)).unwrap();
        assert_eq!(memory.waiting().unwrap().len(), 1);
    }
}
