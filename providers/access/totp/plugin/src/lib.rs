//! `coqui-access-totp` as a library a host loads: the Guatiao entry point and the config that
//! builds the provider.
//!
//! The config names where accounts come from in `source`, a file in `toml` or `json`; the
//! enrolments waiting for a first code are kept beside it (`<path>.pending`) unless `pending`
//! names another source:
//!
//! ```json
//! { "source": { "file": { "path": "totp.toml", "format": "toml" } },
//!   "issuer": "Example", "algorithm": "sha1", "digits": 6, "period": 30, "skew": 1,
//!   "recovery_codes": 10, "enrol_seconds": 600, "max_records": 10000 }
//! ```
//!
//! Every key is optional. With no `source` the accounts live in memory. The file holds each
//! account's secret readable, as a time-based code needs it: it is written with the owner's
//! permissions only, and belongs where only the service can read it.

mod format;

use std::sync::Arc;

use coqui_access::guatiao::library::ProviderError;
use coqui_access::guatiao::{FromWalk, Provider, Walk};
use coqui_access::{
    AccountInfo, AccountPut, Accounts, Attempt, Authenticator, Description, PutOutcome, Verdict,
    Waiting,
};
use coqui_access_kit::file::Source;
use coqui_access_kit::{Keyed, MemoryTable, RecordLimits, Table};
use coqui_access_totp::{
    Algorithm, DEFAULT_DIGITS, DEFAULT_ENROL_SECONDS, DEFAULT_MAX_RECORDS, DEFAULT_PERIOD,
    DEFAULT_RECOVERY_CODES, DEFAULT_SKEW, PendingTotp, TotpAccounts, TotpRecord,
};

use coqui_builder::{Describe, Partial};
use guatiao_builder::Described;

pub use format::Format;

/// Guatiao configuration for the one-time code provider.
#[derive(Debug, Clone, Describe)]
pub struct TotpConfig {
    /// Where the enrolled accounts are kept; memory when absent.
    pub source: Option<Source<Format>>,
    /// Where enrolments waiting for a first code are kept; a file beside `source`
    /// (`<path>.pending`) when that is a file, else memory.
    pub pending: Option<Source<Format>>,
    /// The name an authenticator app shows beside the account.
    pub issuer: Option<String>,
    /// The hash new secrets use: `sha1` (every app reads it), `sha256` or `sha512`.
    #[map(default)]
    pub algorithm: Algorithm,
    /// Digits of a code, 6 to 8.
    #[map(default = DEFAULT_DIGITS)]
    pub digits: u32,
    /// Seconds a code lasts.
    #[map(default = DEFAULT_PERIOD)]
    pub period: u32,
    /// Steps either side of the present one a code is accepted in, at most 10.
    #[map(default = DEFAULT_SKEW)]
    pub skew: u32,
    /// Recovery codes made at enrolment, at most 64.
    #[map(default = DEFAULT_RECOVERY_CODES)]
    pub recovery_codes: u32,
    /// Seconds an enrolment waits for its first code.
    #[map(default = DEFAULT_ENROL_SECONDS)]
    pub enrol_seconds: u32,
    /// The most accounts, and the most enrolments waiting, the tables may hold.
    #[map(default = DEFAULT_MAX_RECORDS as u32)]
    pub max_records: u32,
    /// How large a record's fields may be: `groups`, `field_bytes`, `email_bytes`,
    /// `display_name_bytes`, each a number or `none` for no bound.
    #[map(default)]
    pub record_limits: RecordLimits,
}

impl Default for TotpConfig {
    /// What an empty configuration reads as: every default the schema declares.
    fn default() -> Self {
        Partial::new()
            .build()
            .expect("an empty configuration reads, every key having a default")
    }
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
            .map_err(|reason| reason.writing("one-time code table")),
        None => Ok(Arc::new(MemoryTable::new())),
    }
}

/// The one-time code provider a host loads.
#[derive(Debug, Provider)]
#[provider(
    Authenticator,
    Accounts,
    id = "coqui_access_totp",
    name = "One-time codes",
    config = Described<TotpConfig>,
    crate = ::coqui_access::guatiao
)]
pub struct TotpProvider(TotpAccounts);

impl TryFrom<TotpConfig> for TotpProvider {
    type Error = ProviderError;

    fn try_from(config: TotpConfig) -> Result<Self, Self::Error> {
        let pending_source = config.pending.clone().or_else(|| {
            config
                .source
                .as_ref()
                .map(|source| source.sibling("pending"))
        });
        let mut builder = TotpAccounts::builder()
            .table(open::<TotpRecord>(config.source.as_ref(), "accounts")?)
            .pending(open::<PendingTotp>(pending_source.as_ref(), "pending")?)
            .algorithm(config.algorithm)
            .digits(config.digits)
            .period(config.period)
            .skew(config.skew)
            .recovery_codes(config.recovery_codes)
            .enrol_seconds(config.enrol_seconds)
            .max_records(config.max_records as usize)
            .record_limits(config.record_limits);
        if let Some(issuer) = config.issuer {
            builder = builder.issuer(issuer);
        }
        builder
            .build()
            .map(Self)
            .map_err(|reason| reason.writing("one-time code table"))
    }
}

impl TryFrom<Described<TotpConfig>> for TotpProvider {
    type Error = ProviderError;

    fn try_from(config: Described<TotpConfig>) -> Result<Self, Self::Error> {
        Self::try_from(config.0)
    }
}

impl Authenticator for TotpProvider {
    fn authenticate(&self, attempt: Attempt) -> Result<Verdict, ProviderError> {
        self.0.authenticate(attempt)
    }

    fn describe(&self) -> Result<Description, ProviderError> {
        Authenticator::describe(&self.0)
    }
}

impl Accounts for TotpProvider {
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

coqui_access::guatiao::providers!(TotpProvider);

#[cfg(test)]
mod tests {
    use super::*;

    fn config(path: &std::path::Path) -> TotpConfig {
        TotpConfig {
            source: Some(Source::file(path.to_str().unwrap(), Format::Toml)),
            ..TotpConfig::default()
        }
    }

    fn begin(provider: &TotpProvider, name: &str) -> PutOutcome {
        provider
            .put(AccountPut {
                name: name.to_owned(),
                ..AccountPut::default()
            })
            .unwrap()
    }

    #[test]
    fn a_file_source_keeps_accounts_and_enrolments_beside_it() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("totp.toml");
        let provider = TotpProvider::try_from(config(&path)).unwrap();
        let begun = begin(&provider, "id-alice");
        let pending = directory.path().join("totp.toml.pending");
        let text = std::fs::read_to_string(&pending).unwrap();
        assert!(text.contains("[[pending]]"), "{text}");
        // Neither the link, the secret nor a recovery code is written as itself in the
        // recovery digests.
        let first = begun.codes.unwrap().remove(0);
        assert!(!text.contains(&first) && !text.contains(&first.replace('-', "")));
        // A second provider over the same files sees the enrolment waiting.
        let other = TotpProvider::try_from(config(&path)).unwrap();
        assert_eq!(other.waiting().unwrap().len(), 1);
        assert!(other.accounts().unwrap().is_empty());
    }

    #[test]
    fn a_hand_written_file_with_a_bad_secret_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("totp.toml");
        std::fs::write(
            &path,
            "[[accounts]]\nname='id-alice'\nsecret='!!!'\nalgorithm='sha1'\ndigits=6\nperiod=30\n",
        )
        .unwrap();
        assert!(TotpProvider::try_from(config(&path)).is_err());
    }

    #[test]
    fn no_source_is_memory_and_the_defaults_read() {
        let provider = TotpProvider::try_from(TotpConfig::default()).unwrap();
        let begun = begin(&provider, "id-bob");
        assert_eq!(begun.codes.unwrap().len(), 10);
        let defaults = TotpConfig::default();
        assert_eq!(
            (defaults.digits, defaults.period, defaults.skew),
            (6, 30, 1)
        );
    }

    #[test]
    fn a_setting_out_of_range_does_not_build() {
        let bad = TotpConfig {
            digits: 12,
            ..TotpConfig::default()
        };
        assert!(TotpProvider::try_from(bad).is_err());
    }
}
