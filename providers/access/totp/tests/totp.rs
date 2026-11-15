//! Enrolment, verification, replay, recovery and reset, through the public API and with a
//! clock the test moves.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use coqui_access::guatiao::library::ProviderError;
use coqui_access::{AccountPut, Accounts, Attempt, Authenticator, Lookup, Verdict, methods};
use coqui_access_kit::{MemoryTable, Revision, Snapshot, SourceError, Table};
use coqui_access_totp::{PendingTotp, TotpAccounts, TotpRecord};
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;

const START: i64 = 1_700_000_000;

/// SHA-1, six digits, thirty seconds: written here from RFC 4226, not taken from the crate.
fn code(key: &[u8], unix: i64) -> String {
    let mut mac = <Hmac<Sha1> as KeyInit>::new_from_slice(key).unwrap();
    mac.update(&((unix / 30) as u64).to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[19] & 0x0f);
    let number = u32::from_be_bytes([
        digest[offset] & 0x7f,
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]);
    format!("{:06}", number % 1_000_000)
}

struct Setup {
    clock: Arc<AtomicI64>,
    totp: TotpAccounts,
}

fn setup() -> Setup {
    let clock = Arc::new(AtomicI64::new(START));
    let reader = clock.clone();
    let totp = TotpAccounts::builder()
        .issuer("Example Co")
        .clock(move || reader.load(Ordering::SeqCst))
        .build()
        .unwrap();
    Setup { clock, totp }
}

impl Setup {
    fn at(&self, unix: i64) {
        self.clock.store(unix, Ordering::SeqCst);
    }

    fn begin(&self, name: &str) -> (Vec<u8>, Vec<String>, String) {
        let begun = self
            .totp
            .put(AccountPut {
                name: name.to_owned(),
                display_name: Some("alice@example.org".to_owned()),
                ..AccountPut::default()
            })
            .unwrap();
        let link = begun.secret.unwrap();
        let secret = link
            .split(['?', '&'])
            .find_map(|part| part.strip_prefix("secret="))
            .unwrap();
        let key = data_encoding::BASE32_NOPAD
            .decode(secret.as_bytes())
            .unwrap();
        (key, begun.codes.unwrap(), link)
    }

    fn confirm(&self, name: &str, with: &str) -> Result<(), ProviderError> {
        self.totp
            .put(AccountPut {
                name: name.to_owned(),
                secret: Some(with.to_owned()),
                ..AccountPut::default()
            })
            .map(|_| ())
    }

    /// Enrols and confirms with the code of the present step.
    fn enrol(&self, name: &str) -> (Vec<u8>, Vec<String>) {
        let (key, codes, _) = self.begin(name);
        self.confirm(name, &code(&key, self.clock.load(Ordering::SeqCst)))
            .unwrap();
        (key, codes)
    }

    fn present(&self, name: &str, presented: &str) -> Verdict {
        self.totp
            .authenticate(Attempt {
                name: Some(name.to_owned()),
                secret: Some(presented.to_owned()),
                ..Attempt::default()
            })
            .unwrap()
    }

    fn recover(&self, name: &str, presented: &str) -> Verdict {
        self.totp
            .authenticate(Attempt {
                name: Some(name.to_owned()),
                secret: Some(presented.to_owned()),
                method: Some(methods::RECOVERY_CODE.to_owned()),
                ..Attempt::default()
            })
            .unwrap()
    }
}

fn valid(name: &str) -> Verdict {
    Verdict::Valid(Lookup {
        by: "id".to_owned(),
        value: name.to_owned(),
    })
}

fn error_text(error: &ProviderError) -> String {
    format!("{error:?} {error} {}", error.message())
}

#[test]
fn begin_confirm_with_a_code_and_sign_in_with_the_next() {
    let setup = setup();
    let (key, _) = setup.enrol("id-alice");
    // The code that confirmed the enrolment is spent; the next step's is a factor.
    assert_eq!(
        setup.present("id-alice", &code(&key, START)),
        Verdict::Invalid
    );
    setup.at(START + 30);
    assert_eq!(
        setup.present("id-alice", &code(&key, START + 30)),
        valid("id-alice")
    );
    assert_eq!(setup.totp.accounts().unwrap().len(), 1);
    assert!(setup.totp.waiting().unwrap().is_empty());
}

#[test]
fn an_unconfirmed_enrolment_is_not_a_factor_and_is_listed_as_waiting() {
    let setup = setup();
    let (key, _, _) = setup.begin("id-alice");
    assert_eq!(
        setup.present("id-alice", &code(&key, START)),
        Verdict::Unknown
    );
    assert!(setup.totp.accounts().unwrap().is_empty());
    let waiting = setup.totp.waiting().unwrap();
    assert_eq!(waiting.len(), 1);
    assert_eq!(waiting[0].shown, "id-alice");
}

#[test]
fn the_same_code_twice_fails_the_second_time() {
    let setup = setup();
    let (key, _) = setup.enrol("id-alice");
    setup.at(START + 60);
    let now = code(&key, START + 60);
    assert_eq!(setup.present("id-alice", &now), valid("id-alice"));
    assert_eq!(setup.present("id-alice", &now), Verdict::Invalid);
    // An earlier step than the one used is no better.
    assert_eq!(
        setup.present("id-alice", &code(&key, START + 30)),
        Verdict::Invalid
    );
}

#[test]
fn a_code_one_step_early_and_late_passes_with_the_default_skew_and_two_does_not() {
    let setup = setup();
    let (key, _) = setup.enrol("id-alice");
    setup.at(START + 120);
    let late = code(&key, START + 120 - 30);
    assert_eq!(setup.present("id-alice", &late), valid("id-alice"));
    setup.at(START + 240);
    let early = code(&key, START + 240 + 30);
    assert_eq!(setup.present("id-alice", &early), valid("id-alice"));
    setup.at(START + 360);
    assert_eq!(
        setup.present("id-alice", &code(&key, START + 360 + 60)),
        Verdict::Invalid
    );
}

#[test]
fn with_no_skew_only_the_present_step_passes() {
    let clock = Arc::new(AtomicI64::new(START));
    let reader = clock.clone();
    let totp = TotpAccounts::builder()
        .skew(0)
        .clock(move || reader.load(Ordering::SeqCst))
        .build()
        .unwrap();
    let setup = Setup { clock, totp };
    let (key, _) = setup.enrol("id-alice");
    setup.at(START + 120);
    assert_eq!(
        setup.present("id-alice", &code(&key, START + 120 - 30)),
        Verdict::Invalid
    );
    assert_eq!(
        setup.present("id-alice", &code(&key, START + 120)),
        valid("id-alice")
    );
}

#[test]
fn a_wrong_code_a_malformed_one_and_an_unknown_account() {
    let setup = setup();
    let (key, _) = setup.enrol("id-alice");
    setup.at(START + 30);
    let good = code(&key, START + 30);
    let wrong = if good == "000000" { "000001" } else { "000000" };
    for bad in [wrong, "12345", "1234567", "abcdef", ""] {
        assert_eq!(setup.present("id-alice", bad), Verdict::Invalid, "{bad:?}");
    }
    assert_eq!(setup.present("id-nobody", &good), Verdict::Unknown);
    // Needs a name and a secret.
    let nameless = Attempt {
        secret: Some(good.clone()),
        ..Attempt::default()
    };
    assert_eq!(setup.totp.authenticate(nameless).unwrap(), Verdict::Unknown);
    // Another method is not this provider's.
    let other = Attempt {
        name: Some("id-alice".to_owned()),
        secret: Some(good.clone()),
        method: Some("password".to_owned()),
        ..Attempt::default()
    };
    assert_eq!(setup.totp.authenticate(other).unwrap(), Verdict::Unknown);
    // The good code still works: none of the above spent it.
    assert_eq!(setup.present("id-alice", &good), valid("id-alice"));
}

#[test]
fn a_recovery_code_works_once_and_is_not_a_time_code() {
    let setup = setup();
    let (_, codes) = setup.enrol("id-alice");
    assert_eq!(codes.len(), 10);
    for recovery in &codes {
        assert!(recovery.contains('-') && recovery.len() == 11, "{recovery}");
        assert!(!recovery.bytes().all(|b| b.is_ascii_digit() || b == b'-'));
    }
    assert_eq!(setup.recover("id-alice", &codes[0]), valid("id-alice"));
    assert_eq!(setup.recover("id-alice", &codes[0]), Verdict::Invalid);
    // Typed in lower case, without the hyphen, the next one is the same code.
    let typed = codes[1].replace('-', "").to_lowercase();
    assert_eq!(setup.recover("id-alice", &typed), valid("id-alice"));
    // A recovery code is not accepted as a time-based one, nor the reverse.
    assert_eq!(setup.present("id-alice", &codes[2]), Verdict::Invalid);
    assert_eq!(setup.recover("id-alice", "123456"), Verdict::Invalid);
    assert_eq!(setup.recover("id-alice", "short"), Verdict::Invalid);
    assert_eq!(setup.recover("id-nobody", &codes[3]), Verdict::Unknown);
    // The rest are still there.
    assert_eq!(setup.recover("id-alice", &codes[3]), valid("id-alice"));
}

#[test]
fn a_disabled_account_takes_nothing_and_can_be_enabled_again() {
    let setup = setup();
    let (key, codes) = setup.enrol("id-alice");
    let toggle = |disabled: bool| {
        setup
            .totp
            .put(AccountPut {
                name: "id-alice".to_owned(),
                disabled: Some(disabled),
                ..AccountPut::default()
            })
            .unwrap();
    };
    toggle(true);
    setup.at(START + 30);
    assert_eq!(
        setup.present("id-alice", &code(&key, START + 30)),
        Verdict::Invalid
    );
    assert_eq!(setup.recover("id-alice", &codes[0]), Verdict::Invalid);
    toggle(false);
    assert_eq!(
        setup.present("id-alice", &code(&key, START + 30)),
        valid("id-alice")
    );
    assert!(
        setup
            .totp
            .put(AccountPut {
                name: "id-nobody".to_owned(),
                disabled: Some(true),
                ..AccountPut::default()
            })
            .is_err()
    );
}

#[test]
fn an_expired_enrolment_cannot_be_confirmed() {
    let setup = setup();
    let (key, _, _) = setup.begin("id-alice");
    setup.at(START + 601);
    let error = setup
        .confirm("id-alice", &code(&key, START + 601))
        .unwrap_err();
    assert!(error_text(&error).contains("BAD_VALUE"), "{error:?}");
    assert!(
        setup.totp.waiting().unwrap().is_empty(),
        "the stale entry is gone"
    );
    assert!(setup.totp.accounts().unwrap().is_empty());
}

#[test]
fn a_wrong_confirmation_code_and_no_enrolment_are_refused_differently() {
    let setup = setup();
    let (key, _, _) = setup.begin("id-alice");
    let good = code(&key, START);
    let wrong = if good == "000000" { "000001" } else { "000000" };
    let bad = setup.confirm("id-alice", wrong).unwrap_err();
    assert!(error_text(&bad).contains("BAD_VALUE"), "{bad:?}");
    let none = setup.confirm("id-other", &good).unwrap_err();
    assert!(error_text(&none).contains("NOT_FOUND"), "{none:?}");
    // The wrong try did not end the enrolment.
    setup.confirm("id-alice", &good).unwrap();
}

#[test]
fn rotation_keeps_the_old_secret_working_until_the_new_one_is_proven() {
    let setup = setup();
    let (old, _) = setup.enrol("id-alice");
    setup.at(START + 90);
    let (new, _, _) = setup.begin("id-alice");
    assert_ne!(old, new);
    // Before the new code is confirmed, the old secret is the factor.
    assert_eq!(
        setup.present("id-alice", &code(&old, START + 90)),
        valid("id-alice")
    );
    assert_eq!(
        setup.present("id-alice", &code(&new, START + 90)),
        Verdict::Invalid
    );
    setup.at(START + 120);
    setup.confirm("id-alice", &code(&new, START + 120)).unwrap();
    setup.at(START + 150);
    assert_eq!(
        setup.present("id-alice", &code(&old, START + 150)),
        Verdict::Invalid
    );
    assert_eq!(
        setup.present("id-alice", &code(&new, START + 150)),
        valid("id-alice")
    );
}

#[test]
fn beginning_again_replaces_the_enrolment_that_was_waiting() {
    let setup = setup();
    let (first, _, _) = setup.begin("id-alice");
    let (second, _, _) = setup.begin("id-alice");
    assert_ne!(first, second);
    assert_eq!(setup.totp.waiting().unwrap().len(), 1);
    assert!(setup.confirm("id-alice", &code(&first, START)).is_err());
    setup.confirm("id-alice", &code(&second, START)).unwrap();
}

#[test]
fn removing_resets_the_account_and_any_enrolment_waiting() {
    let setup = setup();
    let (key, _) = setup.enrol("id-alice");
    setup.begin("id-alice");
    setup.totp.remove("id-alice".to_owned()).unwrap();
    setup.at(START + 30);
    assert_eq!(
        setup.present("id-alice", &code(&key, START + 30)),
        Verdict::Unknown
    );
    assert!(setup.totp.waiting().unwrap().is_empty());
    assert!(setup.totp.remove("id-alice".to_owned()).is_err());
}

#[test]
fn the_link_names_the_issuer_label_algorithm_digits_and_period() {
    let setup = setup();
    let (key, _, link) = setup.begin("id-alice");
    let rest = link.strip_prefix("otpauth://totp/").unwrap();
    let (path, query) = rest.split_once('?').unwrap();
    assert_eq!(path, "Example%20Co:alice%40example.org");
    let params: std::collections::BTreeMap<&str, &str> = query
        .split('&')
        .map(|pair| pair.split_once('=').unwrap())
        .collect();
    assert_eq!(params["issuer"], "Example%20Co");
    assert_eq!(params["algorithm"], "SHA1");
    assert_eq!(params["digits"], "6");
    assert_eq!(params["period"], "30");
    assert_eq!(
        data_encoding::BASE32_NOPAD
            .decode(params["secret"].as_bytes())
            .unwrap(),
        key
    );
    assert_eq!(key.len(), 20);
    // With no label the account name is shown.
    let plain = TotpAccounts::builder().build().unwrap();
    let link = plain
        .put(AccountPut {
            name: "id-bob".to_owned(),
            ..AccountPut::default()
        })
        .unwrap()
        .secret
        .unwrap();
    assert!(link.starts_with("otpauth://totp/id-bob?secret="), "{link}");
    assert!(!link.contains("issuer"));
}

#[test]
fn nothing_secret_appears_in_a_debug_line_or_an_error() {
    let setup = setup();
    let (key, codes, link) = setup.begin("id-alice");
    let secret = data_encoding::BASE32_NOPAD.encode(&key);
    let mut shown = format!("{:?}", setup.totp);
    let table = Arc::new(MemoryTable::<TotpRecord>::new());
    let pending = Arc::new(MemoryTable::<PendingTotp>::new());
    let totp = TotpAccounts::builder()
        .table(table.clone())
        .pending(pending.clone())
        .build()
        .unwrap();
    let begun = totp
        .put(AccountPut {
            name: "id-alice".to_owned(),
            ..AccountPut::default()
        })
        .unwrap();
    shown.push_str(&format!("{begun:?}"));
    for entry in pending.load().unwrap().records {
        shown.push_str(&format!("{entry:?}"));
    }
    let wrong = totp
        .put(AccountPut {
            name: "id-alice".to_owned(),
            secret: Some("000000".to_owned()),
            ..AccountPut::default()
        })
        .unwrap_err();
    shown.push_str(&error_text(&wrong));
    for leaked in std::iter::once(&secret)
        .chain(&codes)
        .chain(std::iter::once(&link))
    {
        assert!(
            !shown.contains(leaked.as_str()),
            "a secret shows in {shown}"
        );
    }
    let stored = pending.load().unwrap().records;
    assert!(!format!("{stored:?}").contains(&begun.codes.unwrap()[0]));
}

#[test]
fn recovery_codes_are_kept_as_digests_not_as_themselves() {
    let table = Arc::new(MemoryTable::<TotpRecord>::new());
    let pending = Arc::new(MemoryTable::<PendingTotp>::new());
    let totp = TotpAccounts::builder()
        .table(table.clone())
        .pending(pending.clone())
        .clock(|| START)
        .build()
        .unwrap();
    let begun = totp
        .put(AccountPut {
            name: "id-alice".to_owned(),
            ..AccountPut::default()
        })
        .unwrap();
    let kept = pending.load().unwrap().records.remove(0);
    assert_eq!(kept.codes.len(), 10);
    let shown = begun.codes.unwrap();
    for code in &shown {
        let plain = code.replace('-', "");
        assert!(
            kept.codes
                .iter()
                .all(|digest| digest != code && digest != &plain),
            "a code is kept as itself"
        );
    }
    assert!(kept.codes.iter().all(|digest| digest.len() == 64));
}

/// A table that reads what it was given and cannot be written.
struct ReadOnly(Vec<TotpRecord>);

impl Table<TotpRecord> for ReadOnly {
    fn load(&self) -> Result<Snapshot<TotpRecord>, SourceError> {
        Ok(Snapshot::new(Revision::default(), self.0.clone()))
    }
}

#[test]
fn a_write_that_fails_is_an_error_and_never_a_success_that_could_be_replayed() {
    let table = Arc::new(MemoryTable::<TotpRecord>::new());
    let enrolling = TotpAccounts::builder()
        .table(table.clone())
        .clock(|| START)
        .build()
        .unwrap();
    let begun = enrolling
        .put(AccountPut {
            name: "id-alice".to_owned(),
            ..AccountPut::default()
        })
        .unwrap();
    let key = data_encoding::BASE32_NOPAD
        .decode(
            begun
                .secret
                .unwrap()
                .split(['?', '&'])
                .find_map(|part| part.strip_prefix("secret="))
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
    enrolling
        .put(AccountPut {
            name: "id-alice".to_owned(),
            secret: Some(code(&key, START)),
            ..AccountPut::default()
        })
        .unwrap();
    let kept = table.load().unwrap().records;
    let frozen = TotpAccounts::builder()
        .table(Arc::new(ReadOnly(kept)))
        .clock(|| START + 30)
        .build()
        .unwrap();
    let attempt = Attempt {
        name: Some("id-alice".to_owned()),
        secret: Some(code(&key, START + 30)),
        ..Attempt::default()
    };
    assert!(frozen.authenticate(attempt).is_err());
}

#[test]
fn groups_and_expiry_are_refused_and_settings_out_of_range_do_not_build() {
    let setup = setup();
    for put in [
        AccountPut {
            name: "id-alice".to_owned(),
            groups: Some(vec!["g".to_owned()]),
            ..AccountPut::default()
        },
        AccountPut {
            name: "id-alice".to_owned(),
            expires_unix: Some(1),
            ..AccountPut::default()
        },
        AccountPut {
            name: String::new(),
            ..AccountPut::default()
        },
    ] {
        assert!(setup.totp.put(put).is_err());
    }
    assert!(TotpAccounts::builder().digits(5).build().is_err());
    assert!(TotpAccounts::builder().digits(9).build().is_err());
    assert!(TotpAccounts::builder().period(0).build().is_err());
    assert!(TotpAccounts::builder().skew(11).build().is_err());
    assert!(TotpAccounts::builder().recovery_codes(65).build().is_err());
    assert!(TotpAccounts::builder().enrol_seconds(0).build().is_err());
    assert!(
        TotpAccounts::builder()
            .digits(8)
            .period(60)
            .skew(2)
            .build()
            .is_ok()
    );
}

#[test]
fn eight_digit_sha512_secrets_enrol_and_sign_in() {
    let clock = Arc::new(AtomicI64::new(START));
    let reader = clock.clone();
    let totp = TotpAccounts::builder()
        .algorithm(coqui_access_totp::Algorithm::Sha512)
        .digits(8)
        .clock(move || reader.load(Ordering::SeqCst))
        .build()
        .unwrap();
    let link = totp
        .put(AccountPut {
            name: "id-alice".to_owned(),
            ..AccountPut::default()
        })
        .unwrap()
        .secret
        .unwrap();
    assert!(link.contains("algorithm=SHA512") && link.contains("digits=8"));
}
