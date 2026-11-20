//! Signing in with a passkey: the challenge, the signed answer, and what each check refuses.
//! Every negative case is a signature the real credential made, so the refusal is the
//! provider's and not the authenticator's.

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use coqui_access::guatiao::Status;
use coqui_access::guatiao::library::ProviderError;
use coqui_access::{
    AccountPut, Accounts, Attempt, Authenticator, Challenge, ChallengeRequest, Challenger, Verdict,
    error,
};
use coqui_access_kit::{MemoryTable, Revision, Snapshot, SourceError, Table};
use coqui_access_passkey::{
    Ceremony, OnRegression, PasskeyAccount, Passkeys, PasskeysBuilder, UserVerification,
};
use support::{Device, ORIGIN, RP_ID, challenge_of, client_data};

const START: i64 = 1_700_000_000;

struct Fixture {
    clock: Arc<AtomicI64>,
    passkeys: Passkeys,
    table: Arc<MemoryTable<PasskeyAccount>>,
    ceremonies: Arc<MemoryTable<Ceremony>>,
}

fn fixture_with(configure: impl FnOnce(PasskeysBuilder) -> PasskeysBuilder) -> Fixture {
    let clock = Arc::new(AtomicI64::new(START));
    let reader = clock.clone();
    let table = Arc::new(MemoryTable::<PasskeyAccount>::new());
    let ceremonies = Arc::new(MemoryTable::<Ceremony>::new());
    let builder = Passkeys::builder()
        .rp_id(RP_ID)
        .origin(ORIGIN)
        .table(table.clone())
        .ceremonies(ceremonies.clone())
        .clock(move || reader.load(Ordering::SeqCst));
    Fixture {
        clock,
        passkeys: configure(builder).build().unwrap(),
        table,
        ceremonies,
    }
}

fn fixture() -> Fixture {
    fixture_with(|builder| builder)
}

/// The options with the person not asked to be verified.
fn without_verification(options: &str) -> String {
    let mut value: serde_json::Value = serde_json::from_str(options).unwrap();
    if let Some(selection) = value["publicKey"].get_mut("authenticatorSelection") {
        selection["userVerification"] = "discouraged".into();
    }
    if let Some(public_key) = value["publicKey"].as_object_mut()
        && public_key.contains_key("userVerification")
    {
        public_key.insert("userVerification".to_owned(), "discouraged".into());
    }
    value.to_string()
}

impl Fixture {
    fn at(&self, unix: i64) {
        self.clock.store(unix, Ordering::SeqCst);
    }

    /// Registers `name` with `device`, the way a person does.
    async fn enrol(&self, name: &str, device: &mut Device) {
        self.enrol_as(name, device, false).await;
    }

    async fn enrol_as(&self, name: &str, device: &mut Device, unverified: bool) {
        let mut options = self
            .passkeys
            .put(AccountPut {
                name: name.to_owned(),
                ..AccountPut::default()
            })
            .unwrap()
            .secret
            .unwrap();
        if unverified {
            options = without_verification(&options);
        }
        let answer = device.register(ORIGIN, &options).await.unwrap();
        self.passkeys
            .put(AccountPut {
                name: name.to_owned(),
                secret: Some(answer),
                ..AccountPut::default()
            })
            .unwrap();
    }

    fn id_of(&self, name: &str) -> String {
        self.passkeys
            .accounts()
            .unwrap()
            .into_iter()
            .find(|account| account.name == name)
            .unwrap()
            .id
    }

    fn challenge(
        &self,
        name: Option<&str>,
        peer: Option<&str>,
    ) -> Result<Challenge, ProviderError> {
        self.passkeys.challenge(ChallengeRequest {
            method: Some("passkey".to_owned()),
            name: name.map(str::to_owned),
            peer: peer.map(str::to_owned),
        })
    }

    fn present(&self, challenge: &str, answer: &str) -> Verdict {
        self.passkeys
            .authenticate(Attempt {
                method: Some("passkey".to_owned()),
                challenge: Some(challenge.to_owned()),
                secret: Some(answer.to_owned()),
                ..Attempt::default()
            })
            .unwrap()
    }

    /// A whole sign-in: the challenge, the device's answer and its presentation.
    async fn sign_in(&self, device: &mut Device, name: Option<&str>) -> Verdict {
        let challenge = self.challenge(name, None).unwrap();
        let answer = device
            .authenticate(ORIGIN, &challenge.options)
            .await
            .unwrap();
        self.present(&challenge.challenge, &answer)
    }

    fn is_valid_for(&self, verdict: &Verdict, name: &str) -> bool {
        matches!(verdict, Verdict::Valid(lookup) if lookup.by == "id" && lookup.value == self.id_of(name))
    }
}

fn status(error: &ProviderError) -> Status {
    error.status
}

#[tokio::test]
async fn a_discoverable_sign_in_names_nobody_and_a_named_one_lists_the_passkeys() {
    let fixture = fixture();
    let mut device = Device::new();
    fixture.enrol("alice", &mut device).await;
    fixture.at(START + 10);

    let open = fixture.challenge(None, Some("192.0.2.7:4000")).unwrap();
    assert_eq!(open.expires_unix, START + 10 + 300);
    let value: serde_json::Value = serde_json::from_str(&open.options).unwrap();
    assert_eq!(value["publicKey"]["userVerification"], "required");
    assert!(
        value["publicKey"]["allowCredentials"]
            .as_array()
            .is_none_or(Vec::is_empty)
    );
    assert_eq!(open.challenge, challenge_of(&open.options));
    let answer = device.authenticate(ORIGIN, &open.options).await.unwrap();
    let verdict = fixture.present(&open.challenge, &answer);
    assert!(fixture.is_valid_for(&verdict, "alice"), "{verdict:?}");
    let Verdict::Valid(lookup) = verdict else {
        unreachable!()
    };
    let claims = lookup.claims.unwrap();
    assert_eq!(claims.get("passkey.user_verified"), ["true"]);
    // The software authenticator is backup eligible, as a platform passkey is.
    assert_eq!(claims.get("passkey.synced"), ["true"]);
    assert_eq!(claims.get("passkey.credential").len(), 1);

    let named = fixture.challenge(Some("alice"), None).unwrap();
    let value: serde_json::Value = serde_json::from_str(&named.options).unwrap();
    assert_eq!(
        value["publicKey"]["allowCredentials"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let answer = device.authenticate(ORIGIN, &named.options).await.unwrap();
    let verdict = fixture.present(&named.challenge, &answer);
    assert!(fixture.is_valid_for(&verdict, "alice"), "{verdict:?}");

    // The last use is written down.
    let used = fixture.passkeys.accounts().unwrap()[0]
        .credentials
        .as_ref()
        .unwrap()[0]
        .used_unix;
    assert_eq!(used, Some(START + 10));
}

#[tokio::test]
async fn the_same_answer_twice_is_unknown_the_second_time() {
    let fixture = fixture();
    let mut device = Device::new();
    fixture.enrol("alice", &mut device).await;
    let challenge = fixture.challenge(None, None).unwrap();
    let answer = device
        .authenticate(ORIGIN, &challenge.options)
        .await
        .unwrap();
    assert!(fixture.is_valid_for(&fixture.present(&challenge.challenge, &answer), "alice"));
    assert_eq!(
        fixture.present(&challenge.challenge, &answer),
        Verdict::Unknown
    );
}

#[tokio::test]
async fn an_answer_for_one_challenge_presented_with_another_is_invalid_and_leaves_the_other() {
    let fixture = fixture();
    let mut device = Device::new();
    fixture.enrol("alice", &mut device).await;
    let first = fixture.challenge(None, None).unwrap();
    let second = fixture.challenge(None, None).unwrap();
    let answer = device.authenticate(ORIGIN, &first.options).await.unwrap();
    assert_eq!(
        fixture.present(&second.challenge, &answer),
        Verdict::Invalid
    );
    // The challenge it was made for is untouched, and the one it was wrongly given is spent.
    assert_eq!(
        fixture.present(&second.challenge, &answer),
        Verdict::Unknown
    );
    assert!(fixture.is_valid_for(&fixture.present(&first.challenge, &answer), "alice"));
}

#[tokio::test]
async fn an_expired_challenge_is_invalid_and_one_not_issued_here_is_unknown() {
    let fixture = fixture();
    let mut device = Device::new();
    fixture.enrol("alice", &mut device).await;
    let challenge = fixture.challenge(None, None).unwrap();
    let answer = device
        .authenticate(ORIGIN, &challenge.options)
        .await
        .unwrap();
    fixture.at(START + 301);
    assert_eq!(
        fixture.present(&challenge.challenge, &answer),
        Verdict::Invalid
    );
    assert_eq!(
        fixture.present(&challenge.challenge, &answer),
        Verdict::Unknown
    );
    assert_eq!(fixture.present("never-issued", &answer), Verdict::Unknown);
    // Without a challenge or an answer, or presented as another method, it is not for this provider.
    for attempt in [
        Attempt {
            secret: Some(answer.clone()),
            ..Attempt::default()
        },
        Attempt {
            challenge: Some(challenge.challenge.clone()),
            ..Attempt::default()
        },
        Attempt {
            method: Some("totp".to_owned()),
            challenge: Some(challenge.challenge.clone()),
            secret: Some(answer.clone()),
            ..Attempt::default()
        },
    ] {
        assert_eq!(
            fixture.passkeys.authenticate(attempt).unwrap(),
            Verdict::Unknown
        );
    }
}

/// A fixture, its device and one fresh challenge with its options.
async fn ready(
    configure: impl FnOnce(PasskeysBuilder) -> PasskeysBuilder,
) -> (Fixture, Device, Challenge) {
    let fixture = fixture_with(configure);
    let mut device = Device::new();
    fixture.enrol("alice", &mut device).await;
    let challenge = fixture.challenge(None, None).unwrap();
    (fixture, device, challenge)
}

#[tokio::test]
async fn an_origin_that_is_not_the_relying_partys_is_refused_whoever_signed() {
    // The control: the same raw signing with the right origin signs in.
    let (fixture, mut device, challenge) = ready(|builder| builder).await;
    let good = client_data("webauthn.get", &challenge.challenge, ORIGIN, false);
    let answer = device.raw_assertion(RP_ID, &good, &[]).await.unwrap();
    assert!(fixture.is_valid_for(&fixture.present(&challenge.challenge, &answer), "alice"));

    let challenge = fixture.challenge(None, None).unwrap();
    let evil = client_data(
        "webauthn.get",
        &challenge.challenge,
        "https://evil.example",
        false,
    );
    let answer = device.raw_assertion(RP_ID, &evil, &[]).await.unwrap();
    assert_eq!(
        fixture.present(&challenge.challenge, &answer),
        Verdict::Invalid
    );
}

#[tokio::test]
async fn a_subdomain_origin_is_refused_unless_subdomains_are_allowed() {
    let (fixture, mut device, challenge) = ready(|builder| builder).await;
    let answer = device
        .authenticate("https://sub.portal.example", &challenge.options)
        .await
        .unwrap();
    assert_eq!(
        fixture.present(&challenge.challenge, &answer),
        Verdict::Invalid
    );

    let (fixture, mut device, challenge) = ready(|builder| builder.allow_subdomains(true)).await;
    let answer = device
        .authenticate("https://sub.portal.example", &challenge.options)
        .await
        .unwrap();
    assert!(fixture.is_valid_for(&fixture.present(&challenge.challenge, &answer), "alice"));
    assert!(
        fixture
            .passkeys
            .non_defaults()
            .iter()
            .any(|setting| setting.setting == "allow_subdomains")
    );
}

#[tokio::test]
async fn a_cross_origin_answer_and_a_registration_answer_are_refused() {
    let (fixture, mut device, challenge) = ready(|builder| builder).await;
    let crossed = client_data("webauthn.get", &challenge.challenge, ORIGIN, true);
    let answer = device.raw_assertion(RP_ID, &crossed, &[]).await.unwrap();
    assert_eq!(
        fixture.present(&challenge.challenge, &answer),
        Verdict::Invalid
    );

    let challenge = fixture.challenge(None, None).unwrap();
    let created = client_data("webauthn.create", &challenge.challenge, ORIGIN, false);
    let answer = device.raw_assertion(RP_ID, &created, &[]).await.unwrap();
    assert_eq!(
        fixture.present(&challenge.challenge, &answer),
        Verdict::Invalid
    );
}

#[tokio::test]
async fn an_answer_signed_for_another_relying_party_is_refused() {
    let (fixture, mut device, challenge) = ready(|builder| builder).await;
    device.store.ignore_rp(true);
    let data = client_data("webauthn.get", &challenge.challenge, ORIGIN, false);
    let answer = device
        .raw_assertion("other.example", &data, &[])
        .await
        .unwrap();
    assert_eq!(
        fixture.present(&challenge.challenge, &answer),
        Verdict::Invalid
    );
}

#[tokio::test]
async fn an_answer_that_did_not_verify_the_person_needs_user_verification_not_required() {
    let (fixture, mut device, challenge) = ready(|builder| builder).await;
    let options = without_verification(&challenge.options);
    let answer = device.authenticate(ORIGIN, &options).await.unwrap();
    assert_eq!(
        fixture.present(&challenge.challenge, &answer),
        Verdict::Invalid
    );

    // Under preferred, a passkey registered without verification signs in without it, and the
    // claim says so.
    let fixture = fixture_with(|builder| builder.user_verification(UserVerification::Preferred));
    let mut device = Device::new();
    fixture.enrol_as("alice", &mut device, true).await;
    let challenge = fixture.challenge(None, None).unwrap();
    let options = without_verification(&challenge.options);
    let answer = device.authenticate(ORIGIN, &options).await.unwrap();
    let verdict = fixture.present(&challenge.challenge, &answer);
    assert!(fixture.is_valid_for(&verdict, "alice"), "{verdict:?}");
    let Verdict::Valid(lookup) = verdict else {
        unreachable!()
    };
    assert_eq!(
        lookup.claims.unwrap().get("passkey.user_verified"),
        ["false"]
    );
}

async fn regress(fixture: &Fixture, device: &mut Device, counter: u32) -> Verdict {
    device.store.set_counter(counter);
    fixture.sign_in(device, None).await
}

#[tokio::test]
async fn a_counter_that_does_not_rise_refuses_and_disables_the_passkey() {
    let fixture = fixture();
    let mut device = Device::new();
    fixture.enrol("alice", &mut device).await;
    assert!(fixture.is_valid_for(&regress(&fixture, &mut device, 5).await, "alice"));
    // A copy of the key signs with a lower counter.
    assert_eq!(regress(&fixture, &mut device, 1).await, Verdict::Invalid);
    let listed = fixture
        .passkeys
        .accounts()
        .unwrap()
        .remove(0)
        .credentials
        .unwrap();
    assert_eq!(listed[0].disabled, Some(true));
    // The next good answer is refused too, until the passkey is removed.
    assert_eq!(regress(&fixture, &mut device, 100).await, Verdict::Invalid);
    let refused = fixture.challenge(Some("alice"), None).unwrap_err();
    assert_eq!(status(&refused), Status::GUATIAO_ERR_NOT_FOUND);
}

#[tokio::test]
async fn a_counter_that_does_not_rise_is_only_refused_when_the_setting_says_refuse() {
    let fixture = fixture_with(|builder| builder.counter_regression(OnRegression::Refuse));
    let mut device = Device::new();
    fixture.enrol("alice", &mut device).await;
    assert!(fixture.is_valid_for(&regress(&fixture, &mut device, 5).await, "alice"));
    assert_eq!(regress(&fixture, &mut device, 1).await, Verdict::Invalid);
    assert!(fixture.is_valid_for(&regress(&fixture, &mut device, 100).await, "alice"));
    assert!(
        fixture
            .passkeys
            .non_defaults()
            .iter()
            .any(|setting| setting.setting == "counter_regression")
    );
}

#[tokio::test]
async fn a_synced_passkey_reports_no_counter_and_is_not_checked() {
    let fixture = fixture();
    let mut device = Device::new();
    fixture.enrol("alice", &mut device).await;
    for _ in 0..3 {
        assert!(fixture.is_valid_for(&fixture.sign_in(&mut device, None).await, "alice"));
    }
}

#[tokio::test]
async fn another_accounts_user_handle_does_not_take_the_credential() {
    let fixture = fixture();
    let mut alice = Device::new();
    let mut bob = Device::new();
    fixture.enrol("alice", &mut alice).await;
    fixture.enrol("bob", &mut bob).await;
    let bob_handle = {
        let id = fixture.id_of("bob");
        data_encoding::BASE64URL_NOPAD
            .encode(&data_encoding::HEXLOWER.decode(id.as_bytes()).unwrap())
    };

    // Alice's own, signed for a discoverable challenge, signs in (the control).
    let challenge = fixture.challenge(None, None).unwrap();
    let data = client_data("webauthn.get", &challenge.challenge, ORIGIN, false);
    let answer = alice.raw_assertion(RP_ID, &data, &[]).await.unwrap();
    assert!(fixture.is_valid_for(&fixture.present(&challenge.challenge, &answer), "alice"));

    // The same signature with bob's handle written beside it: bob holds no such credential.
    let challenge = fixture.challenge(None, None).unwrap();
    let data = client_data("webauthn.get", &challenge.challenge, ORIGIN, false);
    let mut value: serde_json::Value =
        serde_json::from_str(&alice.raw_assertion(RP_ID, &data, &[]).await.unwrap()).unwrap();
    value["response"]["userHandle"] = bob_handle.clone().into();
    assert_eq!(
        fixture.present(&challenge.challenge, &value.to_string()),
        Verdict::Invalid
    );

    // No handle at all names nobody for a challenge that named nobody.
    let challenge = fixture.challenge(None, None).unwrap();
    let data = client_data("webauthn.get", &challenge.challenge, ORIGIN, false);
    let mut value: serde_json::Value =
        serde_json::from_str(&alice.raw_assertion(RP_ID, &data, &[]).await.unwrap()).unwrap();
    value["response"]
        .as_object_mut()
        .unwrap()
        .remove("userHandle");
    assert_eq!(
        fixture.present(&challenge.challenge, &value.to_string()),
        Verdict::Invalid
    );

    // A challenge named for alice, answered by bob's passkey with bob's handle.
    let challenge = fixture.challenge(Some("alice"), None).unwrap();
    let data = client_data("webauthn.get", &challenge.challenge, ORIGIN, false);
    let answer = bob.raw_assertion(RP_ID, &data, &[]).await.unwrap();
    assert_eq!(
        fixture.present(&challenge.challenge, &answer),
        Verdict::Invalid
    );
}

#[tokio::test]
async fn a_disabled_account_or_passkey_signs_nobody_in_and_is_not_challenged() {
    let fixture = fixture();
    let mut device = Device::new();
    fixture.enrol("alice", &mut device).await;
    let challenge = fixture.challenge(None, None).unwrap();
    let answer = device
        .authenticate(ORIGIN, &challenge.options)
        .await
        .unwrap();
    fixture
        .passkeys
        .put(AccountPut {
            name: "alice".to_owned(),
            disabled: Some(true),
            ..AccountPut::default()
        })
        .unwrap();
    assert_eq!(
        fixture.present(&challenge.challenge, &answer),
        Verdict::Invalid
    );
    for name in ["alice", "nobody"] {
        let refused = fixture.challenge(Some(name), None).unwrap_err();
        assert_eq!(status(&refused), Status::GUATIAO_ERR_NOT_FOUND);
    }
    // Enabled again, with no passkey, there is nothing to sign in with.
    fixture
        .passkeys
        .put(AccountPut {
            name: "alice".to_owned(),
            disabled: Some(false),
            reset: true,
            ..AccountPut::default()
        })
        .unwrap();
    let refused = fixture.challenge(Some("alice"), None).unwrap_err();
    assert_eq!(status(&refused), Status::GUATIAO_ERR_NOT_FOUND);
    let other = fixture
        .passkeys
        .challenge(ChallengeRequest {
            method: Some("totp".to_owned()),
            ..ChallengeRequest::default()
        })
        .unwrap_err();
    assert_eq!(status(&other), Status::GUATIAO_ERR_UNSUPPORTED);
}

#[tokio::test]
async fn an_answer_that_is_too_large_or_is_not_a_passkey_is_invalid() {
    let fixture = fixture_with(|builder| builder.max_response_bytes(coqui_access::Limit::at(4096)));
    let mut device = Device::new();
    fixture.enrol("alice", &mut device).await;
    let challenge = fixture.challenge(None, None).unwrap();
    let large = format!("{{\"id\":\"{}\"}}", "a".repeat(8192));
    assert_eq!(
        fixture.present(&challenge.challenge, &large),
        Verdict::Invalid
    );
    let challenge = fixture.challenge(None, None).unwrap();
    assert_eq!(
        fixture.present(&challenge.challenge, "{}"),
        Verdict::Invalid
    );
    let challenge = fixture.challenge(None, None).unwrap();
    assert_eq!(
        fixture.present(&challenge.challenge, "nonsense"),
        Verdict::Invalid
    );
}

#[tokio::test]
async fn the_ninth_challenge_from_one_source_is_busy_while_another_source_is_served() {
    let fixture = fixture();
    for _ in 0..8 {
        fixture.challenge(None, Some("192.0.2.1:5000")).unwrap();
    }
    // The port is not the source: the same address is one.
    let busy = fixture.challenge(None, Some("192.0.2.1:5001")).unwrap_err();
    assert!(error::is_busy(&busy), "{busy:?}");
    fixture.challenge(None, Some("192.0.2.2:5000")).unwrap();
    // An IPv6 /64 is one source.
    for last in 0..8 {
        fixture
            .challenge(None, Some(&format!("[2001:db8:0:1::{last:x}]:443")))
            .unwrap();
    }
    let busy = fixture
        .challenge(None, Some("[2001:db8:0:1:ffff::1]:443"))
        .unwrap_err();
    assert!(error::is_busy(&busy));
    // No address is one source too.
    for _ in 0..8 {
        fixture.challenge(None, None).unwrap();
    }
    assert!(error::is_busy(&fixture.challenge(None, None).unwrap_err()));
    // Once they expire there is room again, and the table does not keep them.
    fixture.at(START + 301);
    fixture.challenge(None, Some("192.0.2.1:5000")).unwrap();
    assert_eq!(fixture.ceremonies.load().unwrap().records.len(), 1);
}

#[tokio::test]
async fn the_challenges_in_all_are_bounded() {
    let mut limits = coqui_access_passkey::default_ceremony_limits();
    limits.total = 3;
    limits.per_source = 100;
    let fixture = fixture_with(|builder| builder.ceremony_limits(limits));
    for last in 0..3 {
        fixture
            .challenge(None, Some(&format!("192.0.2.{last}")))
            .unwrap();
    }
    let busy = fixture.challenge(None, Some("192.0.2.9")).unwrap_err();
    assert!(error::is_busy(&busy));
}

/// A table that reads what it was given and cannot be written.
struct ReadOnly(Vec<PasskeyAccount>);

impl Table<PasskeyAccount> for ReadOnly {
    fn load(&self) -> Result<Snapshot<PasskeyAccount>, SourceError> {
        Ok(Snapshot::new(Revision::default(), self.0.clone()))
    }
}

#[tokio::test]
async fn a_write_that_fails_is_an_internal_error_and_never_a_success() {
    let fixture = fixture();
    let mut device = Device::new();
    fixture.enrol("alice", &mut device).await;
    let kept = fixture.table.load().unwrap().records;
    let frozen = Passkeys::builder()
        .rp_id(RP_ID)
        .origin(ORIGIN)
        .table(Arc::new(ReadOnly(kept)))
        .ceremonies(fixture.ceremonies.clone())
        .clock(|| START)
        .build()
        .unwrap();
    let challenge = frozen.challenge(ChallengeRequest::default()).unwrap();
    let answer = device
        .authenticate(ORIGIN, &challenge.options)
        .await
        .unwrap();
    let outcome = frozen.authenticate(Attempt {
        challenge: Some(challenge.challenge),
        secret: Some(answer),
        ..Attempt::default()
    });
    let refused = outcome.unwrap_err();
    assert_eq!(status(&refused), Status::GUATIAO_ERR_INTERNAL);
}

#[tokio::test]
async fn a_debug_line_of_a_challenge_holds_nothing_to_replay() {
    let fixture = fixture();
    let mut device = Device::new();
    fixture.enrol("alice", &mut device).await;
    let challenge = fixture
        .challenge(Some("alice"), Some("192.0.2.7:1"))
        .unwrap();
    let held = fixture.ceremonies.load().unwrap().records.remove(0);
    let shown = format!("{challenge:?} {held:?} {:?}", held.clone());
    for leaked in [
        challenge.challenge.as_str(),
        challenge.options.as_str(),
        held.state.as_str(),
        "192.0.2.7",
        "alice",
    ] {
        assert!(!shown.contains(leaked), "{leaked} in {shown}");
    }
}
