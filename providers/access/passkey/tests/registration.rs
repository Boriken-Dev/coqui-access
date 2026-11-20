//! Registering, listing and removing passkeys through the `Accounts` kind, with a software
//! authenticator and a client that checks the origin the way a browser does.

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use coqui_access::guatiao::Status;
use coqui_access::guatiao::library::ProviderError;
use coqui_access::{AccountPut, Accounts, Directory, Limit, Lookup};
use coqui_access_kit::{MemoryTable, Table};
use coqui_access_passkey::{
    Algorithm, Attestation, PasskeyAccount, Passkeys, PendingRegistration, UserVerification,
};
use support::{Device, ORIGIN, RP_ID};

const START: i64 = 1_700_000_000;

struct Fixture {
    clock: Arc<AtomicI64>,
    passkeys: Passkeys,
    table: Arc<MemoryTable<PasskeyAccount>>,
    pending: Arc<MemoryTable<PendingRegistration>>,
}

fn fixture_with(
    configure: impl FnOnce(
        coqui_access_passkey::PasskeysBuilder,
    ) -> coqui_access_passkey::PasskeysBuilder,
) -> Fixture {
    let clock = Arc::new(AtomicI64::new(START));
    let reader = clock.clone();
    let table = Arc::new(MemoryTable::<PasskeyAccount>::new());
    let pending = Arc::new(MemoryTable::<PendingRegistration>::new());
    let builder = Passkeys::builder()
        .rp_id(RP_ID)
        .origin(ORIGIN)
        .table(table.clone())
        .pending(pending.clone())
        .clock(move || reader.load(Ordering::SeqCst));
    let passkeys = configure(builder).build().unwrap();
    Fixture {
        clock,
        passkeys,
        table,
        pending,
    }
}

fn fixture() -> Fixture {
    fixture_with(|builder| builder)
}

impl Fixture {
    fn at(&self, unix: i64) {
        self.clock.store(unix, Ordering::SeqCst);
    }

    fn begin(&self, name: &str) -> String {
        self.passkeys
            .put(AccountPut {
                name: name.to_owned(),
                display_name: Some(format!("{name} Example")),
                ..AccountPut::default()
            })
            .unwrap()
            .secret
            .unwrap()
    }

    fn confirm(&self, name: &str, answer: &str) -> Result<(), ProviderError> {
        self.passkeys
            .put(AccountPut {
                name: name.to_owned(),
                secret: Some(answer.to_owned()),
                display_name: Some("Laptop".to_owned()),
                ..AccountPut::default()
            })
            .map(|_| ())
    }

    /// Begins, has `device` answer and confirms: the person's whole registration.
    async fn register(&self, name: &str, device: &mut Device) -> Result<(), ProviderError> {
        let options = self.begin(name);
        let answer = device.register(ORIGIN, &options).await.unwrap();
        self.confirm(name, &answer)
    }

    fn credential_ids(&self, name: &str) -> Vec<String> {
        self.passkeys
            .accounts()
            .unwrap()
            .into_iter()
            .find(|account| account.name == name)
            .and_then(|account| account.credentials)
            .unwrap_or_default()
            .into_iter()
            .map(|credential| credential.id)
            .collect()
    }
}

fn status(error: &ProviderError) -> Status {
    error.status
}

#[tokio::test]
async fn a_registration_is_begun_confirmed_listed_and_found_by_the_directory() {
    let fixture = fixture();
    let mut device = Device::new();
    fixture.register("alice", &mut device).await.unwrap();
    let accounts = fixture.passkeys.accounts().unwrap();
    assert_eq!(accounts.len(), 1);
    let alice = &accounts[0];
    assert_eq!(alice.name, "alice");
    assert_eq!(alice.id.len(), 32);
    let credentials = alice.credentials.as_ref().unwrap();
    assert_eq!(credentials.len(), 1);
    assert_eq!(credentials[0].label.as_deref(), Some("Laptop"));
    assert_eq!(credentials[0].made_unix, Some(START));
    assert_eq!(credentials[0].used_unix, None);
    assert_eq!(credentials[0].disabled, Some(false));
    // Nothing waits any more.
    assert!(fixture.passkeys.waiting().unwrap().is_empty());
    let found = fixture
        .passkeys
        .lookup(Lookup {
            by: "id".to_owned(),
            value: alice.id.clone(),
            claims: None,
        })
        .unwrap()
        .unwrap();
    assert_eq!(found.name, "alice");
    assert_eq!(found.display_name.as_deref(), Some("alice Example"));
    let by_name = fixture
        .passkeys
        .lookup(Lookup {
            by: "name".to_owned(),
            value: "alice".to_owned(),
            claims: None,
        })
        .unwrap();
    assert_eq!(by_name.unwrap().id, alice.id);
}

#[tokio::test]
async fn a_second_registration_excludes_the_first_credential() {
    let fixture = fixture();
    let mut device = Device::new();
    fixture.register("alice", &mut device).await.unwrap();
    let first = fixture.credential_ids("alice").remove(0);
    let options = fixture.begin("alice");
    let value: serde_json::Value = serde_json::from_str(&options).unwrap();
    let excluded = value["publicKey"]["excludeCredentials"].as_array().unwrap();
    assert_eq!(excluded.len(), 1);
    assert_eq!(excluded[0]["id"], first.as_str());
    // A first registration excludes nothing.
    let fresh = fixture.begin("bob");
    let value: serde_json::Value = serde_json::from_str(&fresh).unwrap();
    assert!(
        value["publicKey"]["excludeCredentials"]
            .as_array()
            .is_none_or(Vec::is_empty)
    );
    // Another device may.
    let mut other = Device::new();
    let answer = other.register(ORIGIN, &options).await.unwrap();
    fixture.confirm("alice", &answer).unwrap();
    assert_eq!(fixture.credential_ids("alice").len(), 2);
}

#[tokio::test]
async fn an_expired_and_a_missing_registration_are_refused_differently() {
    let fixture = fixture();
    let mut device = Device::new();
    let options = fixture.begin("alice");
    let answer = device.register(ORIGIN, &options).await.unwrap();
    fixture.at(START + 601);
    let expired = fixture.confirm("alice", &answer).unwrap_err();
    assert_eq!(status(&expired), Status::GUATIAO_ERR_BAD_VALUE);
    // The expired entry is gone, so a second answer finds nothing waiting.
    let missing = fixture.confirm("alice", &answer).unwrap_err();
    assert_eq!(status(&missing), Status::GUATIAO_ERR_NOT_FOUND);
    let never = fixture.confirm("bob", &answer).unwrap_err();
    assert_eq!(status(&never), Status::GUATIAO_ERR_NOT_FOUND);
    assert!(fixture.passkeys.accounts().unwrap().is_empty());
}

#[tokio::test]
async fn an_answer_made_for_alice_is_not_taken_for_bob() {
    let fixture = fixture();
    let mut device = Device::new();
    let for_alice = fixture.begin("alice");
    fixture.begin("bob");
    let answer = device.register(ORIGIN, &for_alice).await.unwrap();
    assert!(fixture.confirm("bob", &answer).is_err());
    // Bob's registration was consumed by the attempt, and alice's is still waiting.
    assert_eq!(fixture.passkeys.waiting().unwrap().len(), 1);
    fixture.confirm("alice", &answer).unwrap();
    assert!(fixture.credential_ids("bob").is_empty());
}

#[tokio::test]
async fn a_credential_id_another_account_holds_is_refused() {
    let fixture = fixture();
    let mut device = Device::new();
    let options = fixture.begin("alice");
    let answer = device.register(ORIGIN, &options).await.unwrap();
    // The registration for bob that would take the same answer: only the challenge ties them.
    let mut copy = fixture.pending.get("alice").unwrap().unwrap();
    copy.name = "bob".to_owned();
    copy.id = "00000000000000000000000000000001".to_owned();
    fixture.pending.put(copy).unwrap();
    fixture.confirm("alice", &answer).unwrap();
    let refused = fixture.confirm("bob", &answer).unwrap_err();
    assert_eq!(status(&refused), Status::GUATIAO_ERR_BAD_VALUE);
    assert!(fixture.credential_ids("bob").is_empty());
    assert_eq!(fixture.credential_ids("alice").len(), 1);
}

#[tokio::test]
async fn an_account_holds_no_more_passkeys_than_max_credentials() {
    let fixture = fixture_with(|builder| builder.max_credentials(Limit::at(1)));
    fixture.register("alice", &mut Device::new()).await.unwrap();
    let refused = fixture
        .register("alice", &mut Device::new())
        .await
        .unwrap_err();
    assert_eq!(status(&refused), Status::GUATIAO_ERR_BAD_VALUE);
    assert_eq!(fixture.credential_ids("alice").len(), 1);
    // Unbounded is a choice the caller makes.
    let open = fixture_with(|builder| builder.max_credentials(Limit::UNBOUNDED));
    open.register("alice", &mut Device::new()).await.unwrap();
    open.register("alice", &mut Device::new()).await.unwrap();
    assert_eq!(open.credential_ids("alice").len(), 2);
}

/// The options with the person not asked to be verified, as a client that ignores the relying
/// party's wish would send them.
fn without_verification(options: &str) -> String {
    let mut value: serde_json::Value = serde_json::from_str(options).unwrap();
    value["publicKey"]["authenticatorSelection"]["userVerification"] = "discouraged".into();
    value.to_string()
}

#[tokio::test]
async fn a_registration_that_did_not_verify_the_person_needs_user_verification_not_required() {
    let required = fixture();
    let options = required.begin("alice");
    let answer = Device::new()
        .register(ORIGIN, &without_verification(&options))
        .await
        .unwrap();
    assert!(required.confirm("alice", &answer).is_err());
    assert!(required.credential_ids("alice").is_empty());

    let preferred = fixture_with(|builder| builder.user_verification(UserVerification::Preferred));
    let options = preferred.begin("alice");
    let answer = Device::new()
        .register(ORIGIN, &without_verification(&options))
        .await
        .unwrap();
    preferred.confirm("alice", &answer).unwrap();
    assert_eq!(preferred.credential_ids("alice").len(), 1);
    let listed = preferred.passkeys.non_defaults();
    assert!(
        listed
            .iter()
            .any(|setting| setting.setting == "user_verification"),
        "{listed:?}"
    );
}

/// A certificate authority made for the test: nothing signed by it exists.
fn authority_pem() -> Vec<u8> {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let key = rcgen::KeyPair::generate().unwrap();
    params.self_signed(&key).unwrap().pem().into_bytes()
}

#[tokio::test]
async fn an_attestation_that_does_not_chain_to_the_authorities_is_refused() {
    let fixture = fixture_with(|builder| {
        builder
            .attestation(Attestation::Direct)
            .attestation_ca_pem(authority_pem())
    });
    // The software authenticator attests nothing, which no authority vouches for.
    let refused = fixture
        .register("alice", &mut Device::new())
        .await
        .unwrap_err();
    assert_eq!(status(&refused), Status::GUATIAO_ERR_BAD_VALUE);
    assert!(fixture.credential_ids("alice").is_empty());
}

#[tokio::test]
async fn a_passkey_is_removed_and_labelled_by_id_and_an_account_is_changed_and_removed() {
    let fixture = fixture();
    fixture.register("alice", &mut Device::new()).await.unwrap();
    fixture.register("alice", &mut Device::new()).await.unwrap();
    let ids = fixture.credential_ids("alice");
    assert_eq!(ids.len(), 2);

    fixture
        .passkeys
        .put(AccountPut {
            name: "alice".to_owned(),
            secret: Some(format!("label:{}", ids[1])),
            display_name: Some("Phone".to_owned()),
            ..AccountPut::default()
        })
        .unwrap();
    let account = fixture.passkeys.accounts().unwrap().remove(0);
    let labels: Vec<_> = account
        .credentials
        .unwrap()
        .into_iter()
        .map(|credential| credential.label)
        .collect();
    assert_eq!(
        labels,
        [Some("Laptop".to_owned()), Some("Phone".to_owned())]
    );

    fixture
        .passkeys
        .put(AccountPut {
            name: "alice".to_owned(),
            secret: Some(format!("remove:{}", ids[0])),
            ..AccountPut::default()
        })
        .unwrap();
    assert_eq!(fixture.credential_ids("alice"), vec![ids[1].clone()]);
    let none = fixture.passkeys.put(AccountPut {
        name: "alice".to_owned(),
        secret: Some("remove:nothing".to_owned()),
        ..AccountPut::default()
    });
    assert!(none.is_err());

    // Disabled and groups alone change the account, and a disabled one is not in the directory.
    fixture
        .passkeys
        .put(AccountPut {
            name: "alice".to_owned(),
            disabled: Some(true),
            groups: Some(vec!["staff".to_owned()]),
            ..AccountPut::default()
        })
        .unwrap();
    let account = fixture.passkeys.accounts().unwrap().remove(0);
    assert_eq!(account.disabled, Some(true));
    assert_eq!(account.groups, ["staff".to_owned()]);
    let lookup = Lookup {
        by: "name".to_owned(),
        value: "alice".to_owned(),
        claims: None,
    };
    assert!(fixture.passkeys.lookup(lookup).unwrap().is_none());
    // Changing a name that is not there is not a registration.
    let unknown = fixture
        .passkeys
        .put(AccountPut {
            name: "nobody".to_owned(),
            disabled: Some(true),
            ..AccountPut::default()
        })
        .unwrap_err();
    assert_eq!(status(&unknown), Status::GUATIAO_ERR_NOT_FOUND);
    // An expiry is refused, and an unlock begins nothing.
    let expires = fixture.passkeys.put(AccountPut {
        name: "alice".to_owned(),
        expires_unix: Some(1),
        ..AccountPut::default()
    });
    assert!(expires.is_err());
    fixture
        .passkeys
        .put(AccountPut {
            name: "alice".to_owned(),
            unlock: true,
            ..AccountPut::default()
        })
        .unwrap();
    assert!(fixture.passkeys.waiting().unwrap().is_empty());

    // A reset takes the passkeys and the registration waiting, and keeps the account.
    fixture.begin("alice");
    fixture
        .passkeys
        .put(AccountPut {
            name: "alice".to_owned(),
            reset: true,
            ..AccountPut::default()
        })
        .unwrap();
    assert!(fixture.credential_ids("alice").is_empty());
    assert!(fixture.passkeys.waiting().unwrap().is_empty());
    assert_eq!(fixture.passkeys.accounts().unwrap().len(), 1);

    fixture.begin("carol");
    fixture.passkeys.remove("alice".to_owned()).unwrap();
    fixture.passkeys.remove("carol".to_owned()).unwrap();
    let gone = fixture.passkeys.remove("alice".to_owned()).unwrap_err();
    assert_eq!(status(&gone), Status::GUATIAO_ERR_NOT_FOUND);
    assert!(fixture.passkeys.accounts().unwrap().is_empty());
}

#[tokio::test]
async fn an_oversized_or_unreadable_answer_is_refused_and_consumes_the_registration() {
    let fixture = fixture_with(|builder| builder.max_response_bytes(Limit::at(64)));
    fixture.begin("alice");
    let big = format!("{{\"id\":\"{}\"}}", "a".repeat(200));
    let refused = fixture.confirm("alice", &big).unwrap_err();
    assert_eq!(status(&refused), Status::GUATIAO_ERR_BAD_VALUE);
    // The size is checked before the entry is touched.
    assert_eq!(fixture.passkeys.waiting().unwrap().len(), 1);
    let unreadable = fixture_with(|builder| builder);
    unreadable.begin("alice");
    assert!(unreadable.confirm("alice", "{\"nonsense\":1}").is_err());
    assert!(unreadable.passkeys.waiting().unwrap().is_empty());
    let neither = unreadable.confirm("alice", "plain text");
    assert!(neither.is_err());
}

#[test]
fn the_provider_refuses_to_be_built_without_what_a_passkey_could_not_do_without() {
    let base = || Passkeys::builder().rp_id(RP_ID).origin(ORIGIN);
    assert!(base().build().is_ok());
    let refused = |builder: coqui_access_passkey::PasskeysBuilder| builder.build().is_err();
    assert!(refused(Passkeys::builder().origin(ORIGIN)), "no rp_id");
    assert!(refused(Passkeys::builder().rp_id(RP_ID)), "no origin");
    assert!(refused(
        Passkeys::builder()
            .rp_id("https://portal.example")
            .origin(ORIGIN)
    ));
    assert!(refused(
        Passkeys::builder()
            .rp_id("portal.example:8443")
            .origin(ORIGIN)
    ));
    assert!(refused(
        Passkeys::builder()
            .rp_id(RP_ID)
            .origin("https://portal.example/login")
    ));
    assert!(refused(
        Passkeys::builder()
            .rp_id(RP_ID)
            .origin("https://portal.example/?a=b")
    ));
    assert!(refused(
        Passkeys::builder()
            .rp_id(RP_ID)
            .origin("https://portal.example/#a")
    ));
    assert!(refused(
        Passkeys::builder()
            .rp_id(RP_ID)
            .origin("https://other.example")
    ));
    assert!(refused(
        Passkeys::builder()
            .rp_id(RP_ID)
            .origin("https://notportal.example")
    ));
    assert!(refused(
        Passkeys::builder()
            .rp_id(RP_ID)
            .origin("ftp://portal.example")
    ));
    assert!(refused(
        base().algorithms([Algorithm::Es256, Algorithm::Eddsa])
    ));
    assert!(refused(base().algorithms([])));
    assert!(refused(base().attestation_ca_pem(authority_pem())), "none");
    assert!(refused(
        base()
            .attestation(Attestation::Direct)
            .attestation_ca_pem(b"not a certificate".to_vec())
    ));
    assert!(refused(base().enrol_seconds(0)));
    assert!(refused(base().ceremony_seconds(0)));
    // A host under the rp_id, a second origin and every other setting are accepted.
    assert!(
        Passkeys::builder()
            .rp_id(RP_ID)
            .origin("https://login.portal.example:8443")
            .origin(ORIGIN)
            .algorithms([Algorithm::Es256])
            .build()
            .is_ok()
    );
    // Plain http is a choice, and is listed unless it is a loopback host.
    let http = Passkeys::builder()
        .rp_id(RP_ID)
        .origin("http://portal.example")
        .build()
        .unwrap();
    assert_eq!(http.non_defaults().len(), 1);
    let local = Passkeys::builder()
        .rp_id("localhost")
        .origin("http://localhost:3000")
        .build()
        .unwrap();
    assert!(local.non_defaults().is_empty());
    assert!(base().build().unwrap().non_defaults().is_empty());
}

#[tokio::test]
async fn a_debug_line_of_every_record_holds_no_key_id_or_handle() {
    let fixture = fixture();
    fixture.register("alice", &mut Device::new()).await.unwrap();
    fixture.begin("bob");
    let account = fixture.table.load().unwrap().records.remove(0);
    let credential = account.credentials[0].clone();
    let waiting = fixture.pending.load().unwrap().records.remove(0);
    let shown = format!(
        "{account:?} {credential:?} {waiting:?} {:?} {:?}",
        fixture.passkeys,
        fixture.passkeys.put(AccountPut {
            name: "alice".to_owned(),
            secret: Some("{}".to_owned()),
            ..AccountPut::default()
        })
    );
    for leaked in [
        account.id.as_str(),
        "alice",
        credential.id.as_str(),
        credential.key.as_str(),
        waiting.state.as_str(),
        waiting.id.as_str(),
    ] {
        assert!(!shown.contains(leaked), "{leaked} in {shown}");
    }
}
