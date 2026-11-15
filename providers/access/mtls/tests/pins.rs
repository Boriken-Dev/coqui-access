//! Pinning by public key beside the fingerprint, and several pins on one account.

use std::sync::Arc;

use coqui_access::guatiao::{FromValue, ToValue};
use coqui_access::{AccountPut, Accounts, Attempt, Authenticator, Lookup, Verdict};
use coqui_access_kit::MemoryTable;
use coqui_access_mtls::{MtlsAccounts, PeerRecord, Pin};
use coqui_peer_tls::PeerId;
use rcgen::{CertificateParams, DnType, KeyPair};

/// A self-signed certificate for `key`, as DER; two with the same key differ in name and so
/// in fingerprint, as a renewed certificate does.
fn certificate(key: &KeyPair, common_name: &str) -> Vec<u8> {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.self_signed(key).unwrap().der().to_vec()
}

fn presented(der: &[u8]) -> Attempt {
    Attempt {
        secure: Some(true),
        certificates: Some(vec![der.to_vec().into()]),
        peer: Some("192.0.2.7:4000".to_owned()),
        ..Attempt::default()
    }
}

fn fingerprint_of(der: &[u8]) -> PeerId {
    PeerId::of(der)
}

fn key_pin_text(der: &[u8]) -> String {
    let pin = Pin::key_of_certificate(der).expect("a certificate has a key");
    pin.text()
}

fn put(name: &str, secret: &str) -> AccountPut {
    AccountPut {
        name: name.to_owned(),
        secret: Some(secret.to_owned()),
        ..AccountPut::default()
    }
}

/// The verdict without the claims that ride along: these tests are about which account.
fn bare(verdict: Verdict) -> Verdict {
    match verdict {
        Verdict::Valid(lookup) => Verdict::Valid(Lookup {
            claims: None,
            ..lookup
        }),
        other => other,
    }
}

fn valid(id: &str) -> Verdict {
    Verdict::Valid(Lookup {
        by: "id".to_owned(),
        value: id.to_owned(),
        ..Lookup::default()
    })
}

fn id_of(accounts: &MtlsAccounts, name: &str) -> String {
    accounts
        .accounts()
        .unwrap()
        .into_iter()
        .find(|account| account.name == name)
        .unwrap()
        .id
}

#[test]
fn a_renewed_certificate_with_the_same_key_signs_in_under_a_key_pin_and_not_a_fingerprint_pin() {
    let key = KeyPair::generate().unwrap();
    let first = certificate(&key, "Smartcard 2025");
    let renewed = certificate(&key, "Smartcard 2026");
    assert_ne!(fingerprint_of(&first), fingerprint_of(&renewed));

    let by_key = MtlsAccounts::builder().build().unwrap();
    by_key.put(put("alice", &key_pin_text(&first))).unwrap();
    let id = id_of(&by_key, "alice");
    assert_eq!(
        bare(by_key.authenticate(presented(&first)).unwrap()),
        valid(&id)
    );
    assert_eq!(
        bare(by_key.authenticate(presented(&renewed)).unwrap()),
        valid(&id)
    );

    let by_fingerprint = MtlsAccounts::builder().build().unwrap();
    by_fingerprint
        .put(put("alice", &fingerprint_of(&first).canonical()))
        .unwrap();
    let id = id_of(&by_fingerprint, "alice");
    assert_eq!(
        bare(by_fingerprint.authenticate(presented(&first)).unwrap()),
        valid(&id)
    );
    assert_eq!(
        bare(by_fingerprint.authenticate(presented(&renewed)).unwrap()),
        Verdict::Unknown
    );
}

#[test]
fn another_key_does_not_match_a_key_pin() {
    let (mine, theirs) = (KeyPair::generate().unwrap(), KeyPair::generate().unwrap());
    let accounts = MtlsAccounts::builder().build().unwrap();
    accounts
        .put(put("alice", &key_pin_text(&certificate(&mine, "a"))))
        .unwrap();
    assert_eq!(
        accounts
            .authenticate(presented(&certificate(&theirs, "a")))
            .unwrap(),
        Verdict::Unknown
    );
}

#[test]
fn a_key_pin_needs_the_chain_and_a_transport_that_proved_the_key() {
    let key = KeyPair::generate().unwrap();
    let der = certificate(&key, "a");
    let accounts = MtlsAccounts::builder().build().unwrap();
    accounts.put(put("alice", &key_pin_text(&der))).unwrap();
    let mut unproved = presented(&der);
    unproved.secure = Some(false);
    assert_eq!(accounts.authenticate(unproved).unwrap(), Verdict::Unknown);
    // A fingerprint alone says nothing of the key.
    let only_fingerprint = Attempt {
        certificate: Some(fingerprint_of(&der).canonical()),
        ..Attempt::default()
    };
    assert_eq!(
        accounts.authenticate(only_fingerprint).unwrap(),
        Verdict::Unknown
    );
    // A fingerprint that is not the chain's leaf's is not a proof of that leaf.
    let other = certificate(&KeyPair::generate().unwrap(), "b");
    let mut mixed = presented(&der);
    mixed.certificate = Some(fingerprint_of(&other).canonical());
    assert_eq!(accounts.authenticate(mixed).unwrap(), Verdict::Unknown);
}

#[test]
fn a_second_pin_on_the_same_account_is_added_up_to_the_bound() {
    let keys: Vec<KeyPair> = (0..4).map(|_| KeyPair::generate().unwrap()).collect();
    let ders: Vec<Vec<u8>> = keys.iter().map(|key| certificate(key, "a")).collect();
    let accounts = MtlsAccounts::builder().max_pins(3).build().unwrap();
    accounts.put(put("alice", &key_pin_text(&ders[0]))).unwrap();
    accounts.put(put("alice", &key_pin_text(&ders[1]))).unwrap();
    accounts
        .put(put("alice", &fingerprint_of(&ders[2]).canonical()))
        .unwrap();
    assert_eq!(accounts.accounts().unwrap().len(), 1, "one account");
    let id = id_of(&accounts, "alice");
    for der in &ders[..3] {
        assert_eq!(
            bare(accounts.authenticate(presented(der)).unwrap()),
            valid(&id)
        );
    }
    // Past the bound, and the account keeps what it had.
    assert!(accounts.put(put("alice", &key_pin_text(&ders[3]))).is_err());
    assert_eq!(
        bare(accounts.authenticate(presented(&ders[3])).unwrap()),
        Verdict::Unknown
    );
    // Saying a pin the account holds again is not another pin.
    accounts.put(put("alice", &key_pin_text(&ders[0]))).unwrap();
}

#[test]
fn a_pin_belongs_to_one_account() {
    let der = certificate(&KeyPair::generate().unwrap(), "a");
    let accounts = MtlsAccounts::builder().build().unwrap();
    accounts.put(put("alice", &key_pin_text(&der))).unwrap();
    assert!(accounts.put(put("bob", &key_pin_text(&der))).is_err());
    accounts
        .put(put("bob", &fingerprint_of(&der).canonical()))
        .unwrap();
    assert!(
        accounts
            .put(put("carol", &fingerprint_of(&der).canonical()))
            .is_err()
    );
}

#[test]
fn a_pin_is_removed_alone() {
    let ders: Vec<Vec<u8>> = (0..2)
        .map(|_| certificate(&KeyPair::generate().unwrap(), "a"))
        .collect();
    let accounts = MtlsAccounts::builder().build().unwrap();
    accounts.put(put("alice", &key_pin_text(&ders[0]))).unwrap();
    accounts.put(put("alice", &key_pin_text(&ders[1]))).unwrap();
    let id = id_of(&accounts, "alice");

    accounts
        .put(put("alice", &format!("remove:{}", key_pin_text(&ders[0]))))
        .unwrap();
    assert_eq!(
        bare(accounts.authenticate(presented(&ders[0])).unwrap()),
        Verdict::Unknown
    );
    assert_eq!(
        bare(accounts.authenticate(presented(&ders[1])).unwrap()),
        valid(&id)
    );
    // The last pin stays: an account that nothing could sign in to is removed instead.
    assert!(
        accounts
            .put(put("alice", &format!("remove:{}", key_pin_text(&ders[1]))))
            .is_err()
    );
    // A pin the account does not hold is refused, and nothing changes.
    assert!(
        accounts
            .put(put("alice", &format!("remove:{}", key_pin_text(&ders[0]))))
            .is_err()
    );
    assert_eq!(accounts.accounts().unwrap().len(), 1);
}

#[test]
fn a_fingerprint_pin_is_removed_alone_whether_it_is_the_first_or_a_later_one() {
    let ders: Vec<Vec<u8>> = (0..2)
        .map(|_| certificate(&KeyPair::generate().unwrap(), "a"))
        .collect();
    let accounts = MtlsAccounts::builder().build().unwrap();
    for der in &ders {
        accounts
            .put(put("alice", &fingerprint_of(der).canonical()))
            .unwrap();
    }
    let id = id_of(&accounts, "alice");
    accounts
        .put(put(
            "alice",
            &format!("remove:{}", fingerprint_of(&ders[0]).canonical()),
        ))
        .unwrap();
    assert_eq!(
        bare(accounts.authenticate(presented(&ders[0])).unwrap()),
        Verdict::Unknown
    );
    assert_eq!(
        bare(accounts.authenticate(presented(&ders[1])).unwrap()),
        valid(&id)
    );
}

#[test]
fn a_disabled_account_refuses_its_key_pin() {
    let der = certificate(&KeyPair::generate().unwrap(), "a");
    let accounts = MtlsAccounts::builder().build().unwrap();
    accounts.put(put("alice", &key_pin_text(&der))).unwrap();
    accounts
        .put(AccountPut {
            name: "alice".to_owned(),
            disabled: Some(true),
            ..AccountPut::default()
        })
        .unwrap();
    assert_eq!(
        bare(accounts.authenticate(presented(&der)).unwrap()),
        Verdict::Invalid
    );
}

#[test]
fn a_record_names_its_kind_of_pin_and_a_fingerprint_only_record_still_reads() {
    let der = certificate(&KeyPair::generate().unwrap(), "a");
    let mut record = PeerRecord::new("1", "alice", &fingerprint_of(&der));
    record.pins.push(Pin::key_of_certificate(&der).unwrap());
    let value = record.to_value().unwrap();
    let text = format!("{value:?}");
    assert!(text.contains("key") || !text.is_empty());
    assert_eq!(PeerRecord::from_value(&value).unwrap(), record);
    assert_eq!(record.pins[0].kind, Pin::KEY);

    // A record written before pins existed: a fingerprint, no list.
    let mut old = coqui_access::guatiao::Map::new();
    old.set("id", "1");
    old.set("name", "alice");
    old.set("certificate", fingerprint_of(&der).canonical());
    let read = PeerRecord::from_value(&old.into()).unwrap();
    assert!(read.pins.is_empty());
    let accounts = MtlsAccounts::builder()
        .table(Arc::new(MemoryTable::from_records([read])))
        .build()
        .unwrap();
    assert_eq!(
        bare(accounts.authenticate(presented(&der)).unwrap()),
        valid("1")
    );
}

#[test]
fn a_table_with_a_bad_pin_a_pinless_record_or_too_many_pins_is_refused() {
    let der = certificate(&KeyPair::generate().unwrap(), "a");
    let build = |record: PeerRecord, max: usize| {
        MtlsAccounts::builder()
            .max_pins(max)
            .table(Arc::new(MemoryTable::from_records([record])))
            .build()
    };
    let keyed = || PeerRecord::keyed("1", "alice", Pin::key_of_certificate(&der).unwrap());
    assert!(build(keyed(), 4).is_ok());
    let mut bad = keyed();
    bad.pins[0].value = "sha256:nothex".to_owned();
    assert!(build(bad, 4).is_err());
    let mut unknown = keyed();
    unknown.pins[0].kind = "password".to_owned();
    assert!(build(unknown, 4).is_err());
    let mut pinless = keyed();
    pinless.pins.clear();
    assert!(build(pinless, 4).is_err());
    let mut many = keyed();
    many.pins.push(Pin::fingerprint(&PeerId::of(b"one")));
    assert!(build(many, 1).is_err());
    let mut twice = keyed();
    twice.pins.push(twice.pins[0].clone());
    assert!(build(twice, 4).is_err(), "a pin is listed once");
}

#[test]
fn a_waiting_fingerprint_is_accepted_as_one_more_pin_and_waits_no_more() {
    let key = KeyPair::generate().unwrap();
    let first = certificate(&key, "a");
    let other = certificate(&KeyPair::generate().unwrap(), "b");
    let accounts = MtlsAccounts::builder().build().unwrap();
    accounts.put(put("alice", &key_pin_text(&first))).unwrap();
    assert_eq!(
        bare(accounts.authenticate(presented(&other)).unwrap()),
        Verdict::Unknown
    );
    let shown = accounts.waiting().unwrap()[0].shown.clone();
    accounts.put(put("alice", &shown)).unwrap();
    assert!(accounts.waiting().unwrap().is_empty());
    assert_eq!(
        bare(accounts.authenticate(presented(&other)).unwrap()),
        valid(&id_of(&accounts, "alice"))
    );
}
