//! Client certificates trusted by a certificate authority, and the account their fields name.

use std::path::Path;
use std::sync::Arc;

use coqui_access::{Attempt, Authenticator, Lookup, Verdict};
use coqui_access_kit::MemoryTable;
use coqui_access_kit::pick::Pick;
use coqui_access_mtls::{MtlsAccounts, PeerRecord, TrustMode};
use coqui_peer_tls::{CaPolicy, PeerId};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, OtherNameValue, SanType,
};

/// A certificate authority: its PEM, and what signs with it.
struct Authority {
    pem: String,
    issuer: Issuer<'static, KeyPair>,
}

fn authority(name: &str) -> Authority {
    let params = || {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name.push(DnType::CommonName, name);
        params
    };
    let key = KeyPair::generate().unwrap();
    let pem = params().self_signed(&key).unwrap().pem();
    Authority {
        pem,
        issuer: Issuer::new(params(), key),
    }
}

/// A leaf with these names, signed by `by`, as DER.
fn leaf(by: &Authority, names: Vec<SanType>) -> Vec<u8> {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(DnType::CommonName, "Client One");
    params.subject_alt_names = names;
    let key = KeyPair::generate().unwrap();
    params.signed_by(&key, &by.issuer).unwrap().der().to_vec()
}

fn email(address: &str) -> SanType {
    SanType::Rfc822Name(address.try_into().unwrap())
}

fn upn(name: &str) -> SanType {
    SanType::OtherName((
        vec![1, 3, 6, 1, 4, 1, 311, 20, 2, 3],
        OtherNameValue::Utf8String(name.into()),
    ))
}

fn ip(text: &str) -> SanType {
    SanType::IpAddress(text.parse().unwrap())
}

fn dns(text: &str) -> SanType {
    SanType::DnsName(text.try_into().unwrap())
}

fn attempt(chain: &[&[u8]], secure: bool) -> Attempt {
    Attempt {
        secure: Some(secure),
        certificates: Some(chain.iter().map(|der| der.to_vec().into()).collect()),
        peer: Some("192.0.2.7:4000".to_owned()),
        ..Attempt::default()
    }
}

fn ca_file(directory: &Path, authority: &Authority) -> CaPolicy {
    let file = directory.join("ca.pem");
    std::fs::write(&file, &authority.pem).unwrap();
    CaPolicy::new(file)
}

fn trusting(directory: &Path, authority: &Authority, account: Vec<Pick>) -> MtlsAccounts {
    MtlsAccounts::builder()
        .trust(TrustMode::Ca)
        .ca(ca_file(directory, authority))
        .account(account)
        .build()
        .unwrap()
}

fn found(by: &str, value: &str) -> Verdict {
    Verdict::Valid(Lookup {
        by: by.to_owned(),
        value: value.to_owned(),
    })
}

#[test]
fn an_email_san_under_a_ca_names_the_account_by_email() {
    let directory = tempfile::tempdir().unwrap();
    let ca = authority("Root");
    let provider = trusting(directory.path(), &ca, vec![Pick::new("san.email", "email")]);
    let der = leaf(&ca, vec![email("one@example.org")]);
    assert_eq!(
        provider.authenticate(attempt(&[&der], true)).unwrap(),
        found("email", "one@example.org")
    );
}

#[test]
fn a_upn_with_its_domain_names_the_account_by_name() {
    let directory = tempfile::tempdir().unwrap();
    let ca = authority("Root");
    let provider = trusting(
        directory.path(),
        &ca,
        vec![Pick::new("san.upn", "name").domain("corp.example")],
    );
    let der = leaf(&ca, vec![upn("alice@CORP.example")]);
    assert_eq!(
        provider.authenticate(attempt(&[&der], true)).unwrap(),
        found("name", "alice")
    );
}

#[test]
fn two_emails_are_ambiguous_and_invalid() {
    let directory = tempfile::tempdir().unwrap();
    let ca = authority("Root");
    let provider = trusting(directory.path(), &ca, vec![Pick::new("san.email", "email")]);
    let der = leaf(
        &ca,
        vec![email("one@example.org"), email("two@example.org")],
    );
    assert_eq!(
        provider.authenticate(attempt(&[&der], true)).unwrap(),
        Verdict::Invalid
    );
}

#[test]
fn another_ca_or_an_insecure_attempt_is_unknown() {
    let directory = tempfile::tempdir().unwrap();
    let (ca, other) = (authority("Root"), authority("Other"));
    let provider = trusting(directory.path(), &ca, vec![Pick::new("san.email", "email")]);
    let stranger = leaf(&other, vec![email("one@example.org")]);
    assert_eq!(
        provider.authenticate(attempt(&[&stranger], true)).unwrap(),
        Verdict::Unknown
    );
    let ours = leaf(&ca, vec![email("one@example.org")]);
    assert_eq!(
        provider.authenticate(attempt(&[&ours], false)).unwrap(),
        Verdict::Unknown
    );
    assert_eq!(
        provider.authenticate(Attempt::default()).unwrap(),
        Verdict::Unknown
    );
}

#[test]
fn the_default_account_is_the_certificate_fingerprint() {
    let directory = tempfile::tempdir().unwrap();
    let ca = authority("Root");
    let provider = MtlsAccounts::builder()
        .trust(TrustMode::Ca)
        .ca(ca_file(directory.path(), &ca))
        .build()
        .unwrap();
    let der = leaf(&ca, vec![email("one@example.org")]);
    assert_eq!(
        provider.authenticate(attempt(&[&der], true)).unwrap(),
        found("certificate", &PeerId::of(&der).canonical())
    );
}

#[test]
fn an_ip_written_as_an_ip_or_a_dns_name_or_both_names_one_address() {
    let directory = tempfile::tempdir().unwrap();
    let ca = authority("Root");
    let provider = trusting(directory.path(), &ca, vec![Pick::new("san.ip", "address")]);
    for names in [
        vec![dns("10.0.0.9")],
        vec![ip("10.0.0.9")],
        vec![ip("10.0.0.9"), dns("10.0.0.9")],
        vec![ip("::ffff:10.0.0.9")],
    ] {
        let der = leaf(&ca, names.clone());
        assert_eq!(
            provider.authenticate(attempt(&[&der], true)).unwrap(),
            found("address", "10.0.0.9"),
            "{names:?}"
        );
    }
    let strict = trusting(
        directory.path(),
        &ca,
        vec![Pick::new("san.ip", "address").ip_in_dns(false)],
    );
    let dns_only = leaf(&ca, vec![dns("10.0.0.9")]);
    assert_eq!(
        strict.authenticate(attempt(&[&dns_only], true)).unwrap(),
        Verdict::Unknown
    );
}

#[test]
fn a_san_glob_for_an_ip_matches_it_written_either_way() {
    let directory = tempfile::tempdir().unwrap();
    let ca = authority("Root");
    let mut policy = ca_file(directory.path(), &ca);
    policy.san = vec!["ip:10.0.0.*".to_owned()];
    let provider = MtlsAccounts::builder()
        .trust(TrustMode::Ca)
        .ca(policy)
        .account(vec![Pick::new("subject.cn", "name")])
        .build()
        .unwrap();
    for names in [vec![dns("10.0.0.9")], vec![ip("10.0.0.9")]] {
        let der = leaf(&ca, names);
        assert_eq!(
            provider.authenticate(attempt(&[&der], true)).unwrap(),
            found("name", "Client One")
        );
    }
    let elsewhere = leaf(&ca, vec![ip("10.0.1.9")]);
    assert_eq!(
        provider.authenticate(attempt(&[&elsewhere], true)).unwrap(),
        Verdict::Unknown
    );
}

#[test]
fn pinned_or_ca_takes_a_pinned_certificate_from_an_unknown_ca() {
    let directory = tempfile::tempdir().unwrap();
    let (ca, other) = (authority("Root"), authority("Other"));
    let pinned = leaf(&other, vec![email("pinned@example.org")]);
    let provider = MtlsAccounts::builder()
        .trust(TrustMode::PinnedOrCa)
        .ca(ca_file(directory.path(), &ca))
        .account(vec![Pick::new("san.email", "email")])
        .table(Arc::new(MemoryTable::from_records([PeerRecord::new(
            "peer-1",
            "site-a",
            &PeerId::of(&pinned),
        )])))
        .build()
        .unwrap();
    assert_eq!(
        provider.authenticate(attempt(&[&pinned], true)).unwrap(),
        found("id", "peer-1")
    );
    let by_ca = leaf(&ca, vec![email("one@example.org")]);
    assert_eq!(
        provider.authenticate(attempt(&[&by_ca], true)).unwrap(),
        found("email", "one@example.org")
    );
}

#[test]
fn a_ca_trust_without_a_ca_file_is_refused_and_a_long_chain_is_unknown() {
    assert!(
        MtlsAccounts::builder()
            .trust(TrustMode::Ca)
            .build()
            .is_err()
    );
    let directory = tempfile::tempdir().unwrap();
    let ca = authority("Root");
    let provider = MtlsAccounts::builder()
        .trust(TrustMode::Ca)
        .ca(ca_file(directory.path(), &ca))
        .account(vec![Pick::new("san.email", "email")])
        .max_chain(coqui_access::Limit::at(1))
        .build()
        .unwrap();
    let der = leaf(&ca, vec![email("one@example.org")]);
    assert_eq!(
        provider.authenticate(attempt(&[&der, &der], true)).unwrap(),
        Verdict::Unknown
    );
}
