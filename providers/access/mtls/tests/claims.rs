//! The identity a certificate gave, answered in full as claims.

use std::path::Path;
use std::sync::Arc;

use coqui_access::{Attempt, Authenticator, Verdict};
use coqui_access_kit::MemoryTable;
use coqui_access_kit::pick::Pick;
use coqui_access_mtls::{MtlsAccounts, PeerRecord, Pin, TrustMode, default_account};
use coqui_peer_tls::{CaPolicy, PeerId};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, OtherNameValue, SanType,
};

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

/// A leaf naming one of everything, signed by `by`.
fn leaf(by: &Authority) -> Vec<u8> {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(DnType::CommonName, "Client One");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Example Org");
    params.subject_alt_names = vec![
        SanType::OtherName((
            vec![1, 3, 6, 1, 4, 1, 311, 20, 2, 3],
            OtherNameValue::Utf8String("clientone@corp.example".into()),
        )),
        SanType::Rfc822Name("one@example.org".try_into().unwrap()),
        SanType::DnsName("one.example.org".try_into().unwrap()),
        SanType::URI("urn:example:one".try_into().unwrap()),
        SanType::IpAddress("192.0.2.9".parse().unwrap()),
    ];
    let key = KeyPair::generate().unwrap();
    params.signed_by(&key, &by.issuer).unwrap().der().to_vec()
}

fn presented(der: &[u8]) -> Attempt {
    Attempt {
        secure: Some(true),
        certificates: Some(vec![der.to_vec().into()]),
        peer: Some("192.0.2.7:4000".to_owned()),
        ..Attempt::default()
    }
}

fn ca_policy(directory: &Path, authority: &Authority) -> CaPolicy {
    let file = directory.join("ca.pem");
    std::fs::write(&file, &authority.pem).unwrap();
    CaPolicy::new(file)
}

fn trusting(directory: &Path, authority: &Authority, account: Vec<Pick>) -> MtlsAccounts {
    MtlsAccounts::builder()
        .trust(TrustMode::Ca)
        .ca(ca_policy(directory, authority))
        .account(account)
        .build()
        .unwrap()
}

fn valid(verdict: Verdict) -> coqui_access::Lookup {
    match verdict {
        Verdict::Valid(lookup) => lookup,
        other => panic!("expected a valid verdict, got {other:?}"),
    }
}

fn first<'a>(claims: &'a coqui_access::Claims, name: &str) -> &'a str {
    claims
        .get(name)
        .first()
        .unwrap_or_else(|| panic!("no claim {name}"))
}

#[test]
fn a_ca_trusted_certificate_with_no_picks_answers_by_claims_with_everything_it_said() {
    let directory = tempfile::tempdir().unwrap();
    let ca = authority("Root");
    let der = leaf(&ca);
    let provider = trusting(directory.path(), &ca, default_account());
    assert!(default_account().is_empty(), "the account is the matcher's");

    let lookup = valid(provider.authenticate(presented(&der)).unwrap());
    assert_eq!(lookup.by, "claims");
    assert_eq!(lookup.value, PeerId::of(&der).canonical());
    let claims = lookup.claims.expect("the claims came with the lookup");
    assert_eq!(first(&claims, "subject.cn"), "Client One");
    assert_eq!(first(&claims, "subject.o"), "Example Org");
    assert!(first(&claims, "subject.dn").contains("CN=Client One"));
    assert_eq!(first(&claims, "issuer.cn"), "Root");
    assert!(first(&claims, "issuer.dn").contains("CN=Root"));
    assert_eq!(first(&claims, "san.upn"), "clientone@corp.example");
    assert_eq!(first(&claims, "san.email"), "one@example.org");
    assert_eq!(first(&claims, "san.dns"), "one.example.org");
    assert_eq!(first(&claims, "san.uri"), "urn:example:one");
    assert_eq!(first(&claims, "san.ip"), "192.0.2.9");
    assert_eq!(first(&claims, "fingerprint"), PeerId::of(&der).canonical());
    assert_eq!(
        first(&claims, "spki"),
        Pin::key_of_certificate(&der).unwrap().value
    );
    let serial = first(&claims, "serial.hex");
    let reversed = first(&claims, "serial.reversed");
    assert!(!serial.is_empty());
    let bytes = |text: &str| -> Vec<String> {
        let padded = if text.len() % 2 == 1 {
            format!("0{text}")
        } else {
            text.to_owned()
        };
        padded
            .as_bytes()
            .chunks(2)
            .map(|pair| String::from_utf8(pair.to_vec()).unwrap())
            .collect()
    };
    let mut forward = bytes(serial);
    forward.reverse();
    assert_eq!(forward, bytes(reversed));
    assert_eq!(
        claims.certificate.as_ref().map(AsRef::<[u8]>::as_ref),
        Some(der.as_slice())
    );
}

#[test]
fn picks_still_name_the_account_and_the_claims_ride_along() {
    let directory = tempfile::tempdir().unwrap();
    let ca = authority("Root");
    let der = leaf(&ca);
    let provider = trusting(directory.path(), &ca, vec![Pick::new("san.email", "email")]);
    let lookup = valid(provider.authenticate(presented(&der)).unwrap());
    assert_eq!(
        (lookup.by.as_str(), lookup.value.as_str()),
        ("email", "one@example.org")
    );
    assert_eq!(
        first(&lookup.claims.unwrap(), "san.upn"),
        "clientone@corp.example"
    );
}

#[test]
fn a_pinned_certificate_answers_by_id_and_carries_its_claims_when_the_chain_came() {
    let ca = authority("Root");
    let der = leaf(&ca);
    let fingerprint = PeerId::of(&der);
    let provider = MtlsAccounts::builder()
        .table(Arc::new(MemoryTable::from_records([PeerRecord::new(
            "id-1",
            "one",
            &fingerprint,
        )])))
        .build()
        .unwrap();
    let lookup = valid(provider.authenticate(presented(&der)).unwrap());
    assert_eq!((lookup.by.as_str(), lookup.value.as_str()), ("id", "id-1"));
    assert_eq!(
        first(&lookup.claims.expect("claims"), "san.email"),
        "one@example.org"
    );
    // A fingerprint alone has no certificate to read claims from.
    let alone = provider
        .authenticate(Attempt {
            certificate: Some(fingerprint.canonical()),
            ..Attempt::default()
        })
        .unwrap();
    assert_eq!(valid(alone).claims, None);
}
