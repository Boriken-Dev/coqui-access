//! Client certificates a reverse proxy forwards, in each proxy's encoding.

use coqui_access::{Attempt, Authenticator, Limit, Lookup, Verdict};
use coqui_access_kit::pick::Pick;
use coqui_access_proxy::{CertificateEncoding, ProxyWord, ProxyWordConfig};
use data_encoding::BASE64;
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use rcgen::{CertificateParams, DnType, KeyPair, SanType};

struct Client {
    pem: String,
    der: Vec<u8>,
}

fn client(names: Vec<SanType>) -> Client {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(DnType::CommonName, "Client One");
    params.subject_alt_names = names;
    let certificate = params.self_signed(&KeyPair::generate().unwrap()).unwrap();
    Client {
        pem: certificate.pem(),
        der: certificate.der().to_vec(),
    }
}

fn email(address: &str) -> SanType {
    SanType::Rfc822Name(address.try_into().unwrap())
}

fn proxy(encoding: CertificateEncoding, account: Vec<Pick>) -> ProxyWord {
    let mut config = ProxyWordConfig::default();
    config.trusted = vec!["10.0.0.0/24".to_owned()];
    config.certificate_header = Some("x-client-cert".to_owned());
    config.certificate_encoding = encoding;
    config.account = account;
    ProxyWord::new(config).unwrap()
}

fn from_proxy(headers: &[(&str, String)]) -> Attempt {
    Attempt {
        peer: Some("10.0.0.2:443".to_owned()),
        headers: headers
            .iter()
            .map(|(name, value)| ((*name).to_owned(), value.clone()))
            .collect(),
        ..Attempt::default()
    }
}

fn url(text: &str) -> String {
    utf8_percent_encode(text, NON_ALPHANUMERIC).to_string()
}

fn by_email(address: &str) -> Verdict {
    Verdict::Valid(Lookup {
        by: "email".to_owned(),
        value: address.to_owned(),
    })
}

#[test]
fn every_proxy_encoding_names_the_same_account() {
    let one = client(vec![email("one@example.org")]);
    let other = client(vec![email("other@example.org")]);
    let account = vec![Pick::new("san.email", "email")];
    let envoy = format!(
        "By=spiffe://edge;Hash=00;Cert=\"{}\",By=spiffe://backend;Hash=ab;Cert=\"{}\";Subject=\"CN=Client One,O=a\\\"b\";URI=",
        url(&other.pem),
        url(&one.pem)
    );
    for (encoding, value) in [
        (CertificateEncoding::PemUrl, url(&one.pem)),
        (CertificateEncoding::DerBase64, BASE64.encode(&one.der)),
        (
            CertificateEncoding::DerBase64,
            format!("{},{}", BASE64.encode(&one.der), BASE64.encode(&other.der)),
        ),
        (CertificateEncoding::Xfcc, envoy),
    ] {
        let verdict = proxy(encoding, account.clone())
            .authenticate(from_proxy(&[("X-Client-Cert", value)]))
            .unwrap();
        assert_eq!(verdict, by_email("one@example.org"), "{encoding:?}");
    }
}

#[test]
fn the_default_account_is_the_subject_cn_and_an_ip_in_a_dns_name_counts() {
    let one = client(vec![SanType::DnsName("10.0.0.9".try_into().unwrap())]);
    let verdict = proxy(
        CertificateEncoding::PemUrl,
        coqui_access_proxy::default_account(),
    )
    .authenticate(from_proxy(&[("x-client-cert", url(&one.pem))]))
    .unwrap();
    assert_eq!(
        verdict,
        Verdict::Valid(Lookup {
            by: "name".to_owned(),
            value: "Client One".to_owned(),
        })
    );
    let by_ip = proxy(
        CertificateEncoding::PemUrl,
        vec![Pick::new("san.ip", "address")],
    )
    .authenticate(from_proxy(&[("x-client-cert", url(&one.pem))]))
    .unwrap();
    assert_eq!(
        by_ip,
        Verdict::Valid(Lookup {
            by: "address".to_owned(),
            value: "10.0.0.9".to_owned(),
        })
    );
}

#[test]
fn an_unreadable_oversized_or_repeated_certificate_header_is_invalid() {
    let one = client(vec![email("one@example.org")]);
    let account = vec![Pick::new("san.email", "email")];
    let checked = proxy(CertificateEncoding::PemUrl, account.clone());
    for headers in [
        vec![("x-client-cert", "not a certificate".to_owned())],
        vec![
            ("x-client-cert", url(&one.pem)),
            ("X-Client-Cert", url(&one.pem)),
        ],
    ] {
        assert_eq!(
            checked.authenticate(from_proxy(&headers)).unwrap(),
            Verdict::Invalid
        );
    }
    let mut small = ProxyWordConfig::default();
    small.trusted = vec!["10.0.0.0/24".to_owned()];
    small.certificate_header = Some("x-client-cert".to_owned());
    small.account = account;
    small.max_certificate_bytes = Limit::at(64);
    assert_eq!(
        ProxyWord::new(small)
            .unwrap()
            .authenticate(from_proxy(&[("x-client-cert", url(&one.pem))]))
            .unwrap(),
        Verdict::Invalid
    );
}

#[test]
fn a_user_header_comes_first_then_the_certificate_then_the_subject() {
    let one = client(vec![email("one@example.org")]);
    let mut config = ProxyWordConfig::default();
    config.trusted = vec!["10.0.0.0/24".to_owned()];
    config.user_header = Some("x-remote-user".to_owned());
    config.certificate_header = Some("x-client-cert".to_owned());
    config.subject_header = Some("x-client-subject".to_owned());
    config.account = vec![
        Pick::new("san.email", "email"),
        Pick::new("subject.o", "group"),
    ];
    let proxy = ProxyWord::new(config).unwrap();
    let all = [
        ("x-remote-user", "alice".to_owned()),
        ("x-client-cert", url(&one.pem)),
        ("x-client-subject", "CN=Doe,O=Ops".to_owned()),
    ];
    assert_eq!(
        proxy.authenticate(from_proxy(&all)).unwrap(),
        Verdict::Valid(Lookup {
            by: "name".to_owned(),
            value: "alice".to_owned(),
        })
    );
    assert_eq!(
        proxy.authenticate(from_proxy(&all[1..])).unwrap(),
        by_email("one@example.org")
    );
    assert_eq!(
        proxy.authenticate(from_proxy(&all[2..])).unwrap(),
        Verdict::Valid(Lookup {
            by: "group".to_owned(),
            value: "Ops".to_owned(),
        })
    );
    let mut untrusted = from_proxy(&all[1..]);
    untrusted.peer = Some("192.0.2.1:443".to_owned());
    assert_eq!(proxy.authenticate(untrusted).unwrap(), Verdict::Unknown);
}
