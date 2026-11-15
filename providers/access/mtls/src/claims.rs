//! What a client certificate says, as the claims a matcher reads.

use std::collections::BTreeMap;

use coqui_access::Claims;
use coqui_access::guatiao::Bytes;
use coqui_peer_tls::CertificateFields;

use crate::Pin;

/// The claims of a leaf certificate, or `None` when it does not parse.
///
/// The certificate's own named fields (`subject.cn`, `san.upn`, `san.email`, `san.dns`,
/// `san.uri`, `san.ip`, `fingerprint`, ...) with `subject`, `issuer` and `serial` named
/// `subject.dn`, `issuer.dn` and `serial.hex`, `serial.reversed` (the serial's bytes last
/// first, as a directory that spells them that way wants), `spki` and the DER itself.
pub(crate) fn of_certificate(der: &[u8]) -> Option<Claims> {
    let fields = CertificateFields::parse(der).ok()?;
    let mut values: BTreeMap<String, Vec<String>> = fields.to_map();
    for (from, to) in [
        ("subject", "subject.dn"),
        ("issuer", "issuer.dn"),
        ("serial", "serial.hex"),
    ] {
        if let Some(found) = values.remove(from) {
            values.insert(to.to_owned(), found);
        }
    }
    if let Some(serial) = values.get("serial.hex").and_then(|found| found.first()) {
        values.insert("serial.reversed".to_owned(), vec![reversed(serial)]);
    }
    if let Some(key) = Pin::key_of_certificate(der) {
        values.insert("spki".to_owned(), vec![key.value]);
    }
    Some(Claims {
        values,
        certificate: Some(Bytes::from(der.to_vec())),
    })
}

/// The bytes of a hex string in the opposite order: `0a1b2c` is `2c1b0a`. An odd length is
/// padded with a leading zero first, as the serial's own bytes would be.
fn reversed(hex: &str) -> String {
    let padded = if hex.len() % 2 == 1 {
        format!("0{hex}")
    } else {
        hex.to_owned()
    };
    padded
        .as_bytes()
        .chunks(2)
        .rev()
        .map(|pair| String::from_utf8_lossy(pair).into_owned())
        .collect()
}
