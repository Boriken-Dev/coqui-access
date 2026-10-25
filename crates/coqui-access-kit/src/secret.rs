//! Secrets that are made, not chosen, and what is kept of them.

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Characters of base64url text that 32 random bytes take.
pub const SECRET_CHARS: usize = 43;

/// Makes a secret: `prefix` followed by 256 random bits as 43 URL-safe base64 characters.
///
/// Random and that long, it needs no slow hash to be kept: keep [`hash`] of it.
///
/// # Errors
///
/// Returns an error when the operating system random source is unavailable.
pub fn generate(prefix: &str) -> Result<String, String> {
    let mut random = [0u8; 32];
    getrandom::fill(&mut random).map_err(|_| "system random source is unavailable".to_owned())?;
    let mut written = String::with_capacity(prefix.len() + SECRET_CHARS);
    written.push_str(prefix);
    for three in random.chunks(3) {
        let bits = three
            .iter()
            .fold(0u32, |bits, byte| (bits << 8) | u32::from(*byte));
        let bits = bits << (8 * (3 - three.len()));
        // Three bytes are four characters; two are three; one is two.
        for letter in 0..=three.len() {
            let six = (bits >> (18 - 6 * letter)) & 0x3f;
            written.push(char::from(ALPHABET[six as usize]));
        }
    }
    Ok(written)
}

/// Makes a random 128-bit identifier as 32 lowercase hexadecimal characters.
///
/// # Errors
///
/// Returns an error when the operating system random source is unavailable.
pub fn identifier() -> Result<String, String> {
    let mut random = [0u8; 16];
    getrandom::fill(&mut random).map_err(|_| "system random source is unavailable".to_owned())?;
    Ok(hex(&random))
}

/// What a secret is kept as: its SHA-256 as 64 lowercase hexadecimal characters.
///
/// With a `domain`, the digest is over `domain`, a zero byte, then the secret, so a digest
/// kept for one purpose cannot be presented for another.
pub fn hash(secret: &str, domain: Option<&str>) -> String {
    let mut digest = Sha256::new();
    if let Some(domain) = domain {
        digest.update(domain.as_bytes());
        digest.update([0]);
    }
    digest.update(secret.as_bytes());
    hex(&digest.finalize())
}

/// The SHA-256 of `bytes` as 64 lowercase hexadecimal characters.
pub fn hash_bytes(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// Compares two strings in time that does not depend on where they differ.
pub fn same(a: &str, b: &str) -> bool {
    bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

/// Whether `value` is a SHA-256 digest as [`hash`] writes it.
pub fn is_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_is_prefixed_long_random_and_url_safe() {
        let (one, other) = (generate("ck_").unwrap(), generate("ck_").unwrap());
        assert_ne!(one, other);
        for secret in [&one, &other] {
            assert_eq!(secret.len(), 3 + SECRET_CHARS);
            let letters = secret.strip_prefix("ck_").unwrap();
            assert!(
                letters
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            );
        }
    }

    #[test]
    fn hashes_are_sha256_hex_and_domain_separated() {
        assert_eq!(
            hash("abc", None),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_ne!(hash("abc", Some("login")), hash("abc", Some("ticket")));
        assert_ne!(hash("abc", Some("login")), hash("abc", None));
        assert!(is_hash(&hash("x", None)));
        assert!(!is_hash("ABC"));
    }

    #[test]
    fn comparison_and_identifiers() {
        assert!(same("abc", "abc"));
        assert!(!same("abc", "abd") && !same("abc", "ab"));
        let id = identifier().unwrap();
        assert_eq!(id.len(), 32);
        assert_ne!(id, identifier().unwrap());
    }
}
