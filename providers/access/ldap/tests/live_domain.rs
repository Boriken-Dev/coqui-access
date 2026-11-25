//! The Kerberos and NTLM binds against an Active Directory domain controller, read-only: binds
//! and searches, nothing written. Ignored by default; they need a domain-joined machine and the
//! settings below, and run as the signed-in domain account (SSPI's default credentials on
//! Windows, the ticket cache on Unix).
//!
//! `COQUI_TEST_DC=1` confirms the directory may be read. `COQUI_TEST_DC_URL` is `ldap://host`,
//! `ldaps://host` or `ldap://host` with `COQUI_TEST_DC_START_TLS=1`; `COQUI_TEST_DC_BASE` the
//! search root; `COQUI_TEST_DC_USER` the `sAMAccountName` of an account to find; and
//! `COQUI_TEST_DC_CA`, when set, a PEM file of the only trusted roots. The NTLM test also needs
//! `COQUI_TEST_DC_NTLM_PASSWORD` and `COQUI_TEST_DC_NTLM_WRONG_PASSWORD` for that account: it is
//! the one test that takes a password, so it fails with a message when they are not set.
//!
//! `cargo test -p coqui-access-ldap --features gssapi,ntlm --test live_domain -- --ignored`

#![cfg(any(feature = "gssapi", feature = "ntlm"))]

use std::env;

use coqui_access::guatiao::{FromValue, Map};
use coqui_access::{Attempt, Authenticator, Directory, Lookup, Verdict};
use coqui_access_ldap::{LdapAccounts, LdapAccountsConfig};
use guatiao_builder::Described;

fn required(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("set {name} for the domain controller test"))
}

fn provider(more: impl FnOnce(&mut Map)) -> LdapAccounts {
    assert_eq!(
        required("COQUI_TEST_DC"),
        "1",
        "set COQUI_TEST_DC=1 to confirm this directory may be read"
    );
    let mut value = Map::new();
    value.set("url", required("COQUI_TEST_DC_URL"));
    value.set("base", required("COQUI_TEST_DC_BASE"));
    value.set("timeout_seconds", 20_u32);
    if env::var("COQUI_TEST_DC_START_TLS").as_deref() == Ok("1") {
        value.set("start_tls", true);
    }
    if let Some(ca) = env::var("COQUI_TEST_DC_CA")
        .ok()
        .filter(|ca| !ca.is_empty())
    {
        value.set("ca_file", ca);
    }
    more(&mut value);
    let config = Described::<LdapAccountsConfig>::from_value(&value.into())
        .expect("the settings match the provider schema")
        .0;
    LdapAccounts::new(config).expect("the settings are valid")
}

fn find(accounts: &LdapAccounts, user: &str) -> coqui_access::Person {
    accounts
        .lookup(Lookup {
            by: "name".to_owned(),
            value: user.to_owned(),
            ..Lookup::default()
        })
        .expect("the domain controller answers the lookup")
        .expect("the account exists")
}

#[cfg(feature = "gssapi")]
#[test]
#[ignore = "needs a domain controller; see the file's documentation"]
fn gssapi_binds_as_the_signed_in_account_and_searches() {
    let user = required("COQUI_TEST_DC_USER");
    let accounts = provider(|value| value.set("bind_method", "gssapi"));
    let person = find(&accounts, &user);
    assert!(person.name.eq_ignore_ascii_case(&user));
    assert!(person.id.to_ascii_lowercase().contains("dc="));
}

#[cfg(all(feature = "gssapi", feature = "ntlm"))]
#[test]
#[ignore = "needs a domain controller and an account's passwords; see the file's documentation"]
fn ntlm_checks_a_known_good_and_a_wrong_password() {
    let user = required("COQUI_TEST_DC_USER");
    let accounts = provider(|value| {
        value.set("bind_method", "gssapi");
        value.set("user_bind", "ntlm");
        value.set("allow_cleartext_password", false);
    });
    let attempt = |secret: String| Attempt {
        name: Some(user.clone()),
        secret: Some(secret),
        headers: Vec::new(),
        peer: None,
        secure: Some(false),
        certificate: None,
        certificates: None,
        method: None,
        challenge: None,
    };
    let Verdict::Valid(valid) = accounts
        .authenticate(attempt(required("COQUI_TEST_DC_NTLM_PASSWORD")))
        .expect("the domain controller answers")
    else {
        panic!("the known-good password is accepted");
    };
    assert!(valid.value.eq_ignore_ascii_case(&user));
    assert_eq!(
        accounts
            .authenticate(attempt(required("COQUI_TEST_DC_NTLM_WRONG_PASSWORD")))
            .expect("the domain controller answers"),
        Verdict::Invalid
    );
}
