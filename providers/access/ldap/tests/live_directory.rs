use std::env;

use coqui_access::guatiao::{FromValue, Map};
use coqui_access::{Attempt, Authenticator, Directory, Lookup, Verdict};
use coqui_access_ldap::{LdapAccounts, LdapAccountsConfig};

fn required(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("set {name} for the live LDAP test"))
}

fn attempt(name: String, secret: String) -> Attempt {
    Attempt {
        name: Some(name),
        secret: Some(secret),
        headers: Vec::new(),
        peer: None,
        secure: Some(false),
        certificate: None,
        certificates: None,
    }
}

fn config() -> LdapAccountsConfig {
    let base = required("COQUI_TEST_LDAP_BASE");
    let mut value = Map::new();
    value.set("url", required("COQUI_TEST_LDAP_URL"));
    value.set("base", base.clone());
    value.set("bind", required("COQUI_TEST_LDAP_BIND"));
    value.set("bind_password", required("COQUI_TEST_LDAP_BIND_PASSWORD"));
    value.set("user_filter", "(uid={name})");
    value.set("name_attribute", "uid");
    value.set("group_attribute", "");
    value.set("group_filter", "(&(objectClass=groupOfNames)(member={dn}))");
    value.set("group_base", format!("ou=groups,{base}"));
    value.set("timeout_seconds", 5_u32);
    LdapAccountsConfig::from_value(&value.into())
        .expect("the disposable LDAP configuration should match the provider schema")
}

#[test]
#[ignore = "requires a disposable LDAP server; set COQUI_TEST_LDAP_* and pass --ignored"]
fn authenticates_accounts_and_resolves_directory_groups() {
    assert_eq!(
        required("COQUI_TEST_LDAP"),
        "1",
        "set COQUI_TEST_LDAP=1 to confirm this is a disposable directory"
    );
    let user = required("COQUI_TEST_LDAP_USER");
    let base = required("COQUI_TEST_LDAP_BASE");
    let provider = LdapAccounts::new(config()).expect("the throwaway LDAP config is valid");

    assert_eq!(
        provider
            .authenticate(attempt(
                user.clone(),
                required("COQUI_TEST_LDAP_WRONG_PASSWORD"),
            ))
            .expect("LDAP should answer the rejected-password check"),
        Verdict::Invalid
    );

    let lookup = provider
        .authenticate(attempt(user.clone(), required("COQUI_TEST_LDAP_PASSWORD")))
        .expect("LDAP should answer the valid-password check");
    let Verdict::Valid(lookup) = lookup else {
        panic!("the seeded LDAP account should authenticate");
    };
    assert_eq!(lookup.by, "name");
    assert_eq!(lookup.value, user);

    let person = provider
        .lookup(Lookup {
            by: lookup.by,
            value: lookup.value,
        })
        .expect("the directory should answer the account lookup")
        .expect("the authenticated account should resolve");
    assert_eq!(person.name, user);
    assert_eq!(person.id, format!("uid={user},ou=people,{base}"));
    assert_eq!(person.groups, ["operators"]);
}
