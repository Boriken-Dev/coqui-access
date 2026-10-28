//! Signs a real account in through the operating system. Ignored by default: run against a
//! throwaway account made for the purpose, never a real one, with
//!
//! - `COQUI_ACCESS_TEST_SYSTEM_USER`: the account's name;
//! - `COQUI_ACCESS_TEST_SYSTEM_PASSWORD`: its password;
//! - `COQUI_ACCESS_TEST_SYSTEM_GROUP`: a group it belongs to (optional);
//! - `COQUI_ACCESS_TEST_SYSTEM_PAM_SERVICE`: the PAM service (Unix; default `coqui-access`).
//!
//! `cargo test -p coqui-access-system --test real_login -- --include-ignored`. Under
//! `pam_unix` (Linux, FreeBSD) checking another account's password needs root.

use coqui_access::{Attempt, Authenticator, Directory, Lookup, Verdict};
use coqui_access_system::{SystemAccounts, SystemAccountsBuilder};

struct Throwaway {
    user: String,
    password: String,
    group: Option<String>,
    accounts: SystemAccounts,
    builder: SystemAccountsBuilder,
}

fn throwaway() -> Throwaway {
    let variable = |name: &str| std::env::var(format!("COQUI_ACCESS_TEST_SYSTEM_{name}")).ok();
    let user = variable("USER").expect("COQUI_ACCESS_TEST_SYSTEM_USER names the account");
    let password = variable("PASSWORD").expect("COQUI_ACCESS_TEST_SYSTEM_PASSWORD is its password");
    let mut builder = SystemAccounts::builder();
    if let Some(service) = variable("PAM_SERVICE") {
        builder = builder.pam_service(service);
    }
    Throwaway {
        user,
        password,
        group: variable("GROUP"),
        accounts: builder.clone().build().expect("the provider builds"),
        builder,
    }
}

fn attempt(user: &str, password: &str) -> Attempt {
    Attempt {
        name: Some(user.to_owned()),
        secret: Some(password.to_owned()),
        ..Attempt::default()
    }
}

#[test]
#[ignore = "needs a throwaway OS account named by COQUI_ACCESS_TEST_SYSTEM_USER"]
fn the_right_password_signs_in_and_names_the_account_by_id() {
    let account = throwaway();
    let Verdict::Valid(lookup) = account
        .accounts
        .authenticate(attempt(&account.user, &account.password))
        .unwrap()
    else {
        panic!("the throwaway account's password is refused");
    };
    assert_eq!(lookup.by, "id");
    let person = account.accounts.lookup(lookup.clone()).unwrap().unwrap();
    assert_eq!(person.id, lookup.value);
    assert!(person.name.eq_ignore_ascii_case(&account.user));
    if let Some(group) = &account.group {
        assert!(person.groups.contains(group), "{:?}", person.groups);
    }
    let by_name = account
        .accounts
        .lookup(Lookup {
            by: "name".to_owned(),
            value: account.user.clone(),
        })
        .unwrap()
        .unwrap();
    assert_eq!(by_name.id, person.id);
}

#[test]
#[ignore = "needs a throwaway OS account named by COQUI_ACCESS_TEST_SYSTEM_USER"]
fn a_wrong_password_is_invalid() {
    let account = throwaway();
    let wrong = format!("{}-wrong", account.password);
    assert_eq!(
        account
            .accounts
            .authenticate(attempt(&account.user, &wrong))
            .unwrap(),
        Verdict::Invalid
    );
}

#[test]
#[ignore = "needs a throwaway OS account named by COQUI_ACCESS_TEST_SYSTEM_USER"]
fn an_unknown_account_is_unknown_and_not_found() {
    let account = throwaway();
    let nobody = format!("{}-nobody", account.user);
    assert_eq!(
        account
            .accounts
            .authenticate(attempt(&nobody, &account.password))
            .unwrap(),
        Verdict::Unknown
    );
    let lookup = Lookup {
        by: "name".to_owned(),
        value: nobody,
    };
    assert_eq!(account.accounts.lookup(lookup).unwrap(), None);
}

#[test]
#[ignore = "needs a throwaway OS account named by COQUI_ACCESS_TEST_SYSTEM_USER"]
fn a_group_the_account_is_not_in_keeps_it_out() {
    let account = throwaway();
    let narrowed = account
        .builder
        .clone()
        .groups(["coqui-no-such-group"])
        .build()
        .unwrap();
    assert_eq!(
        narrowed
            .authenticate(attempt(&account.user, &account.password))
            .unwrap(),
        Verdict::Unknown
    );
}
