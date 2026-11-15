//! The contract, pinned.
//!
//! A provider library built against this crate keeps working with a newer host only while
//! two things hold, and the compiler checks neither:
//!
//! - the **tables**: each kind's name and the hash Guatiao takes over its required methods'
//!   names and their argument and return types as written;
//! - the **required keys** of each model: a field that is not an `Option`.
//!
//! A failure here is not a test to update in passing: it means every provider library
//! already built stops loading (a table) or starts failing at its first call (a key).
//! `kinds.json` is the same contract as data, for bindings and generators.

use std::fmt::Debug;
use std::path::PathBuf;

use coqui_access::guatiao::library::Kind;
use coqui_access::guatiao::library::kind::kind_document;
use coqui_access::guatiao::{FromValue, Map, ToValue, Value};
use coqui_access::{
    AccountInfo, AccountPut, Accounts, Attempt, Authenticator, AuthorizationDecision,
    AuthorizationRequest, Authorizer, Description, Directory, Factor, Lookup, Offer, Person,
    PutOutcome, SignInContext, SignInDecision, SignInPolicy, Verdict, Waiting,
};
use guatiao_serde::Presentation;
use guatiao_serde::text::json;

fn table<K: ?Sized + Kind>() -> (&'static str, bool, u32) {
    (K::NAME, K::OBJECT, K::FLOOR_HASH)
}

#[test]
fn every_kind_has_the_table_built_providers_were_built_against() {
    assert_eq!(
        [
            table::<dyn Authenticator>(),
            table::<dyn Directory>(),
            table::<dyn Authorizer>(),
            table::<dyn Accounts>(),
            table::<dyn SignInPolicy>(),
        ],
        [
            ("coqui_authenticator", false, PINNED_AUTHENTICATOR),
            ("coqui_directory", false, PINNED_DIRECTORY),
            ("coqui_authorizer", false, PINNED_AUTHORIZER),
            ("coqui_accounts", false, PINNED_ACCOUNTS),
            ("coqui_sign_in_policy", false, PINNED_SIGN_IN_POLICY),
        ],
        "a required method of a kind changed, or a type one of them names was renamed: \
         every provider library built before this change is now refused at load. \
         Add a method with a default body after the required ones instead."
    );
}

/// The keys a model writes when every optional field is absent: the ones a reader cannot
/// do without.
fn required<T: Default + ToValue>() -> Vec<String> {
    let value = T::default().to_value().expect("a model converts");
    let map = Map::try_from(value).expect("a model is a map");
    let mut keys: Vec<String> = map.iter().map(|entry| entry.key().to_string()).collect();
    keys.sort();
    keys
}

/// A model written by a newer build, with a key this build has never heard of, still reads.
fn reads_past_what_it_does_not_know<T>() -> Vec<String>
where
    T: Default + ToValue + FromValue + PartialEq + Debug,
{
    let value = T::default().to_value().expect("a model converts");
    let mut map = Map::try_from(value).expect("a model is a map");
    map.set("added_by_a_later_version", "anything");
    let read = T::from_value(&Value::from(map)).expect("an unknown key is skipped");
    assert_eq!(read, T::default());
    required::<T>()
}

fn keys(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

#[test]
fn every_model_requires_the_keys_it_always_did_and_skips_ones_it_does_not_know() {
    assert_eq!(reads_past_what_it_does_not_know::<Description>(), keys(&[]));
    assert_eq!(
        reads_past_what_it_does_not_know::<Attempt>(),
        keys(&["headers"])
    );
    assert_eq!(
        reads_past_what_it_does_not_know::<Lookup>(),
        keys(&["by", "value"])
    );
    assert_eq!(
        reads_past_what_it_does_not_know::<Person>(),
        keys(&["attributes", "groups", "id", "name"])
    );
    assert_eq!(
        reads_past_what_it_does_not_know::<AuthorizationRequest>(),
        keys(&["action", "person", "resource"])
    );
    assert_eq!(
        reads_past_what_it_does_not_know::<AuthorizationDecision>(),
        keys(&["allowed", "limits"])
    );
    assert_eq!(
        reads_past_what_it_does_not_know::<AccountInfo>(),
        keys(&["groups", "id", "name"])
    );
    assert_eq!(
        reads_past_what_it_does_not_know::<AccountPut>(),
        keys(&["name"])
    );
    assert_eq!(reads_past_what_it_does_not_know::<PutOutcome>(), keys(&[]));
    assert_eq!(
        reads_past_what_it_does_not_know::<Waiting>(),
        keys(&["shown"])
    );
    assert_eq!(
        reads_past_what_it_does_not_know::<SignInContext>(),
        keys(&["done", "purpose"])
    );
    assert_eq!(
        reads_past_what_it_does_not_know::<SignInDecision>(),
        keys(&["complete", "methods"])
    );
    assert_eq!(
        reads_past_what_it_does_not_know::<Factor>(),
        keys(&["method"])
    );
    assert_eq!(
        reads_past_what_it_does_not_know::<Offer>(),
        keys(&["method"])
    );
}

/// A request written before `method` existed still reads, and says no method.
#[test]
fn an_attempt_written_before_method_existed_still_reads() {
    let mut map = Map::new();
    map.set("headers", Vec::<String>::new().to_value().unwrap());
    map.set("name", "alice");
    let read = Attempt::from_value(&Value::from(map)).expect("an old attempt reads");
    assert_eq!(read.method, None);
    assert_eq!(read.name.as_deref(), Some("alice"));
}

#[test]
fn each_sign_in_model_round_trips_with_every_field_set() {
    let context = SignInContext {
        purpose: "sign_in".to_owned(),
        done: vec![Factor {
            method: "password".to_owned(),
            provider: Some("coqui_access_password".to_owned()),
        }],
        address: Some("192.0.2.7".to_owned()),
        client: Some("browser".to_owned()),
        service: Some("portal".to_owned()),
        time_unix: Some(1_700_000_000),
        person: Some(Person {
            id: "p1".to_owned(),
            name: "alice".to_owned(),
            ..Person::default()
        }),
        attributes: [("tab".to_owned(), "x".to_value().unwrap())].into(),
    };
    let decision = SignInDecision {
        complete: false,
        methods: vec![Offer {
            method: "totp".to_owned(),
            providers: vec!["coqui_access_totp".to_owned()],
        }],
        rule: Some("outside".to_owned()),
        limits: [("session_seconds".to_owned(), 60u32.to_value().unwrap())].into(),
    };
    let value = context.to_value().unwrap();
    assert_eq!(SignInContext::from_value(&value).unwrap(), context);
    let value = decision.to_value().unwrap();
    assert_eq!(SignInDecision::from_value(&value).unwrap(), decision);
    let outcome = PutOutcome {
        secret: Some("s".to_owned()),
        codes: Some(vec!["a".to_owned(), "b".to_owned()]),
    };
    let value = outcome.to_value().unwrap();
    assert_eq!(PutOutcome::from_value(&value).unwrap(), outcome);
    let put = AccountPut {
        name: "alice".to_owned(),
        display_name: Some("Alice".to_owned()),
        ..AccountPut::default()
    };
    let value = put.to_value().unwrap();
    assert_eq!(AccountPut::from_value(&value).unwrap(), put);
}

/// A debug line is read in logs: it holds words and counts, never an identity or a code.
#[test]
fn a_debug_line_of_a_sign_in_model_holds_no_identity_address_or_code() {
    let context = SignInContext {
        purpose: "sign_in".to_owned(),
        address: Some("192.0.2.77".to_owned()),
        person: Some(Person {
            id: "identity-7".to_owned(),
            name: "alice-secret-name".to_owned(),
            ..Person::default()
        }),
        ..SignInContext::default()
    };
    let shown = format!("{context:?}");
    for leaked in ["192.0.2.77", "identity-7", "alice-secret-name"] {
        assert!(!shown.contains(leaked), "{shown}");
    }
    assert!(shown.contains("sign_in"));
    let outcome = PutOutcome {
        secret: Some("hunter2-secret".to_owned()),
        codes: Some(vec!["CODE-AAAA".to_owned()]),
    };
    let shown = format!("{outcome:?}");
    assert!(
        !shown.contains("hunter2") && !shown.contains("CODE-AAAA"),
        "{shown}"
    );
    let attempt = Attempt {
        method: Some("totp".to_owned()),
        ..Attempt::default()
    };
    assert!(format!("{attempt:?}").contains("totp"));
}

#[test]
fn a_verdict_round_trips_in_each_form() {
    let valid = Verdict::Valid(Lookup {
        by: "id".to_owned(),
        value: "x".to_owned(),
    });
    for verdict in [Verdict::Unknown, Verdict::Invalid, valid] {
        let value = verdict.to_value().unwrap();
        assert_eq!(Verdict::from_value(&value).unwrap(), verdict);
    }
}

/// Every kind as one document, in declaration order.
fn rendered() -> String {
    let document = kind_document(&[
        <dyn Authenticator as Kind>::describe,
        <dyn Directory as Kind>::describe,
        <dyn Authorizer as Kind>::describe,
        <dyn Accounts as Kind>::describe,
        <dyn SignInPolicy as Kind>::describe,
    ]);
    let value = json::from_str(
        &document,
        coqui_access::guatiao::Alloc::rust(),
        Presentation::new(),
    )
    .expect("a kind description is JSON");
    let mut text = json::to_string_pretty(&value, Presentation::new()).expect("written");
    text.push('\n');
    text
}

#[test]
fn the_committed_description_is_what_this_build_describes() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("kinds.json");
    let fresh = rendered();
    if std::env::var_os("GUATIAO_WRITE_HEADER").is_some() {
        std::fs::write(&path, &fresh).expect("the description is written");
    }
    let committed = std::fs::read_to_string(&path).expect("kinds.json is committed");
    assert!(
        committed == fresh,
        "kinds.json is not what this build describes. Regenerate it only for a change that \
         means to break providers:\n  GUATIAO_WRITE_HEADER=1 cargo test -p coqui-access --test contract"
    );
}

const PINNED_AUTHENTICATOR: u32 = 3_375_864_644;
const PINNED_DIRECTORY: u32 = 2_407_154_769;
const PINNED_AUTHORIZER: u32 = 2_693_612_885;
const PINNED_ACCOUNTS: u32 = 610_858_279;
const PINNED_SIGN_IN_POLICY: u32 = 3_582_266_584;
