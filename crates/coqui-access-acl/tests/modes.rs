//! Each evaluation mode on one flat ACL.

use coqui_access::guatiao::{Alloc, FromValue, ToValue};
use coqui_access::{Person, Subject};
use coqui_access_acl::{
    Acl, AclError, Context, Decision, Entry, Inherit, ItemAcl, Limits, Mode, OnMissing, Options,
    Principal, Rights, RightsSchema, Weakening,
};
use guatiao_serde::Presentation;
use guatiao_serde::text::json;

fn subject(text: &str) -> Subject {
    text.parse().unwrap()
}

fn person(name: &str, groups: &[&str]) -> Person {
    Person {
        id: format!("id-{name}"),
        name: name.to_owned(),
        groups: groups.iter().map(|group| (*group).to_owned()).collect(),
        ..Person::default()
    }
}

fn schema() -> RightsSchema {
    RightsSchema::builder()
        .rights(["read", "write", "delete"])
        .alias("modify", ["read", "write"])
        .alias("full", ["modify", "delete"])
        .cancel("no_access")
        .build()
        .unwrap()
}

fn check(acl: &Acl, who: &Person, wanted: &[&str]) -> Decision {
    let schema = schema();
    acl.check(
        &Context::new(&schema).person(who),
        &schema.rights(wanted).unwrap(),
    )
    .unwrap()
}

#[test]
fn ordered_an_allow_before_a_deny_wins_that_right() {
    let alice = person("alice", &["staff"]);
    let acl = Acl::new(Mode::Ordered)
        .entry(Entry::allow(subject("account:alice"), ["write"]))
        .entry(Entry::deny(subject("group:staff"), ["write", "delete"]))
        .entry(Entry::allow(subject("group:staff"), ["full"]));
    let write = check(&acl, &alice, &["write"]);
    assert!(write.allowed);
    assert_eq!(write.deciding, Some(0));
    let delete = check(&acl, &alice, &["delete"]);
    assert!(!delete.allowed);
    assert_eq!(delete.deciding, Some(1));
    // The same entries with the deny first refuse the write.
    let mut reordered = acl.clone();
    reordered.entries.swap(0, 1);
    assert!(!check(&reordered, &alice, &["write"]).allowed);
    // Rights nobody named are neither granted nor denied: default deny.
    let none = check(&Acl::new(Mode::Ordered), &alice, &["read"]);
    assert!(!none.allowed && none.granted.is_empty() && none.deciding.is_none());
}

#[test]
fn canonical_order_puts_explicit_denies_then_allows_then_inherited() {
    let mut acl = Acl::new(Mode::Ordered)
        .entry(Entry::allow(Principal::Everyone, ["read"]).inherited(true))
        .entry(Entry::allow(subject("group:a"), ["read"]))
        .entry(Entry::deny(Principal::Everyone, ["write"]).inherited(true))
        .entry(Entry::deny(subject("group:b"), ["write"]));
    acl.canonicalize();
    let order: Vec<_> = acl
        .entries
        .iter()
        .map(|entry| (entry.inherited, entry.principal.to_string()))
        .collect();
    assert_eq!(
        order,
        [
            (false, "group:b".to_owned()),
            (false, "group:a".to_owned()),
            (true, "everyone".to_owned()),
            (true, "everyone".to_owned()),
        ]
    );
}

fn permutations<T: Clone>(items: &[T]) -> Vec<Vec<T>> {
    if items.len() <= 1 {
        return vec![items.to_vec()];
    }
    let mut all = Vec::new();
    for at in 0..items.len() {
        let mut rest = items.to_vec();
        let first = rest.remove(at);
        for mut tail in permutations(&rest) {
            tail.insert(0, first.clone());
            all.push(tail);
        }
    }
    all
}

#[test]
fn deny_overrides_gives_one_answer_for_every_order_of_the_entries() {
    let entries = [
        Entry::allow(subject("group:staff"), ["full"]),
        Entry::deny(subject("account:alice"), ["delete"]),
        Entry::allow(Principal::Authenticated, ["read"]),
        Entry::deny(subject("group:contractors"), ["write"]),
        Entry::allow(subject("account:bob"), ["delete"]),
        Entry::deny(subject("group:nobody"), ["read"]),
    ];
    let people = [
        person("alice", &["staff"]),
        person("bob", &["contractors"]),
        person("carol", &["staff", "contractors"]),
    ];
    let wants: [&[&str]; 4] = [&["read"], &["write"], &["delete"], &["read", "write"]];
    let orders = permutations(&entries);
    assert_eq!(orders.len(), 720);
    for who in &people {
        for wanted in wants {
            let answers: Vec<_> = orders
                .iter()
                .map(|order| {
                    let mut acl = Acl::new(Mode::DenyOverrides);
                    acl.extend(order.clone());
                    let decision = check(&acl, who, wanted);
                    (decision.allowed, decision.granted, decision.denied)
                })
                .collect();
            assert!(answers.windows(2).all(|pair| pair[0] == pair[1]));
        }
    }
    let mut acl = Acl::new(Mode::DenyOverrides);
    acl.extend(entries);
    assert!(!check(&acl, &people[0], &["delete"]).allowed);
    assert!(check(&acl, &people[0], &["read", "write"]).allowed);
    assert!(!check(&acl, &people[2], &["write"]).allowed);
    assert_eq!(check(&acl, &people[2], &["write"]).deciding, Some(3));
}

#[test]
fn additive_unions_allows_and_refuses_a_deny() {
    let schema = schema();
    let acl = Acl::new(Mode::Additive)
        .entry(Entry::allow(subject("group:a"), ["read"]))
        .entry(Entry::allow(subject("group:b"), ["write"]));
    assert!(check(&acl, &person("x", &["a", "b"]), &["modify"]).allowed);
    assert!(!check(&acl, &person("x", &["a"]), &["modify"]).allowed);
    let with_deny = acl.entry(Entry::deny(subject("group:a"), ["read"]));
    assert!(matches!(
        with_deny.check(&Context::new(&schema), &Rights::new()),
        Err(AclError::DenyNotAllowed { entry: 2 })
    ));
    assert!(with_deny.validate(&schema, &Options::new()).is_err());
}

fn posix_acl() -> ItemAcl {
    // user::rwx, user:bob:rwx, group::r--, group:dev:rw-, mask::r--, other::---
    ItemAcl::new(
        Acl::new(Mode::Posix)
            .entry(Entry::allow(Principal::Owner, ["full"]))
            .entry(Entry::allow(subject("account:bob"), ["full"]))
            .entry(Entry::allow(Principal::OwnerGroup, ["read"]))
            .entry(Entry::allow(subject("group:dev"), ["read", "write"]))
            .entry(Entry::allow(Principal::Mask, ["read"]))
            .entry(Entry::allow(Principal::Everyone, Vec::<String>::new())),
    )
    .owner(subject("account:alice"))
    .owner_group(subject("group:users"))
}

fn posix(who: &Person, wanted: &[&str]) -> Decision {
    let schema = schema();
    posix_acl()
        .check(
            &Context::new(&schema).person(who),
            &schema.rights(wanted).unwrap(),
        )
        .unwrap()
}

#[test]
fn posix_the_mask_caps_a_named_user_and_groups_but_not_the_owner() {
    assert!(posix(&person("alice", &[]), &["full"]).allowed);
    let bob = posix(&person("bob", &["dev"]), &["write"]);
    assert!(!bob.allowed, "the mask caps bob's rwx to r");
    assert!(posix(&person("bob", &[]), &["read"]).allowed);
    // A named user is decided as a named user, not through his groups.
    assert!(!posix(&person("bob", &["dev"]), &["write"]).allowed);
    assert!(!posix(&person("dan", &["dev"]), &["write"]).allowed);
    assert!(posix(&person("dan", &["dev"]), &["read"]).allowed);
    assert!(!posix(&person("eve", &[]), &["read"]).allowed);
    let schema = schema();
    let anonymous = posix_acl()
        .check(&Context::new(&schema), &schema.rights(["read"]).unwrap())
        .unwrap();
    assert!(!anonymous.allowed);
}

#[test]
fn posix_without_a_mask_one_group_entry_must_hold_every_wanted_right() {
    let mut item = posix_acl();
    item.acl
        .entries
        .retain(|entry| entry.principal != Principal::Mask);
    // users gives read, dev gives read and write: dev alone holds both.
    let both = posix(&person("x", &["users", "dev"]), &["read"]);
    assert!(both.allowed);
    let schema = schema();
    let ask = |who: &Person, wanted: &[&str]| {
        item.check(
            &Context::new(&schema).person(who),
            &schema.rights(wanted).unwrap(),
        )
        .unwrap()
        .allowed
    };
    assert!(ask(&person("x", &["users", "dev"]), &["modify"]));
    let split = ItemAcl::new(
        Acl::new(Mode::Posix)
            .entry(Entry::allow(subject("group:r"), ["read"]))
            .entry(Entry::allow(subject("group:w"), ["write"])),
    );
    let decision = split
        .check(
            &Context::new(&schema).person(&person("x", &["r", "w"])),
            &schema.rights(["modify"]).unwrap(),
        )
        .unwrap();
    assert!(
        !decision.allowed,
        "no single group entry holds read and write"
    );
    assert_eq!(decision.granted, schema.rights(["modify"]).unwrap());
}

#[test]
fn posix_refuses_denies_authenticated_and_a_second_mask() {
    let schema = schema();
    for (bad, entry) in [
        (Entry::deny(Principal::Everyone, ["read"]), 0),
        (Entry::allow(Principal::Authenticated, ["read"]), 0),
    ] {
        let acl = Acl::new(Mode::Posix).entry(bad);
        let error = acl.validate(&schema, &Options::new()).unwrap_err();
        assert!(matches!(
            error,
            AclError::DenyNotAllowed { entry: at } | AclError::PrincipalNotAllowed { entry: at }
                if at == entry
        ));
    }
    let two_masks = Acl::new(Mode::Posix)
        .entry(Entry::allow(Principal::Mask, ["read"]))
        .entry(Entry::allow(Principal::Mask, ["read"]));
    assert!(two_masks.validate(&schema, &Options::new()).is_err());
    let mask_elsewhere =
        Acl::new(Mode::DenyOverrides).entry(Entry::allow(Principal::Mask, ["read"]));
    assert!(mask_elsewhere.validate(&schema, &Options::new()).is_err());
}

#[test]
fn a_cancelling_name_refuses_everything_in_any_mode() {
    for mode in [Mode::Ordered, Mode::DenyOverrides, Mode::Additive] {
        let acl = Acl::new(mode)
            .entry(Entry::allow(Principal::Everyone, ["full"]))
            .entry(Entry::allow(subject("account:alice"), ["no_access"]));
        let decision = check(&acl, &person("alice", &[]), &["read"]);
        assert!(!decision.allowed && decision.cancelled, "{mode:?}");
        assert_eq!(decision.deciding, Some(1));
        assert!(check(&acl, &person("bob", &[]), &["read"]).allowed);
    }
}

#[test]
fn inherit_only_entries_do_not_apply_to_their_own_item() {
    let acl = Acl::new(Mode::DenyOverrides).entry(
        Entry::allow(Principal::Everyone, ["read"])
            .inherit(Inherit::new(true, true).inherit_only()),
    );
    assert!(!check(&acl, &person("x", &[]), &["read"]).allowed);
}

#[test]
fn unknown_names_and_too_many_entries_are_errors_not_answers() {
    let schema = schema();
    let acl = Acl::new(Mode::DenyOverrides)
        .entry(Entry::allow(Principal::Everyone, ["read"]))
        .entry(Entry::deny(Principal::Everyone, ["read", "erase"]));
    let error = acl
        .check(&Context::new(&schema), &Rights::new())
        .unwrap_err();
    assert!(matches!(
        error,
        AclError::UnknownRight {
            entry: Some(1),
            at: 1
        }
    ));
    assert!(!error.to_string().contains("erase"));
    let mut many = Acl::new(Mode::DenyOverrides);
    many.extend(vec![Entry::allow(Principal::Everyone, ["read"]); 1025]);
    assert!(matches!(
        many.validate(&schema, &Options::new()),
        Err(AclError::TooManyEntries)
    ));
    let unbounded = Options::new().limits(Limits::default().entries(None));
    many.validate(&schema, &unbounded).unwrap();
}

#[test]
fn weakenings_are_reported_as_data() {
    let acl = Acl::new(Mode::DenyOverrides)
        .entry(Entry::allow(subject("group:a"), ["read"]))
        .entry(Entry::allow(Principal::Everyone, ["read"]))
        .entry(Entry::deny(Principal::Everyone, ["write"]));
    assert_eq!(acl.weakened(), [Weakening::EveryoneAllowed { entry: 1 }]);
    assert!(Options::new().weakened().is_empty());
    assert_eq!(
        Options::new().on_missing(OnMissing::AllowAll).weakened(),
        [Weakening::MissingAllowsAll]
    );
}

#[test]
fn an_item_acl_round_trips_through_a_stored_document() {
    let item = posix_acl();
    let text = json::to_string(&item.to_value().unwrap(), Presentation::new()).unwrap();
    assert!(text.contains("\"principal\":\"account:bob\""), "{text}");
    assert!(text.contains("\"owner\":\"account:alice\""), "{text}");
    let back = json::from_str(&text, Alloc::rust(), Presentation::new()).unwrap();
    assert_eq!(ItemAcl::from_value(&back).unwrap(), item);
    let stored = r#"{"entries":[{"principal":"group:staff","effect":"deny","rights":["write"],
        "inherit":{"items":true}}],"mode":"ordered"}"#;
    let acl = Acl::from_value(&json::from_str(stored, Alloc::rust(), Presentation::new()).unwrap())
        .unwrap();
    assert_eq!(acl.mode, Mode::Ordered);
    assert!(acl.entries[0].inherit.items && !acl.entries[0].inherit.containers);
    for bad in [
        r#"{"entries":[{"principal":"nobody","rights":[]}]}"#,
        r#"{"entries":[],"surprise":1}"#,
    ] {
        let value = json::from_str(bad, Alloc::rust(), Presentation::new()).unwrap();
        assert!(Acl::from_value(&value).is_err(), "{bad}");
    }
}
