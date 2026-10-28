//! Windows DACLs, written in this model from Microsoft's documentation:
//! <https://learn.microsoft.com/en-us/windows/win32/secauthz/how-dacls-control-access-to-an-object>,
//! <https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-inheritance-rules>,
//! <https://learn.microsoft.com/en-us/windows/win32/secauthz/null-dacls-and-empty-dacls>,
//! <https://learn.microsoft.com/en-us/windows/win32/secauthz/generic-access-rights>,
//! <https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language-for-conditional-aces->.

mod support;

use coqui_access::Person;
use coqui_access_acl::{
    Acl, AclStore, Child, Conditions, Context, Effect, Entry, Inherit, ItemAcl, Mode, OnMissing,
    Options, Principal, Rights, RightsSchema, Truth,
};
use support::{PathStore, person, subject};

/// The file rights, in their mask order, and the generic rights as aliases (the file
/// type's `GENERIC_MAPPING`).
fn files() -> RightsSchema {
    RightsSchema::builder()
        .rights([
            "read_data",
            "write_data",
            "append_data",
            "read_ea",
            "write_ea",
            "execute",
            "delete_child",
            "read_attributes",
            "write_attributes",
            "delete",
            "read_control",
            "write_dac",
            "write_owner",
            "synchronize",
        ])
        .alias(
            "generic_read",
            [
                "read_data",
                "read_attributes",
                "read_ea",
                "read_control",
                "synchronize",
            ],
        )
        .alias(
            "generic_write",
            [
                "write_data",
                "append_data",
                "write_attributes",
                "write_ea",
                "read_control",
                "synchronize",
            ],
        )
        .alias(
            "generic_execute",
            ["execute", "read_attributes", "read_control", "synchronize"],
        )
        .alias(
            "generic_all",
            [
                "generic_read",
                "generic_write",
                "generic_execute",
                "delete",
                "delete_child",
                "write_dac",
                "write_owner",
            ],
        )
        .build()
        .unwrap()
}

fn rights(schema: &RightsSchema, names: &[&str]) -> Rights {
    schema.rights(names).unwrap()
}

/// Microsoft's example: Andrew is denied, Group A may write, Everyone may read and execute.
fn example() -> Acl {
    Acl::new(Mode::Ordered)
        .entry(Entry::deny(
            subject("account:andrew"),
            ["read_data", "write_data", "execute"],
        ))
        .entry(Entry::allow(subject("group:group_a"), ["write_data"]))
        .entry(Entry::allow(
            Principal::Everyone,
            ["read_data", "write_data", "execute"],
        ))
}

#[test]
fn the_documented_example_denies_andrew_at_the_first_entry_and_lets_group_a_in() {
    let schema = files();
    let andrew = person("andrew", &["group_a"]);
    let decision = example()
        .check(
            &Context::new(&schema).person(&andrew),
            &rights(&schema, &["read_data", "write_data", "execute"]),
        )
        .unwrap();
    assert!(!decision.allowed);
    assert_eq!(decision.deciding, Some(0));
    let thread_b = person("b", &["group_a"]);
    let decision = example()
        .check(
            &Context::new(&schema).person(&thread_b),
            &rights(&schema, &["read_data", "write_data", "execute"]),
        )
        .unwrap();
    assert!(decision.allowed);
    assert_eq!(decision.deciding, Some(2), "Everyone completed the grant");
}

#[test]
fn an_allow_granted_earlier_is_not_revoked_by_a_later_deny() {
    let schema = files();
    let acl = Acl::new(Mode::Ordered)
        .entry(Entry::allow(subject("group:staff"), ["read_data"]))
        .entry(Entry::deny(
            Principal::Everyone,
            ["read_data", "write_data"],
        ));
    let staff = person("s", &["staff"]);
    let context = Context::new(&schema).person(&staff);
    assert!(
        acl.check(&context, &rights(&schema, &["read_data"]))
            .unwrap()
            .allowed
    );
    assert!(
        !acl.check(&context, &rights(&schema, &["write_data"]))
            .unwrap()
            .allowed
    );
}

#[test]
fn generic_rights_map_to_the_file_rights() {
    let schema = files();
    let acl = Acl::new(Mode::Ordered).entry(Entry::allow(Principal::Everyone, ["generic_read"]));
    let reader = person("r", &[]);
    let context = Context::new(&schema).person(&reader);
    assert!(
        acl.check(&context, &rights(&schema, &["read_attributes"]))
            .unwrap()
            .allowed
    );
    assert!(
        !acl.check(&context, &rights(&schema, &["write_data"]))
            .unwrap()
            .allowed
    );
    assert_eq!(rights(&schema, &["generic_all"]), schema.all());
}

#[test]
fn an_empty_dacl_grants_nothing_but_the_owners_implicit_rights() {
    let schema = files();
    let owner_rights = rights(&schema, &["read_control", "write_dac"]);
    let item = ItemAcl::new(Acl::new(Mode::Ordered)).owner(subject("account:olga"));
    let olga = person("olga", &[]);
    let context = Context::new(&schema)
        .person(&olga)
        .owner_rights(owner_rights.clone());
    assert!(item.check(&context, &owner_rights).unwrap().allowed);
    assert!(
        !item
            .check(&context, &rights(&schema, &["read_data"]))
            .unwrap()
            .allowed
    );
    let other = person("other", &[]);
    let context = Context::new(&schema)
        .person(&other)
        .owner_rights(owner_rights.clone());
    assert!(!item.check(&context, &owner_rights).unwrap().allowed);
    // An OWNER RIGHTS entry replaces the implicit rights.
    let owner_rights_ace = ItemAcl::new(
        Acl::new(Mode::Ordered).entry(Entry::allow(Principal::Owner, ["read_control"])),
    )
    .owner(subject("account:olga"));
    let context = Context::new(&schema)
        .person(&olga)
        .owner_rights(owner_rights.clone());
    let write_dac = rights(&schema, &["write_dac"]);
    assert!(
        !owner_rights_ace
            .check(&context, &write_dac)
            .unwrap()
            .allowed
    );
}

#[test]
fn a_null_dacl_is_an_item_with_no_acl_under_allow_all() {
    let schema = files();
    let store = PathStore::default();
    let anyone = person("x", &[]);
    let strict = Context::new(&schema).person(&anyone);
    let wanted = rights(&schema, &["write_data"]);
    assert!(!store.check("/file", &strict, &wanted).unwrap().allowed);
    let open = strict.options(Options::new().on_missing(OnMissing::AllowAll));
    assert!(store.check("/file", &open, &wanted).unwrap().allowed);
}

fn parent() -> Acl {
    let flags = [
        ("oi", Inherit::new(true, false)),
        ("ci", Inherit::new(false, true)),
        ("oici", Inherit::new(true, true)),
        ("oici_np", Inherit::new(true, true).no_propagate()),
        ("oi_np", Inherit::new(true, false).no_propagate()),
        ("ci_np", Inherit::new(false, true).no_propagate()),
        ("oici_io", Inherit::new(true, true).inherit_only()),
        ("none", Inherit::default()),
    ];
    let mut acl = Acl::new(Mode::Ordered);
    acl.extend(flags.into_iter().map(|(name, inherit)| {
        Entry::allow(subject(&format!("group:{name}")), ["read_data"]).inherit(inherit)
    }));
    acl
}

fn copies(child: Child) -> Vec<(String, Inherit)> {
    parent()
        .inherited_by(child, &Acl::new(Mode::Ordered), None)
        .entries
        .into_iter()
        .inspect(|entry| assert!(entry.inherited))
        .map(|entry| (entry.principal.to_string(), entry.inherit))
        .collect()
}

#[test]
fn inheritance_follows_microsofts_table_for_items_and_containers() {
    let none = Inherit::default();
    assert_eq!(
        copies(Child::Item),
        [
            ("group:oi".to_owned(), none),
            ("group:oici".to_owned(), none),
            ("group:oici_np".to_owned(), none),
            ("group:oi_np".to_owned(), none),
            ("group:oici_io".to_owned(), none),
        ]
    );
    assert_eq!(
        copies(Child::Container),
        [
            (
                "group:oi".to_owned(),
                Inherit::new(true, false).inherit_only()
            ),
            ("group:ci".to_owned(), Inherit::new(false, true)),
            ("group:oici".to_owned(), Inherit::new(true, true)),
            ("group:oici_np".to_owned(), none),
            ("group:ci_np".to_owned(), none),
            ("group:oici_io".to_owned(), Inherit::new(true, true)),
        ]
    );
}

#[test]
fn an_inherited_inherit_only_entry_reaches_the_grandchild_item() {
    let schema = files();
    let folder = parent().inherited_by(Child::Container, &Acl::new(Mode::Ordered), None);
    let file = folder.inherited_by(Child::Item, &Acl::new(Mode::Ordered), None);
    let member = person("m", &["oi"]);
    let read = rights(&schema, &["read_data"]);
    let context = Context::new(&schema).person(&member);
    assert!(
        !folder.check(&context, &read).unwrap().allowed,
        "inherit-only on the folder"
    );
    assert!(file.check(&context, &read).unwrap().allowed);
    let np = person("n", &["oici_np"]);
    let grandchild = folder.inherited_by(Child::Container, &Acl::new(Mode::Ordered), None);
    let context = Context::new(&schema).person(&np);
    assert!(
        !grandchild.check(&context, &read).unwrap().allowed,
        "no propagation past one level"
    );
}

#[test]
fn explicit_entries_come_first_and_a_protected_child_takes_nothing() {
    let explicit = Acl::new(Mode::Ordered)
        .entry(Entry::deny(subject("group:oici"), ["read_data"]))
        .entry(Entry::allow(subject("group:old"), ["read_data"]).inherited(true));
    let child = parent().inherited_by(Child::Item, &explicit, None);
    assert_eq!(child.entries[0].effect, Effect::Deny);
    assert!(!child.entries[0].inherited);
    assert!(
        child
            .entries
            .iter()
            .all(|entry| entry.principal.to_string() != "group:old")
    );
    let schema = files();
    let member = person("m", &["oici"]);
    let read = rights(&schema, &["read_data"]);
    assert!(
        !child
            .check(&Context::new(&schema).person(&member), &read)
            .unwrap()
            .allowed
    );
    let protected = explicit.clone().protected(true);
    assert_eq!(
        parent().inherited_by(Child::Item, &protected, None),
        protected
    );
}

#[test]
fn creator_owner_becomes_the_creator_and_stays_inheritable_on_a_container() {
    let parent = Acl::new(Mode::Ordered)
        .entry(Entry::allow(Principal::Owner, ["generic_all"]).inherit(Inherit::new(true, true)));
    let creator = subject("account:cara");
    let folder = parent.inherited_by(Child::Container, &Acl::new(Mode::Ordered), Some(&creator));
    let shapes: Vec<_> = folder
        .entries
        .iter()
        .map(|entry| (entry.principal.to_string(), entry.inherit))
        .collect();
    assert_eq!(
        shapes,
        [
            ("account:cara".to_owned(), Inherit::default()),
            ("owner".to_owned(), Inherit::new(true, true).inherit_only()),
        ]
    );
    let file = parent.inherited_by(Child::Item, &Acl::new(Mode::Ordered), Some(&creator));
    assert_eq!(file.entries.len(), 1);
    assert_eq!(file.entries[0].principal.to_string(), "account:cara");
}

struct Claims;

impl Conditions for Claims {
    fn holds(&self, condition: &str, _item: &str, person: &Person) -> Truth {
        match condition {
            "@User.clearance == \"secret\"" if person.name == "spy" => Truth::True,
            "@User.clearance == \"secret\"" => Truth::False,
            _ => Truth::Unknown,
        }
    }
}

#[test]
fn a_conditional_allow_is_skipped_when_unknown_and_a_conditional_deny_applies() {
    let schema = files();
    let acl = Acl::new(Mode::Ordered)
        .entry(Entry::deny(Principal::Everyone, ["write_data"]).condition("@Device.managed == 0"))
        .entry(
            Entry::allow(Principal::Everyone, ["read_data", "write_data"])
                .condition("@User.clearance == \"secret\""),
        );
    let spy = person("spy", &[]);
    let clerk = person("clerk", &[]);
    let ask = |who: &Person, wanted: &[&str]| {
        acl.check(
            &Context::new(&schema).person(who).conditions(&Claims),
            &rights(&schema, wanted),
        )
        .unwrap()
        .allowed
    };
    assert!(ask(&spy, &["read_data"]));
    assert!(!ask(&spy, &["write_data"]), "the unknown deny applies");
    assert!(!ask(&clerk, &["read_data"]), "a false allow does not apply");
    let without = acl
        .check(
            &Context::new(&schema).person(&spy),
            &rights(&schema, &["read_data"]),
        )
        .unwrap();
    assert!(
        !without.allowed,
        "no conditions: the allow is unknown and skipped"
    );
}
