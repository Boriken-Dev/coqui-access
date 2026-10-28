//! TrueNAS SCALE, written in this model from its API documentation and the standards it
//! follows: <https://api.truenas.com/v25.04/api_methods_filesystem.setacl.html>,
//! <https://api.truenas.com/v25.04/rbac.html>, RFC 8881 §6.2.1 (NFSv4 ACL evaluation),
//! acl(5) (POSIX.1e).
//!
//! NFSv4 ACLs are `Ordered` lists TrueNAS always writes in canonical order, so a deny
//! precedes an allow ("deny entries take precedence over allow"); POSIX1E ACLs are `Posix`,
//! their default entries inherit-only entries passed to new children; API roles are one
//! `Additive` list over the API, where a `_WRITE` role includes its `_READ`.

mod support;

use coqui_access::Person;
use coqui_access_acl::{
    Acl, AclError, Child, Context, Entry, Inherit, ItemAcl, Mode, Options, Principal, Rights,
    RightsSchema,
};
use support::{person, subject};

/// The fourteen NFSv4 permissions, and `FULL_CONTROL`, the basic permission holding all.
fn nfs4() -> RightsSchema {
    let advanced = [
        "READ_DATA",
        "WRITE_DATA",
        "APPEND_DATA",
        "READ_NAMED_ATTRS",
        "WRITE_NAMED_ATTRS",
        "EXECUTE",
        "DELETE",
        "DELETE_CHILD",
        "READ_ATTRIBUTES",
        "WRITE_ATTRIBUTES",
        "READ_ACL",
        "WRITE_ACL",
        "WRITE_OWNER",
        "SYNCHRONIZE",
    ];
    RightsSchema::builder()
        .rights(advanced)
        .alias("FULL_CONTROL", advanced)
        .build()
        .unwrap()
}

fn allowed(acl: &ItemAcl, who: &Person, wanted: &[&str]) -> bool {
    let schema = nfs4();
    acl.check(
        &Context::new(&schema).person(who),
        &schema.rights(wanted).unwrap(),
    )
    .unwrap()
    .allowed
}

/// owner@ full control, a deny for one user, group@ and a named group may read, everyone@
/// may read attributes. Written allow first, as a client might send it.
fn share() -> ItemAcl {
    let mut acl = Acl::new(Mode::Ordered)
        .entry(Entry::allow(Principal::Owner, ["FULL_CONTROL"]))
        .entry(Entry::allow(
            Principal::OwnerGroup,
            ["READ_DATA", "READ_ATTRIBUTES", "EXECUTE"],
        ))
        .entry(Entry::allow(
            subject("group:editors"),
            ["READ_DATA", "WRITE_DATA"],
        ))
        .entry(Entry::deny(subject("account:mallory"), ["WRITE_DATA"]))
        .entry(Entry::allow(Principal::Everyone, ["READ_ATTRIBUTES"]));
    acl.canonicalize();
    ItemAcl::new(acl)
        .owner(subject("account:root"))
        .owner_group(subject("group:wheel"))
}

#[test]
fn canonical_order_puts_the_deny_first_so_it_wins() {
    let acl = share();
    assert_eq!(acl.acl.entries[0].principal.to_string(), "account:mallory");
    let mallory = person("mallory", &["editors"]);
    assert!(!allowed(&acl, &mallory, &["WRITE_DATA"]));
    assert!(allowed(&acl, &mallory, &["READ_DATA"]));
    assert!(allowed(&acl, &person("ed", &["editors"]), &["WRITE_DATA"]));
}

#[test]
fn owner_group_and_everyone_resolve_against_the_file() {
    let acl = share();
    assert!(allowed(&acl, &person("root", &[]), &["FULL_CONTROL"]));
    assert!(allowed(&acl, &person("w", &["wheel"]), &["EXECUTE"]));
    assert!(!allowed(&acl, &person("w", &["wheel"]), &["WRITE_DATA"]));
    let stranger = person("s", &[]);
    assert!(allowed(&acl, &stranger, &["READ_ATTRIBUTES"]));
    assert!(!allowed(&acl, &stranger, &["READ_DATA"]));
}

#[test]
fn each_permission_is_decided_on_its_own_in_order() {
    // RFC 8881: an ALLOW of one bit then a DENY of two leaves the first allowed.
    let acl = ItemAcl::new(
        Acl::new(Mode::Ordered)
            .entry(Entry::allow(Principal::Everyone, ["READ_DATA"]))
            .entry(Entry::deny(
                Principal::Everyone,
                ["READ_DATA", "WRITE_DATA"],
            ))
            .entry(Entry::allow(Principal::Everyone, ["WRITE_DATA"])),
    );
    let anyone = person("a", &[]);
    assert!(allowed(&acl, &anyone, &["READ_DATA"]));
    assert!(!allowed(&acl, &anyone, &["WRITE_DATA"]));
    assert!(!allowed(&acl, &anyone, &["READ_DATA", "WRITE_DATA"]));
}

#[test]
fn file_and_directory_inherit_flags_reach_new_files_and_directories() {
    // FILE_INHERIT is `items`, DIRECTORY_INHERIT `containers`.
    let dataset = Acl::new(Mode::Ordered)
        .entry(
            Entry::allow(subject("group:editors"), ["READ_DATA", "WRITE_DATA"])
                .inherit(Inherit::new(true, true)),
        )
        .entry(
            Entry::allow(subject("group:auditors"), ["READ_DATA"])
                .inherit(Inherit::new(true, false).inherit_only()),
        );
    let directory = dataset.inherited_by(Child::Container, &Acl::new(Mode::Ordered), None);
    let file = directory.inherited_by(Child::Item, &Acl::new(Mode::Ordered), None);
    let auditor = person("au", &["auditors"]);
    assert!(!allowed(
        &ItemAcl::new(directory.clone()),
        &auditor,
        &["READ_DATA"]
    ));
    assert!(allowed(
        &ItemAcl::new(file.clone()),
        &auditor,
        &["READ_DATA"]
    ));
    assert!(allowed(
        &ItemAcl::new(file),
        &person("e", &["editors"]),
        &["WRITE_DATA"]
    ));
}

fn rwx() -> RightsSchema {
    RightsSchema::builder()
        .rights(["READ", "WRITE", "EXECUTE"])
        .build()
        .unwrap()
}

#[test]
fn posix1e_default_entries_apply_only_to_what_is_made_inside() {
    let default = Inherit::new(true, true).inherit_only();
    let directory = ItemAcl::new(
        Acl::new(Mode::Posix)
            .entry(Entry::allow(Principal::Owner, ["READ", "WRITE", "EXECUTE"]))
            .entry(Entry::allow(Principal::OwnerGroup, ["READ", "EXECUTE"]))
            .entry(Entry::allow(Principal::Mask, ["READ", "EXECUTE"]))
            .entry(Entry::allow(Principal::Everyone, Vec::<String>::new()))
            .entry(Entry::allow(subject("group:builders"), ["READ", "WRITE"]).inherit(default))
            .entry(Entry::allow(Principal::Mask, ["READ", "WRITE"]).inherit(default)),
    )
    .owner(subject("account:root"))
    .owner_group(subject("group:wheel"));
    let schema = rwx();
    let builder = person("b", &["builders"]);
    let write = schema.rights(["WRITE"]).unwrap();
    let ask = |item: &ItemAcl| {
        item.check(&Context::new(&schema).person(&builder), &write)
            .unwrap()
            .allowed
    };
    // Two masks: one in force here, one default. Only the access mask counts here.
    assert!(!ask(&directory));
    let mut made = directory
        .acl
        .inherited_by(Child::Item, &Acl::new(Mode::Posix), None);
    made.extend([
        Entry::allow(Principal::Owner, ["READ", "WRITE"]),
        Entry::allow(Principal::Everyone, Vec::<String>::new()),
    ]);
    assert!(ask(&ItemAcl::new(made).owner(subject("account:root"))));
}

/// Roles as TrueNAS's RBAC page describes them: a subsystem's `_WRITE` includes its
/// `_READ`, `READONLY_ADMIN` every `_READ`, `FULL_ADMIN` everything.
fn roles() -> RightsSchema {
    RightsSchema::builder()
        .rights(["POOL_READ", "POOL_WRITE", "SHARING_READ", "SHARING_WRITE"])
        .alias("POOL_WRITE_ROLE", ["POOL_READ", "POOL_WRITE"])
        .alias("SHARING_ADMIN", ["SHARING_READ", "SHARING_WRITE"])
        .alias("READONLY_ADMIN", ["POOL_READ", "SHARING_READ"])
        .alias("FULL_ADMIN", ["POOL_WRITE_ROLE", "SHARING_ADMIN"])
        .build()
        .unwrap()
}

fn api() -> Acl {
    Acl::new(Mode::Additive)
        .entry(Entry::allow(subject("group:storage"), ["POOL_WRITE_ROLE"]))
        .entry(Entry::allow(subject("group:auditors"), ["READONLY_ADMIN"]))
        .entry(Entry::allow(subject("group:shares"), ["SHARING_ADMIN"]))
}

fn may_call(who: &Person, needs: &str) -> bool {
    let schema = roles();
    api()
        .check(
            &Context::new(&schema).person(who),
            &schema.rights([needs]).unwrap(),
        )
        .unwrap()
        .allowed
}

#[test]
fn api_roles_are_additive_and_write_includes_read() {
    // pool.query needs POOL_READ; pool.create needs POOL_WRITE.
    let storage = person("s", &["storage"]);
    assert!(may_call(&storage, "POOL_READ") && may_call(&storage, "POOL_WRITE"));
    assert!(!may_call(&storage, "SHARING_READ"));
    let auditor = person("a", &["auditors"]);
    assert!(may_call(&auditor, "POOL_READ") && !may_call(&auditor, "POOL_WRITE"));
    let both = person("b", &["auditors", "shares"]);
    assert!(may_call(&both, "SHARING_WRITE") && may_call(&both, "POOL_READ"));
    let no_deny = api().entry(Entry::deny(subject("group:auditors"), ["POOL_READ"]));
    assert!(matches!(
        no_deny.validate(&roles(), &Options::new()),
        Err(AclError::DenyNotAllowed { entry: 3 })
    ));
    assert!(!may_call(&person("n", &[]), "POOL_READ"));
    assert!(Rights::new().is_subset(&roles().all()));
}
