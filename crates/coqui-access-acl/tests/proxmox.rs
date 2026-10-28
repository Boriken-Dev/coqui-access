//! Proxmox VE permissions, written in this model from its documentation and source:
//! <https://pve.proxmox.com/pve-docs/chapter-pveum.html> ("Permissions", "Inheritance",
//! "Pools") and `PVE::AccessControl::roles` / `PVE::RPCEnvironment::permissions` in
//! <https://github.com/proxmox/pve-access-control>. A path's `propagate` flag is
//! `Inherit::containers`; a role is an alias; `NoAccess` is a cancelling name.

mod support;

use coqui_access::Person;
use coqui_access_acl::{
    Acl, AclError, AclStore, Context, Decision, Entry, Inherit, ItemAcl, Limits, Mode, Options,
    Rights, RightsSchema,
};
use support::{PathStore, person, subject};

fn privileges() -> RightsSchema {
    RightsSchema::builder()
        .rights([
            "VM.Audit",
            "VM.Console",
            "VM.PowerMgmt",
            "VM.Config.Disk",
            "Datastore.Audit",
            "Datastore.AllocateSpace",
            "Sys.Audit",
            "Permissions.Modify",
        ])
        .alias("PVEAuditor", ["VM.Audit", "Datastore.Audit", "Sys.Audit"])
        .alias("PVEVMUser", ["VM.Audit", "VM.Console", "VM.PowerMgmt"])
        .alias("PVEVMAdmin", ["PVEVMUser", "VM.Config.Disk"])
        .alias(
            "PVEDatastoreUser",
            ["Datastore.Audit", "Datastore.AllocateSpace"],
        )
        .alias(
            "Administrator",
            [
                "PVEAuditor",
                "PVEVMAdmin",
                "PVEDatastoreUser",
                "Permissions.Modify",
            ],
        )
        .cancel("NoAccess")
        .build()
        .unwrap()
}

/// One ACL line at a path: `propagate` as Proxmox writes it.
fn line(who: &str, role: &str, propagate: bool) -> Entry {
    Entry::allow(subject(who), [role]).inherit(Inherit::new(false, propagate))
}

fn at(store: &mut PathStore, path: &str, lines: impl IntoIterator<Item = Entry>) {
    let mut acl = Acl::new(Mode::MostSpecific);
    acl.extend(lines);
    store.set(path, ItemAcl::new(acl));
}

fn decide(store: &PathStore, path: &str, who: &Person, wanted: &[&str]) -> Decision {
    let schema = privileges();
    store
        .check(
            path,
            &Context::new(&schema).person(who),
            &schema.rights(wanted).unwrap(),
        )
        .unwrap()
}

fn holds(store: &PathStore, path: &str, who: &Person, wanted: &[&str]) -> bool {
    decide(store, path, who, wanted).allowed
}

#[test]
fn a_users_own_entry_beats_its_groups_at_the_same_level() {
    let mut store = PathStore::default();
    at(
        &mut store,
        "/vms",
        [
            line("group:admins", "PVEVMAdmin", true),
            line("account:jo@pve", "PVEAuditor", true),
        ],
    );
    let jo = person("jo@pve", &["admins"]);
    assert!(holds(&store, "/vms/100", &jo, &["VM.Audit"]));
    assert!(!holds(&store, "/vms/100", &jo, &["VM.PowerMgmt"]));
    assert!(holds(
        &store,
        "/vms/100",
        &person("ann@pve", &["admins"]),
        &["VM.PowerMgmt"]
    ));
}

#[test]
fn the_groups_a_user_is_in_are_unioned_at_one_level() {
    let mut store = PathStore::default();
    at(
        &mut store,
        "/",
        [
            line("group:vm", "PVEVMUser", true),
            line("group:storage", "PVEDatastoreUser", true),
        ],
    );
    let both = person("b@pve", &["vm", "storage"]);
    assert!(holds(
        &store,
        "/vms/100",
        &both,
        &["VM.Console", "Datastore.AllocateSpace"]
    ));
}

#[test]
fn a_deeper_level_replaces_what_came_from_above() {
    let mut store = PathStore::default();
    at(&mut store, "/", [line("group:ops", "Administrator", true)]);
    at(
        &mut store,
        "/vms/100",
        [line("group:ops", "PVEAuditor", true)],
    );
    let op = person("o@pve", &["ops"]);
    assert!(holds(&store, "/vms/101", &op, &["VM.PowerMgmt"]));
    assert!(
        !holds(&store, "/vms/100", &op, &["VM.PowerMgmt"]),
        "replaced, not added"
    );
    assert!(holds(&store, "/vms/100", &op, &["VM.Audit"]));
    // A level where nothing applies to this user leaves what came from above.
    at(
        &mut store,
        "/vms",
        [line("group:other", "PVEAuditor", true)],
    );
    assert!(holds(&store, "/vms/101", &op, &["VM.PowerMgmt"]));
}

#[test]
fn an_entry_without_propagate_counts_only_at_its_own_path() {
    let mut store = PathStore::default();
    at(
        &mut store,
        "/storage",
        [line("account:s@pve", "PVEDatastoreUser", false)],
    );
    let user = person("s@pve", &[]);
    assert!(holds(&store, "/storage", &user, &["Datastore.Audit"]));
    assert!(!holds(
        &store,
        "/storage/local",
        &user,
        &["Datastore.Audit"]
    ));
}

#[test]
fn no_access_cancels_every_other_role_where_it_is_in_force() {
    let mut store = PathStore::default();
    at(&mut store, "/", [line("group:staff", "PVEAuditor", true)]);
    at(
        &mut store,
        "/vms/100",
        [
            line("account:x@pve", "NoAccess", true),
            line("account:x@pve", "PVEVMAdmin", true),
        ],
    );
    let x = person("x@pve", &["staff"]);
    let decision = decide(&store, "/vms/100", &x, &["VM.Audit"]);
    assert!(!decision.allowed && decision.cancelled);
    assert!(holds(&store, "/vms/101", &x, &["VM.Audit"]));
    // A deeper level replaces a NoAccess from above.
    at(
        &mut store,
        "/vms/100/disk",
        [line("account:x@pve", "PVEAuditor", true)],
    );
    assert!(holds(&store, "/vms/100/disk", &x, &["VM.Audit"]));
}

#[test]
fn a_cycle_is_an_error_and_the_depth_is_bounded_by_an_option() {
    struct Looping;
    impl AclStore for Looping {
        fn acl(
            &self,
            _: &str,
        ) -> Result<Option<ItemAcl>, coqui_access::guatiao::library::ProviderError> {
            Ok(None)
        }
        fn parent(
            &self,
            item: &str,
        ) -> Result<Option<String>, coqui_access::guatiao::library::ProviderError> {
            Ok(Some(if item == "a" { "b" } else { "a" }.to_owned()))
        }
    }
    let schema = privileges();
    let unbounded =
        Context::new(&schema).options(Options::new().limits(Limits::default().depth(None)));
    assert!(matches!(
        Looping.check("a", &unbounded, &Rights::new()),
        Err(AclError::Cycle)
    ));
    let mut store = PathStore::default();
    at(&mut store, "/", [line("group:ops", "PVEAuditor", true)]);
    let deep: String = (0..70).map(|level| format!("/{level}")).collect();
    let context = Context::new(&schema);
    assert!(matches!(
        store.check(&deep, &context, &Rights::new()),
        Err(AclError::TooDeep)
    ));
    let op = person("o@pve", &["ops"]);
    let lifted = Context::new(&schema)
        .person(&op)
        .options(Options::new().limits(Limits::default().depth(None)));
    let audit = schema.rights(["VM.Audit"]).unwrap();
    assert!(store.check(&deep, &lifted, &audit).unwrap().allowed);
}

#[test]
fn a_walk_refuses_an_acl_in_another_mode_and_a_broken_store_is_an_error() {
    let mut store = PathStore::default();
    at(
        &mut store,
        "/vms/100",
        [line("group:ops", "PVEAuditor", true)],
    );
    store.set("/vms", ItemAcl::new(Acl::new(Mode::DenyOverrides)));
    let schema = privileges();
    let context = Context::new(&schema);
    assert!(matches!(
        store.check("/vms/100", &context, &Rights::new()),
        Err(AclError::ModeMismatch)
    ));
    store.broken = true;
    assert!(matches!(
        store.check("/vms/100", &context, &Rights::new()),
        Err(AclError::Store(_))
    ));
}
