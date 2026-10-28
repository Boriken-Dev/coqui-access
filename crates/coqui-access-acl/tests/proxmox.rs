//! Proxmox VE permissions, written in this model from its documentation and source:
//! <https://pve.proxmox.com/pve-docs/chapter-pveum.html> ("Permissions", "Inheritance",
//! "Pools") and `PVE::AccessControl::roles` / `PVE::RPCEnvironment::permissions` in
//! <https://github.com/proxmox/pve-access-control>. A path's `propagate` flag is
//! `Inherit::containers`; a role is an alias; `NoAccess` is a cancelling name.

mod support;

use std::sync::Arc;

use coqui_access::guatiao::library::ProviderError;
use coqui_access::{AuthorizationRequest, Authorizer, Person};
use coqui_access_acl::{
    Acl, AclAuthorizer, AclError, AclStore, Context, Decision, Entry, Inherit, ItemAcl, Limits,
    Mode, Options, Rights, RightsSchema,
};
use coqui_access_kit::{Keyed, MemoryTable, Table};
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

/// A pool's roles reach its members as Proxmox's `compile_acl_path` does: each role the
/// path did not set, a `NoAccess` on the path kept, a `NoAccess` on the pool winning.
fn with_pool(store: &PathStore, vm: &str, pool: &str, who: &Person, wanted: &[&str]) -> Decision {
    let path = decide(store, vm, who, wanted);
    let pooled = decide(store, pool, who, wanted);
    path.union_where_unset(&pooled)
}

#[test]
fn a_pools_roles_join_its_members_and_no_access_wins_from_either_side() {
    let mut store = PathStore::default();
    at(
        &mut store,
        "/vms/100",
        [line("account:p@pve", "PVEAuditor", true)],
    );
    at(
        &mut store,
        "/pool/web",
        [line("account:p@pve", "PVEVMUser", true)],
    );
    let user = person("p@pve", &[]);
    assert!(with_pool(&store, "/vms/100", "/pool/web", &user, &["VM.Console"]).allowed);
    assert!(with_pool(&store, "/vms/100", "/pool/web", &user, &["VM.Audit"]).allowed);
    at(
        &mut store,
        "/pool/web",
        [line("account:p@pve", "NoAccess", true)],
    );
    assert!(!with_pool(&store, "/vms/100", "/pool/web", &user, &["VM.Audit"]).allowed);
    at(
        &mut store,
        "/pool/web",
        [line("account:p@pve", "PVEVMUser", true)],
    );
    at(
        &mut store,
        "/vms/100",
        [line("account:p@pve", "NoAccess", true)],
    );
    assert!(!with_pool(&store, "/vms/100", "/pool/web", &user, &["VM.Console"]).allowed);
}

#[test]
fn a_privilege_separated_token_gets_what_both_it_and_its_user_hold() {
    let mut store = PathStore::default();
    at(
        &mut store,
        "/vms",
        [line("account:u@pve", "PVEVMAdmin", true)],
    );
    // The token's own ACL, kept in a store of its own here.
    let mut tokens = PathStore::default();
    at(
        &mut tokens,
        "/",
        [line("account:u@pve!ci", "Administrator", true)],
    );
    let user = person("u@pve", &[]);
    let token = person("u@pve!ci", &[]);
    for (wanted, allowed) in [(["VM.PowerMgmt"], true), (["Sys.Audit"], false)] {
        let both = decide(&store, "/vms/7", &user, &wanted)
            .intersect(&decide(&tokens, "/vms/7", &token, &wanted));
        assert_eq!(both.allowed, allowed, "{wanted:?}");
    }
}

/// Paths and their ACLs in a coqui-access-kit table, as a consumer might keep them.
#[derive(Clone)]
struct Kept {
    path: String,
    acl: ItemAcl,
}

impl Keyed for Kept {
    fn key(&self) -> &str {
        &self.path
    }
}

struct TableStore(Arc<MemoryTable<Kept>>);

impl AclStore for TableStore {
    fn acl(&self, item: &str) -> Result<Option<ItemAcl>, ProviderError> {
        let snapshot = self
            .0
            .load()
            .map_err(|reason| coqui_access::error::internal(&reason.to_string()))?;
        Ok(snapshot
            .records
            .into_iter()
            .find(|kept| kept.path == item)
            .map(|kept| kept.acl))
    }

    fn parent(&self, item: &str) -> Result<Option<String>, ProviderError> {
        PathStore::default().parent(item)
    }
}

#[test]
fn an_authorizer_over_a_table_answers_through_the_kind() {
    let table = Arc::new(MemoryTable::<Kept>::new());
    let mut acl = Acl::new(Mode::MostSpecific);
    acl.extend([line("group:ops", "PVEVMUser", true)]);
    table
        .put(Kept {
            path: "/vms".to_owned(),
            acl: ItemAcl::new(acl),
        })
        .unwrap();
    let authorizer = AclAuthorizer::new(TableStore(table), privileges());
    let ask = |who: &Person, action: &str, resource: &str| {
        authorizer.authorize(AuthorizationRequest {
            person: who.clone(),
            action: action.to_owned(),
            resource: resource.to_owned(),
        })
    };
    let op = person("o@pve", &["ops"]);
    assert!(ask(&op, "VM.Console", "/vms/100").unwrap().allowed);
    assert!(!ask(&op, "VM.Config.Disk", "/vms/100").unwrap().allowed);
    assert!(!ask(&op, "VM.Console", "/storage/local").unwrap().allowed);
    assert!(
        !ask(&op, "NoAccess", "/vms/100").unwrap().allowed,
        "a name with no right"
    );
    assert!(
        !ask(&op, "Sys.Reboot", "/vms/100").unwrap().allowed,
        "unknown"
    );
    let decision = authorizer.decide(&op, "VM.Console", "/vms/100").unwrap();
    assert_eq!(decision.deciding, Some(0));
}

#[test]
fn a_store_that_cannot_answer_is_an_error_never_a_denial() {
    let store = PathStore {
        broken: true,
        ..PathStore::default()
    };
    let authorizer = AclAuthorizer::new(store, privileges());
    let refused = authorizer.authorize(AuthorizationRequest {
        person: person("o@pve", &[]),
        action: "VM.Audit".to_owned(),
        resource: "/vms/100".to_owned(),
    });
    let error = refused.unwrap_err();
    assert_eq!(error.message(), "unreachable");
    // An ACL the schema cannot read is an error too.
    let mut store = PathStore::default();
    at(&mut store, "/vms", [line("group:ops", "PVEUnknown", true)]);
    let authorizer = AclAuthorizer::new(store, privileges());
    assert!(
        authorizer
            .authorize(AuthorizationRequest {
                person: person("o@pve", &["ops"]),
                action: "VM.Audit".to_owned(),
                resource: "/vms/100".to_owned(),
            })
            .is_err()
    );
}
