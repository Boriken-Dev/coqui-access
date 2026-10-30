//! NetBox object permissions, written in this model from its documentation and source:
//! <https://netboxlabs.com/docs/netbox/administration/permissions/>,
//! <https://netboxlabs.com/docs/netbox/models/users/objectpermission/>,
//! <https://netboxlabs.com/docs/netbox/configuration/security/>,
//! <https://netboxlabs.com/docs/netbox/v4.5/features/resource-ownership>,
//! `netbox/netbox/authentication/__init__.py` in
//! <https://github.com/netbox-community/netbox>.
//!
//! An `ObjectPermission` (object types, actions, constraints, assigned to users and groups)
//! is one `Additive` entry per assignee on the ACL of each object type it names; its
//! constraints are the entry's condition, decided by the consumer against its database;
//! a store answers an object's ACL with its type's.

mod support;

use std::collections::BTreeMap;

use coqui_access::guatiao::library::ProviderError;
use coqui_access::{AuthorizationRequest, Authorizer, Person};
use coqui_access_acl::{
    Acl, AclAuthorizer, AclError, AclStore, Conditions, Context, Entry, ItemAcl, Mode, Options,
    Principal, RightsSchema, Truth, Weakening,
};
use support::{person, subject};

fn actions() -> RightsSchema {
    RightsSchema::builder()
        .rights(["view", "add", "change", "delete", "napalm_read"])
        .build()
        .unwrap()
}

/// Objects as the consumer's database keeps them: `dcim.site/12` has a tenant and an owner.
struct Netbox {
    types: BTreeMap<&'static str, Acl>,
    sites: BTreeMap<&'static str, (&'static str, &'static str)>,
}

impl Netbox {
    fn new() -> Self {
        let mut types = BTreeMap::new();
        types.insert(
            "dcim.site",
            Acl::new(Mode::Additive)
                // Permission "acme sites": view and change, tenant acme, for group noc.
                .entry(
                    Entry::allow(subject("group:noc"), ["view", "change"])
                        .condition(r#"{"tenant__slug": "acme"}"#),
                )
                // Permission "own sites": every action on what the user owns ($user).
                .entry(
                    Entry::allow(Principal::Authenticated, ["view", "change", "delete"])
                        .condition(r#"{"owner": "$user"}"#),
                )
                // Permission "globex view": a list ORs, here for one user.
                .entry(
                    Entry::allow(subject("account:gail"), ["view"])
                        .condition(r#"[{"tenant__slug": "globex"}, {"tenant__slug": "initech"}]"#),
                ),
        );
        types.insert(
            "dcim.region",
            // EXEMPT_VIEW_PERMISSIONS = ["dcim.region"]: anyone may view.
            Acl::new(Mode::Additive).entry(Entry::allow(Principal::Everyone, ["view"])),
        );
        let sites = BTreeMap::from([
            ("dcim.site/1", ("acme", "olaf")),
            ("dcim.site/2", ("globex", "olaf")),
            ("dcim.site/3", ("initech", "nobody")),
        ]);
        Self { types, sites }
    }
}

impl AclStore for Netbox {
    fn acl(&self, item: &str) -> Result<Option<ItemAcl>, ProviderError> {
        let kind = item.split('/').next().unwrap_or_default();
        Ok(self.types.get(kind).cloned().map(ItemAcl::new))
    }

    fn parent(&self, _: &str) -> Result<Option<String>, ProviderError> {
        Ok(None)
    }
}

impl Conditions for Netbox {
    fn holds(&self, condition: &str, item: &str, person: &Person) -> Truth {
        let Some((tenant, owner)) = self.sites.get(item) else {
            return Truth::Unknown;
        };
        let tenant_is = |slug: &str| *tenant == slug;
        match condition {
            r#"{"tenant__slug": "acme"}"# => tenant_is("acme").into_truth(),
            r#"{"owner": "$user"}"# => (*owner == person.name).into_truth(),
            r#"[{"tenant__slug": "globex"}, {"tenant__slug": "initech"}]"# => {
                (tenant_is("globex") || tenant_is("initech")).into_truth()
            }
            _ => Truth::Unknown,
        }
    }
}

trait IntoTruth {
    fn into_truth(self) -> Truth;
}

impl IntoTruth for bool {
    fn into_truth(self) -> Truth {
        if self { Truth::True } else { Truth::False }
    }
}

fn may(who: &Person, action: &str, item: &str) -> bool {
    let netbox = Netbox::new();
    let schema = actions();
    netbox
        .check(
            item,
            &Context::new(&schema).person(who).conditions(&netbox),
            &schema.rights([action]).unwrap(),
        )
        .unwrap()
        .allowed
}

#[test]
fn constraints_narrow_a_permission_to_matching_objects() {
    let noc = person("nina", &["noc"]);
    assert!(may(&noc, "change", "dcim.site/1"));
    assert!(!may(&noc, "change", "dcim.site/2"), "another tenant");
    assert!(
        !may(&noc, "delete", "dcim.site/1"),
        "an action the permission lacks"
    );
}

#[test]
fn permissions_are_ored_and_a_list_of_constraints_is_ored() {
    let olaf = person("olaf", &["noc"]);
    assert!(
        may(&olaf, "delete", "dcim.site/1"),
        "his own site, through the owner permission"
    );
    assert!(
        may(&olaf, "change", "dcim.site/2"),
        "owner permission alone"
    );
    let gail = person("gail", &[]);
    assert!(may(&gail, "view", "dcim.site/2") && may(&gail, "view", "dcim.site/3"));
    assert!(!may(&gail, "view", "dcim.site/1"));
}

#[test]
fn a_constraint_the_consumer_cannot_decide_grants_nothing() {
    // dcim.site/9 is not in the database: every constraint on it is unknown.
    assert!(!may(&person("olaf", &["noc"]), "view", "dcim.site/9"));
}

#[test]
fn nothing_is_granted_by_default_and_there_is_no_deny() {
    assert!(!may(&person("x", &[]), "view", "dcim.site/1"));
    assert!(
        !may(&person("x", &[]), "view", "dcim.device/1"),
        "a type with no permission"
    );
    let deny = Acl::new(Mode::Additive).entry(Entry::deny(subject("group:noc"), ["view"]));
    assert!(matches!(
        deny.validate(&actions(), &Options::new()),
        Err(AclError::DenyNotAllowed { entry: 0 })
    ));
}

#[test]
fn exempt_view_types_are_open_to_anyone_and_reported_as_a_weakening() {
    let netbox = Netbox::new();
    let schema = actions();
    let anonymous = Context::new(&schema);
    let view = schema.rights(["view"]).unwrap();
    assert!(
        netbox
            .check("dcim.region/4", &anonymous, &view)
            .unwrap()
            .allowed
    );
    assert_eq!(
        netbox.types["dcim.region"].weakened(),
        [Weakening::EveryoneAllowed { entry: 0 }]
    );
    assert!(netbox.types["dcim.site"].weakened().is_empty());
}

#[test]
fn a_read_only_token_is_the_users_decision_intersected_with_view() {
    let netbox = Netbox::new();
    let schema = actions();
    let olaf = person("olaf", &[]);
    let context = Context::new(&schema).person(&olaf).conditions(&netbox);
    // write_enabled = false: the token's own list grants view on everything.
    let read_only = Acl::new(Mode::Additive).entry(Entry::allow(Principal::Everyone, ["view"]));
    for (action, allowed) in [("view", true), ("change", false)] {
        let wanted = schema.rights([action]).unwrap();
        let user = netbox.check("dcim.site/1", &context, &wanted).unwrap();
        assert!(user.allowed);
        let token = read_only.check(&context, &wanted).unwrap();
        assert_eq!(user.intersect(&token).allowed, allowed, "{action}");
    }
}

#[test]
fn an_owner_field_grants_nothing_by_itself() {
    let schema = actions();
    let owned = ItemAcl::new(Acl::new(Mode::Additive)).owner(subject("account:olaf"));
    let olaf = person("olaf", &[]);
    let decision = owned
        .check(
            &Context::new(&schema).person(&olaf),
            &schema.rights(["view"]).unwrap(),
        )
        .unwrap();
    assert!(!decision.allowed);
}

#[test]
fn the_authorizer_answers_netboxs_questions_through_the_kind() {
    let authorizer = AclAuthorizer::new(Netbox::new(), actions()).conditions(Netbox::new());
    let ask = |who: &Person, action: &str, item: &str| {
        authorizer
            .authorize(AuthorizationRequest {
                person: who.clone(),
                action: action.to_owned(),
                resource: item.to_owned(),
                ancestors: Vec::new(),
            })
            .unwrap()
            .allowed
    };
    let noc = person("nina", &["noc"]);
    assert!(ask(&noc, "change", "dcim.site/1"));
    assert!(!ask(&noc, "change", "dcim.site/2"));
    assert!(
        !ask(&noc, "reboot", "dcim.site/1"),
        "an action no type defines"
    );
}
