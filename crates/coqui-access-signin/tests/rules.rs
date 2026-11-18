//! The reference evaluation, through the public API: what is offered before anyone is named,
//! what decides once someone is, and what a rule set refuses to build.

use coqui_access::{
    Factor, Limit, Person, SignInContext, SignInDecision, SignInPolicy, clients, methods, purposes,
};
use coqui_access_signin::{RuleDef, SignInLimits, SignInRules};

fn context(purpose: &str, address: Option<&str>) -> SignInContext {
    SignInContext {
        purpose: purpose.to_owned(),
        address: address.map(str::to_owned),
        ..SignInContext::default()
    }
}

fn alice() -> Person {
    Person {
        id: "id-alice".to_owned(),
        name: "alice".to_owned(),
        groups: vec!["admins".to_owned()],
        ..Person::default()
    }
}

fn bob() -> Person {
    Person {
        id: "id-bob".to_owned(),
        name: "bob".to_owned(),
        ..Person::default()
    }
}

fn factor(method: &str) -> Factor {
    Factor {
        method: method.to_owned(),
        provider: None,
        person: None,
    }
}

fn by(method: &str, person: &str) -> Factor {
    Factor {
        person: Some(person.to_owned()),
        ..factor(method)
    }
}

fn named(person: Person, done: &[&str], mut base: SignInContext) -> SignInContext {
    base.person = Some(person);
    base.done = done.iter().map(|method| factor(method)).collect();
    base
}

fn offered(decision: &SignInDecision) -> Vec<&str> {
    decision
        .methods
        .iter()
        .map(|offer| offer.method.as_str())
        .collect()
}

/// Password or certificate inside 10/8; the certificate alone anywhere else.
fn owners() -> SignInRules {
    SignInRules::builder()
        .rule(RuleDef::new([["password"], ["certificate"]]).networks(["10.0.0.0/8"]))
        .rule(RuleDef::new([["certificate"]]))
        .build()
        .unwrap()
}

#[test]
fn inside_the_network_a_password_or_a_certificate_is_offered() {
    let decision = owners()
        .decide(context(purposes::SIGN_IN, Some("10.1.2.3")))
        .unwrap();
    assert_eq!(offered(&decision), ["password", "certificate"]);
    assert!(!decision.complete);
}

#[test]
fn an_address_that_is_outside_ipv6_unknown_or_not_an_address_falls_to_the_strict_rule() {
    for address in [
        Some("203.0.113.7"),
        Some("2001:db8::1"),
        None,
        Some("10.1.2.3:443"),
        Some("not an address"),
        Some(""),
        Some("0.0.0.0"),
    ] {
        let decision = owners()
            .decide(context(purposes::SIGN_IN, address))
            .unwrap();
        assert_eq!(offered(&decision), ["certificate"], "{address:?}");
    }
}

#[test]
fn an_ipv4_mapped_address_is_the_ipv4_address() {
    let decision = owners()
        .decide(context(purposes::SIGN_IN, Some("::ffff:10.0.0.9")))
        .unwrap();
    assert_eq!(offered(&decision), ["password", "certificate"]);
}

#[test]
fn the_first_true_rule_stops_the_walk_before_anyone_is_named() {
    let decision = owners()
        .decide(context(purposes::SIGN_IN, Some("10.1.2.3")))
        .unwrap();
    // The strict rule below is not merged in: it would add nothing here, but a rule below
    // that did would not leak into the offer.
    let rules = SignInRules::builder()
        .rule(
            RuleDef::new([["password"]])
                .name("office")
                .networks(["10.0.0.0/8"]),
        )
        .rule(RuleDef::new([["key"]]))
        .build()
        .unwrap();
    let inside = rules
        .decide(context(purposes::SIGN_IN, Some("10.9.9.9")))
        .unwrap();
    assert_eq!(offered(&inside), ["password"]);
    assert_eq!(inside.rule.as_deref(), Some("office"));
    assert_eq!(decision.rule.as_deref(), Some("0"));
}

#[test]
fn a_rule_about_who_is_unknown_before_anyone_is_named_and_adds_its_methods() {
    let rules = SignInRules::builder()
        .rule(RuleDef::new([["password", "totp"]]).subjects(["group:admins"]))
        .rule(RuleDef::new([["password"]]))
        .build()
        .unwrap();
    let before = rules
        .decide(context(purposes::SIGN_IN, Some("10.1.2.3")))
        .unwrap();
    // totp needs an account, so it is not offered before one is named.
    assert_eq!(offered(&before), ["password"]);
    assert_eq!(before.rule.as_deref(), Some("1"));

    // Once alice (an admin) is named, the first rule decides alone and wants a code too.
    let after = rules
        .decide(named(
            alice(),
            &["password"],
            context(purposes::SIGN_IN, Some("10.1.2.3")),
        ))
        .unwrap();
    assert!(!after.complete);
    assert_eq!(offered(&after), ["totp"]);
    assert_eq!(after.rule.as_deref(), Some("0"));

    // Bob is not an admin: the first rule is false for him and the password is enough.
    let bobs = rules
        .decide(named(
            bob(),
            &["password"],
            context(purposes::SIGN_IN, Some("10.1.2.3")),
        ))
        .unwrap();
    assert!(bobs.complete);
    assert!(bobs.methods.is_empty());
}

#[test]
fn a_unknown_rule_that_is_false_on_another_condition_is_not_collected() {
    let rules = SignInRules::builder()
        .rule(
            RuleDef::new([["key"]])
                .subjects(["group:admins"])
                .networks(["192.0.2.0/24"]),
        )
        .rule(RuleDef::new([["password"]]))
        .build()
        .unwrap();
    let decision = rules
        .decide(context(purposes::SIGN_IN, Some("10.1.2.3")))
        .unwrap();
    assert_eq!(offered(&decision), ["password"]);
}

#[test]
fn an_unknown_rule_before_a_true_one_adds_to_the_offer_in_order() {
    let rules = SignInRules::builder()
        .rule(RuleDef::new([["key"]]).subjects(["group:admins"]))
        .rule(RuleDef::new([["password"]]))
        .rule(RuleDef::new([["certificate"]]))
        .build()
        .unwrap();
    let decision = rules
        .decide(context(purposes::SIGN_IN, Some("10.1.2.3")))
        .unwrap();
    assert_eq!(offered(&decision), ["key", "password"]);
}

#[test]
fn once_someone_is_named_only_the_first_true_rule_decides() {
    let rules = SignInRules::builder()
        .rule(RuleDef::new([["certificate"]]).networks(["10.0.0.0/8"]))
        .rule(RuleDef::new([["password"]]))
        .build()
        .unwrap();
    // Inside, the first rule applies: a password is not enough, though the second rule
    // would accept it.
    let inside = rules
        .decide(named(
            alice(),
            &["password"],
            context(purposes::SIGN_IN, Some("10.0.0.5")),
        ))
        .unwrap();
    assert!(!inside.complete);
    assert!(inside.methods.is_empty(), "a refusal, not a step up");
    let outside = rules
        .decide(named(
            alice(),
            &["password"],
            context(purposes::SIGN_IN, Some("192.0.2.5")),
        ))
        .unwrap();
    assert!(outside.complete);
}

#[test]
fn a_chain_is_complete_only_when_every_method_in_it_is_done() {
    let rules = SignInRules::builder()
        .rule(RuleDef::new([
            vec!["password", "totp"],
            vec!["certificate"],
        ]))
        .build()
        .unwrap();
    let ask = |done: &[&str]| {
        rules
            .decide(named(alice(), done, context(purposes::SIGN_IN, None)))
            .unwrap()
    };
    let none = ask(&[]);
    assert!(!none.complete);
    assert_eq!(offered(&none), ["password", "totp", "certificate"]);
    let password = ask(&["password"]);
    assert!(!password.complete);
    assert_eq!(offered(&password), ["totp"]);
    assert!(ask(&["password", "totp"]).complete);
    assert!(ask(&["certificate"]).complete);
    // Steps beyond a whole chain do not undo it.
    assert!(ask(&["password", "certificate"]).complete);
    // A step no chain holds is a refusal.
    let stray = ask(&["key"]);
    assert!(!stray.complete && stray.methods.is_empty());
}

#[test]
fn a_session_resumed_from_outside_loses_what_only_the_inside_accepted() {
    let rules = owners();
    let resumed = rules
        .decide(named(
            alice(),
            &["password"],
            context(purposes::RESUME, Some("203.0.113.7")),
        ))
        .unwrap();
    assert!(!resumed.complete);
    let at_the_office = rules
        .decide(named(
            alice(),
            &["password"],
            context(purposes::RESUME, Some("10.2.3.4")),
        ))
        .unwrap();
    assert!(at_the_office.complete);
    let by_certificate = rules
        .decide(named(
            alice(),
            &["certificate"],
            context(purposes::RESUME, Some("203.0.113.7")),
        ))
        .unwrap();
    assert!(by_certificate.complete);
}

#[test]
fn enrolling_inside_a_sign_in_needs_a_rule_that_names_it_and_a_rule_for_enrol_is_not_one() {
    let for_enrol = SignInRules::builder()
        .rule(
            RuleDef::new([["password"]])
                .name("enrol")
                .purposes([purposes::ENROL]),
        )
        .rule(RuleDef::new([["password"]]))
        .build()
        .unwrap();
    let ask = |rules: &SignInRules, purpose: &str| {
        rules
            .decide(named(
                alice(),
                &["password"],
                context(purpose, Some("10.1.2.3")),
            ))
            .unwrap()
    };
    assert!(ask(&for_enrol, purposes::ENROL).complete);
    let first = ask(&for_enrol, purposes::ENROL_FIRST);
    assert!(
        !first.complete && first.methods.is_empty(),
        "a rule for enrol is not one for enrol_first"
    );
    let named_first = SignInRules::builder()
        .rule(
            RuleDef::new([["password"]])
                .name("first use")
                .networks(["10.0.0.0/8"])
                .purposes([purposes::ENROL_FIRST]),
        )
        .build()
        .unwrap();
    assert!(ask(&named_first, purposes::ENROL_FIRST).complete);
    let outside = named_first
        .decide(named(
            alice(),
            &["password"],
            context(purposes::ENROL_FIRST, Some("203.0.113.7")),
        ))
        .unwrap();
    assert!(!outside.complete);
    assert!(!ask(&named_first, purposes::ENROL).complete);
}

#[test]
fn enrolment_needs_a_rule_that_names_it() {
    let without = owners();
    let refused = without
        .decide(named(
            alice(),
            &["password"],
            context(purposes::ENROL, Some("10.1.2.3")),
        ))
        .unwrap();
    assert!(!refused.complete && refused.methods.is_empty());
    assert!(refused.rule.is_none());

    let with = SignInRules::builder()
        .rule(
            RuleDef::new([["certificate"]])
                .name("enrol")
                .purposes([purposes::ENROL]),
        )
        .rule(RuleDef::new([["password"]]))
        .build()
        .unwrap();
    let ask = |done: &[&str], purpose: &str| {
        with.decide(named(alice(), done, context(purpose, None)))
            .unwrap()
    };
    assert!(!ask(&["password"], purposes::ENROL).complete);
    let enrolling = ask(&["certificate"], purposes::ENROL);
    assert!(enrolling.complete);
    assert_eq!(enrolling.rule.as_deref(), Some("enrol"));
    // The enrol rule does not apply to a sign-in.
    assert!(ask(&["password"], purposes::SIGN_IN).complete);
}

#[test]
fn a_purpose_nobody_knows_matches_no_rule() {
    let decision = owners()
        .decide(context("something_else", Some("10.1.2.3")))
        .unwrap();
    assert!(decision.methods.is_empty());
}

#[test]
fn no_rule_offers_nothing_and_completes_nothing() {
    let rules = SignInRules::builder().build().unwrap();
    let decision = rules
        .decide(context(purposes::SIGN_IN, Some("10.1.2.3")))
        .unwrap();
    assert!(!decision.complete && decision.methods.is_empty());
    let named = rules
        .decide(named(
            alice(),
            &["password"],
            context(purposes::SIGN_IN, None),
        ))
        .unwrap();
    assert!(!named.complete);
}

#[test]
fn clients_and_services_narrow_a_rule_and_an_unsaid_one_does_not_match() {
    let rules = SignInRules::builder()
        .rule(
            RuleDef::new([["key"]])
                .clients([clients::API])
                .services(["unex"]),
        )
        .rule(RuleDef::new([["password"]]))
        .build()
        .unwrap();
    let mut api = context(purposes::SIGN_IN, None);
    api.client = Some(clients::API.to_owned());
    api.service = Some("unex".to_owned());
    assert_eq!(offered(&rules.decide(api.clone()).unwrap()), ["key"]);
    api.service = Some("portal".to_owned());
    assert_eq!(offered(&rules.decide(api.clone()).unwrap()), ["password"]);
    api.service = None;
    assert_eq!(offered(&rules.decide(api).unwrap()), ["password"]);
    let mut browser = context(purposes::SIGN_IN, None);
    browser.client = Some(clients::BROWSER.to_owned());
    browser.service = Some("unex".to_owned());
    assert_eq!(offered(&rules.decide(browser).unwrap()), ["password"]);
}

#[test]
fn a_rule_that_names_providers_offers_only_them_and_counts_only_their_steps() {
    let rules = SignInRules::builder()
        .rule(
            RuleDef::new([["password"]])
                .networks(["10.0.0.0/8"])
                .providers(["ldap"]),
        )
        .rule(RuleDef::new([["password"], ["certificate"]]).providers(["local"]))
        .build()
        .unwrap();
    let inside = rules
        .decide(context(purposes::SIGN_IN, Some("10.1.1.1")))
        .unwrap();
    assert_eq!(inside.methods[0].providers, ["ldap"]);

    let ldap_step = SignInContext {
        done: vec![Factor {
            method: "password".to_owned(),
            provider: Some("ldap".to_owned()),
            person: None,
        }],
        person: Some(alice()),
        ..context(purposes::RESUME, Some("10.1.1.1"))
    };
    assert!(rules.decide(ldap_step.clone()).unwrap().complete);
    for provider in [Some("local".to_owned()), None] {
        let mut other = ldap_step.clone();
        other.done[0].provider = provider;
        let decision = rules.decide(other).unwrap();
        assert!(!decision.complete, "a step by another provider is not done");
        assert_eq!(offered(&decision), ["password"]);
    }
}

#[test]
fn a_method_offered_by_two_rules_asks_the_union_of_their_providers_or_any() {
    let rules = SignInRules::builder()
        .rule(
            RuleDef::new([["password"]])
                .subjects(["group:a"])
                .providers(["one"]),
        )
        .rule(
            RuleDef::new([["password"]])
                .subjects(["group:b"])
                .providers(["two"]),
        )
        .rule(RuleDef::new([["password"]]).subjects(["group:c"]))
        .build()
        .unwrap();
    let decision = rules.decide(context(purposes::SIGN_IN, None)).unwrap();
    assert_eq!(decision.methods.len(), 1);
    assert!(decision.methods[0].providers.is_empty(), "any provider");
    let narrower = SignInRules::builder()
        .rule(
            RuleDef::new([["password"]])
                .subjects(["group:a"])
                .providers(["one"]),
        )
        .rule(RuleDef::new([["password"]]).providers(["two"]))
        .build()
        .unwrap();
    let decision = narrower.decide(context(purposes::SIGN_IN, None)).unwrap();
    assert_eq!(decision.methods[0].providers, ["one", "two"]);
}

#[test]
fn single_factor_accepts_each_method_alone_and_enrolment_is_not_offered() {
    let rules = SignInRules::single_factor(["password", "proxy"]).unwrap();
    let decision = rules.decide(context(purposes::SIGN_IN, None)).unwrap();
    assert_eq!(offered(&decision), ["password", "proxy"]);
    let done = rules
        .decide(named(alice(), &["proxy"], context(purposes::RESUME, None)))
        .unwrap();
    assert!(done.complete);
    let enrol = rules
        .decide(named(alice(), &["proxy"], context(purposes::ENROL, None)))
        .unwrap();
    assert!(!enrol.complete);
    assert!(SignInRules::single_factor(["totp"]).is_err());
}

fn refused(rule: RuleDef) -> String {
    SignInRules::builder()
        .rule(rule)
        .build()
        .expect_err("the rule is refused")
        .to_string()
}

#[test]
fn a_rule_that_cannot_work_is_refused_at_build_time() {
    let none: [[&str; 1]; 0] = [];
    assert!(refused(RuleDef::new(none)).contains("rule 0"));
    assert!(!refused(RuleDef::new([Vec::<String>::new()])).is_empty());
    assert!(refused(RuleDef::new([["password", "password"]])).contains("repeats"));
    assert!(refused(RuleDef::new([["totp"]])).contains("never start"));
    assert!(refused(RuleDef::new([["totp", "recovery_code"]])).contains("never start"));
    assert!(!refused(RuleDef::new([["Password"]])).is_empty());
    assert!(!refused(RuleDef::new([[""]])).is_empty());
    assert!(!refused(RuleDef::new([["password"]]).networks(["10.0.0.0/33"])).is_empty());
    assert!(!refused(RuleDef::new([["password"]]).networks(["somewhere"])).is_empty());
    assert!(refused(RuleDef::new([["password"]]).networks(["any"])).contains("no networks"));
    assert!(!refused(RuleDef::new([["password"]]).subjects(["alice"])).is_empty());
    assert!(!refused(RuleDef::new([["password"]]).purposes(["login"])).is_empty());
    let nothing: [&str; 0] = [];
    assert!(refused(RuleDef::new([["password"]]).purposes(nothing)).contains("purposes"));
    assert!(!refused(RuleDef::new([["password"]]).clients(["phone"])).is_empty());
    assert!(!refused(RuleDef::new([["password"]]).name("")).is_empty());
}

#[test]
fn a_refusal_names_the_rule_by_position_and_never_quotes_the_input() {
    let secret = "needle-in-the-haystack";
    let error = SignInRules::builder()
        .rule(RuleDef::new([["password"]]))
        .rule(RuleDef::new([["password"]]).networks([secret]))
        .rule(RuleDef::new([[secret]]))
        .build()
        .unwrap_err()
        .to_string();
    assert!(error.starts_with("rule 1:"), "{error}");
    for rule in [
        RuleDef::new([["password"]]).networks([secret]),
        RuleDef::new([["password"]]).subjects([secret]),
        RuleDef::new([["password"]]).clients([secret]),
        RuleDef::new([["password"]]).purposes([secret]),
        RuleDef::new([[secret]]),
    ] {
        assert!(!refused(rule).contains(secret));
    }
}

#[test]
fn the_limits_bound_the_set_and_a_caller_lifts_them() {
    let build = |limits: SignInLimits, extra: usize| {
        let mut builder = SignInRules::builder().limits(limits);
        for _ in 0..extra {
            builder = builder.rule(RuleDef::new([["password"]]));
        }
        builder.build()
    };
    assert!(build(SignInLimits::default().rules(Limit::at(2)), 3).is_err());
    assert!(build(SignInLimits::default().rules(Limit::at(2)), 2).is_ok());
    assert!(build(SignInLimits::UNBOUNDED.rules(Limit::UNBOUNDED), 2_000).is_ok());
    assert!(build(SignInLimits::default(), 1_025).is_err());
    let long = RuleDef::new([["password", "totp", "key"]]);
    assert!(
        SignInRules::builder()
            .limits(SignInLimits::default().chain_methods(Limit::at(2)))
            .rule(long)
            .build()
            .is_err()
    );
    let many = RuleDef::new([["password"], ["key"], ["proxy"]]);
    assert!(
        SignInRules::builder()
            .limits(SignInLimits::default().chains(Limit::at(2)))
            .rule(many)
            .build()
            .is_err()
    );
    let nets = RuleDef::new([["password"]]).networks(["10.0.0.0/8", "192.168.0.0/16"]);
    assert!(
        SignInRules::builder()
            .limits(SignInLimits::default().networks(Limit::at(1)))
            .rule(nets)
            .build()
            .is_err()
    );
}

#[test]
fn debug_shows_a_count_and_no_rule_content() {
    let shown = format!("{:?}", owners());
    assert!(
        shown.contains("rules") && !shown.contains("10.0.0.0"),
        "{shown}"
    );
}

#[test]
fn the_methods_words_are_the_ones_the_rules_use() {
    assert!(methods::NEEDS_ACCOUNT.contains(&methods::TOTP));
    assert!(!methods::NEEDS_ACCOUNT.contains(&methods::PASSWORD));
}

#[test]
fn steps_that_name_different_people_are_one_sign_in_for_nobody() {
    let rules = SignInRules::builder()
        .rule(RuleDef::new([["password", "totp"]]))
        .build()
        .unwrap();
    let ask = |done: Vec<Factor>, person: Option<Person>| {
        rules
            .decide(SignInContext {
                done,
                person,
                ..context(purposes::SIGN_IN, None)
            })
            .unwrap()
    };
    // The same person throughout is one sign-in.
    let same = ask(vec![by("password", "id-alice")], Some(alice()));
    assert_eq!(offered(&same), ["totp"]);
    assert!(
        ask(
            vec![by("password", "id-alice"), by("totp", "id-alice")],
            Some(alice())
        )
        .complete
    );
    // Two steps naming different people are refused, complete or not, named or not.
    let mixed = vec![by("password", "id-alice"), by("totp", "id-bob")];
    for person in [None, Some(alice()), Some(bob())] {
        let refused = ask(mixed.clone(), person);
        assert!(!refused.complete && refused.methods.is_empty());
    }
    // A step that names someone other than the context's person is refused too.
    let other = ask(vec![by("password", "id-bob")], Some(alice()));
    assert!(!other.complete && other.methods.is_empty());
    // A step that names nobody is not held against it.
    assert!(
        ask(
            vec![factor("password"), by("totp", "id-alice")],
            Some(alice())
        )
        .complete
    );
}

#[test]
fn a_rule_about_a_group_applies_to_a_person_whose_group_differs_only_in_case() {
    let rules = SignInRules::builder()
        .rule(RuleDef::new([["password", "totp"]]).subjects(["group:Admins"]))
        .rule(RuleDef::new([["password"]]))
        .build()
        .unwrap();
    let decide = |person| {
        rules
            .decide(named(
                person,
                &["password"],
                context(purposes::SIGN_IN, Some("10.1.2.3")),
            ))
            .unwrap()
    };
    // alice's group is `admins`: the rule written `Admins` is the one that wants a code.
    let admin = decide(alice());
    assert_eq!(admin.rule.as_deref(), Some("0"));
    assert_eq!(offered(&admin), ["totp"]);
    let other = Person {
        groups: vec!["administrators".to_owned()],
        ..alice()
    };
    assert_eq!(decide(other).rule.as_deref(), Some("1"));
}
