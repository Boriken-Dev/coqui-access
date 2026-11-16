//! The matcher: templates over claims, the LDAP filter and its escaping, and the order in
//! which rules find an account.

use std::collections::BTreeMap;
use std::sync::Mutex;

use coqui_access::error;
use coqui_access::guatiao::library::ProviderError;
use coqui_access::{Claims, Directory, Lookup, Person};
use coqui_access_kit::matcher::{Match, MatchRule, Matcher, MatcherConfig, escape_filter_value};
use coqui_access_kit::pins::{PinCheck, PinSet, PinSource};

/// A directory that answers what it is told to and remembers what it was asked.
#[derive(Default)]
struct Stand {
    answers: BTreeMap<(String, String), Result<Option<Person>, ProviderError>>,
    asked: Mutex<Vec<(String, String)>>,
}

impl Stand {
    fn knows(mut self, by: &str, value: &str, id: &str) -> Self {
        self.answers.insert(
            (by.to_owned(), value.to_owned()),
            Ok(Some(Person {
                id: id.to_owned(),
                name: id.to_owned(),
                ..Person::default()
            })),
        );
        self
    }

    fn fails(mut self, by: &str, value: &str, error: ProviderError) -> Self {
        self.answers
            .insert((by.to_owned(), value.to_owned()), Err(error));
        self
    }

    fn asked(&self) -> Vec<(String, String)> {
        self.asked.lock().unwrap().clone()
    }
}

impl Directory for Stand {
    fn lookup(&self, lookup: Lookup) -> Result<Option<Person>, ProviderError> {
        let key = (lookup.by, lookup.value);
        self.asked.lock().unwrap().push(key.clone());
        match self.answers.get(&key) {
            Some(Ok(found)) => Ok(found.clone()),
            Some(Err(error)) => Err(ProviderError::new(error.status, error.message())),
            None => Ok(None),
        }
    }
}

fn claims(pairs: &[(&str, &[&str])]) -> Lookup {
    Lookup {
        by: "claims".to_owned(),
        value: "label".to_owned(),
        claims: Some(Claims {
            values: pairs
                .iter()
                .map(|(name, values)| {
                    (
                        (*name).to_owned(),
                        values.iter().map(|value| (*value).to_owned()).collect(),
                    )
                })
                .collect(),
            certificate: None,
        }),
    }
}

fn matcher(rules: &[(&str, &str)]) -> Matcher {
    let mut config = MatcherConfig::default();
    config.rule = rules
        .iter()
        .map(|(by, template)| MatchRule::new(*by, *template))
        .collect();
    Matcher::new(config).unwrap()
}

/// A rule that strips a realm, which a rule must say which realm it is and a test says so.
fn realm(by: &str, template: &str) -> MatchRule {
    MatchRule::new(by, template).domain("corp.example")
}

fn found(result: Match) -> String {
    match result {
        Match::Found(person) => person.id,
        other => panic!("expected an account, got {other:?}"),
    }
}

#[test]
fn a_name_template_renders_claims_through_its_filters() {
    let lookup = claims(&[
        ("subject.cn", &["Client ONE"]),
        ("san.upn", &["Clientone@Corp.Example"]),
    ]);
    for (template, rendered) in [
        ("{subject.cn|lower}", "client one"),
        ("{subject.cn|upper}", "CLIENT ONE"),
        ("{san.upn|local}", "Clientone"),
        ("{san.upn|domain}", "Corp.Example"),
        ("{san.upn|local|lower}", "clientone"),
        ("{san.upn|domain|upper}", "CORP.EXAMPLE"),
        ("prefix-{subject.cn|lower}-{{x}}", "prefix-client one-{x}"),
    ] {
        let directory = Stand::default().knows("name", rendered, "p");
        let mut config = MatcherConfig::default();
        config.rule = vec![if template.contains("local") {
            realm("name", template)
        } else {
            MatchRule::new("name", template)
        }];
        let result = Matcher::new(config)
            .unwrap()
            .resolve(&lookup, &directory)
            .unwrap();
        assert_eq!(found(result.result), "p", "{template}");
        assert_eq!(
            directory.asked(),
            [("name".to_owned(), rendered.to_owned())]
        );
    }
}

#[test]
fn the_default_matcher_tries_the_upn_then_the_email_and_never_the_common_name() {
    let lookup = claims(&[
        ("san.upn", &["u@corp.example"]),
        ("san.email", &["e@example.org"]),
        ("subject.cn", &["Common"]),
    ]);
    // A common name is whatever the issuer let the holder type: it names nobody by default.
    let by_cn = Stand::default().knows("name", "Common", "cn");
    assert!(matches!(
        Matcher::default().resolve(&lookup, &by_cn).unwrap().result,
        Match::NotFound
    ));
    assert_eq!(
        by_cn.asked(),
        [
            ("name".to_owned(), "u@corp.example".to_owned()),
            ("email".to_owned(), "e@example.org".to_owned()),
        ]
    );
    let by_upn = Stand::default()
        .knows("name", "u@corp.example", "upn")
        .knows("email", "e@example.org", "mail");
    assert_eq!(
        found(Matcher::default().resolve(&lookup, &by_upn).unwrap().result),
        "upn"
    );
    assert_eq!(
        by_upn.asked().len(),
        1,
        "the first rule that finds one wins"
    );
}

#[test]
fn a_rule_whose_claim_is_missing_or_empty_asks_nobody() {
    let directory = Stand::default();
    let lookup = claims(&[("san.upn", &[""]), ("subject.cn", &[])]);
    let result = Matcher::default().resolve(&lookup, &directory).unwrap();
    assert!(matches!(result.result, Match::NotFound));
    assert!(directory.asked().is_empty());
    // `domain` of a value with no `@` is nothing.
    let lookup = claims(&[("san.upn", &["plain"])]);
    let result = matcher(&[("name", "{san.upn|domain}")])
        .resolve(&lookup, &directory)
        .unwrap();
    assert!(matches!(result.result, Match::NotFound));
    assert!(directory.asked().is_empty());
}

#[test]
fn several_values_ask_each_and_two_accounts_are_ambiguous() {
    let lookup = claims(&[("san.email", &["a@example.org", "b@example.org"])]);
    let two = Stand::default()
        .knows("email", "a@example.org", "alice")
        .knows("email", "b@example.org", "bob");
    let result = matcher(&[("email", "{san.email}")])
        .resolve(&lookup, &two)
        .unwrap();
    assert!(matches!(result.result, Match::Ambiguous));
    // Two values for the same account are one account.
    let same = Stand::default()
        .knows("email", "a@example.org", "alice")
        .knows("email", "b@example.org", "alice");
    let result = matcher(&[("email", "{san.email}")])
        .resolve(&lookup, &same)
        .unwrap();
    assert_eq!(found(result.result), "alice");
}

#[test]
fn a_filter_escapes_every_value_it_substitutes_and_a_name_does_not() {
    for hostile in [
        "*)(uid=*",
        "a\\b",
        "nul\0byte",
        "line\nfeed",
        "(x)",
        "caf\u{e9}",
    ] {
        let lookup = claims(&[("san.upn", &[hostile])]);
        let directory = Stand::default();
        matcher(&[("filter", "(userPrincipalName={san.upn})")])
            .resolve(&lookup, &directory)
            .unwrap();
        let asked = directory.asked();
        assert_eq!(asked.len(), 1);
        assert_eq!(asked[0].0, "filter");
        assert_eq!(
            asked[0].1,
            format!("(userPrincipalName={})", escape_filter_value(hostile))
        );
        let (attribute, value) = single_assertion(&asked[0].1);
        assert_eq!(attribute, "userPrincipalName");
        assert_eq!(unescape(&value), hostile, "the value survives as one value");

        let named = Stand::default();
        matcher(&[("name", "{san.upn}")])
            .resolve(&lookup, &named)
            .unwrap();
        assert_eq!(named.asked()[0].1, hostile, "a name is not a filter");
    }
}

#[test]
fn escaping_covers_the_metacharacters_controls_and_every_non_ascii_byte() {
    assert_eq!(escape_filter_value("plain-Text_09.@"), "plain-Text_09.@");
    assert_eq!(escape_filter_value("*"), "\\2a");
    assert_eq!(escape_filter_value("("), "\\28");
    assert_eq!(escape_filter_value(")"), "\\29");
    assert_eq!(escape_filter_value("\\"), "\\5c");
    assert_eq!(escape_filter_value("\0"), "\\00");
    assert_eq!(escape_filter_value("\u{7f}\t"), "\\7f\\09");
    assert_eq!(escape_filter_value("\u{e9}"), "\\c3\\a9");
    assert_eq!(escape_filter_value("\u{1f600}"), "\\f0\\9f\\98\\80");
}

#[test]
fn an_alternative_security_identity_filter_holds_an_issuer_with_every_awkward_character() {
    let issuer = r"CN=Ca (Test)\, Inc,O=A*B,DC=example";
    let lookup = claims(&[("issuer.dn", &[issuer]), ("serial.reversed", &["1b0a"])]);
    let directory = Stand::default();
    matcher(&[(
        "filter",
        "(altSecurityIdentities=X509:<I>{issuer.dn}<SR>{serial.reversed})",
    )])
    .resolve(&lookup, &directory)
    .unwrap();
    let filter = directory.asked()[0].1.clone();
    assert!(
        filter.starts_with("(altSecurityIdentities=X509:<I>"),
        "{filter}"
    );
    let (attribute, value) = single_assertion(&filter);
    assert_eq!(attribute, "altSecurityIdentities");
    assert_eq!(unescape(&value), format!("X509:<I>{issuer}<SR>1b0a"));
    assert!(!filter.contains('*'), "no raw wildcard: {filter}");
}

#[test]
fn the_first_rule_that_finds_exactly_one_wins_and_ambiguity_ends_the_walk() {
    let lookup = claims(&[
        ("san.upn", &["u"]),
        ("san.email", &["e"]),
        ("subject.cn", &["c"]),
    ]);
    let rules = [
        ("name", "{san.upn}"),
        ("email", "{san.email}"),
        ("name", "{subject.cn}"),
    ];

    // None, then one.
    let directory = Stand::default().knows("name", "c", "cn");
    assert_eq!(
        found(matcher(&rules).resolve(&lookup, &directory).unwrap().result),
        "cn"
    );
    assert_eq!(directory.asked().len(), 3);

    // The directory says the first is ambiguous: refused, and nothing further is asked.
    let directory = Stand::default()
        .fails("name", "u", error::ambiguous())
        .knows("name", "c", "cn");
    let result = matcher(&rules).resolve(&lookup, &directory).unwrap();
    assert!(matches!(result.result, Match::Ambiguous));
    assert_eq!(directory.asked().len(), 1);

    // Could not find out: an error, never a fall-through to the next rule.
    let directory = Stand::default()
        .fails("name", "u", error::internal("unreachable"))
        .knows("name", "c", "cn");
    assert!(matcher(&rules).resolve(&lookup, &directory).is_err());
    assert_eq!(directory.asked().len(), 1);

    // Nobody anywhere.
    let result = matcher(&rules).resolve(&lookup, &Stand::default()).unwrap();
    assert!(matches!(result.result, Match::NotFound));
}

#[test]
fn a_lookup_that_is_not_by_claims_goes_to_the_directory_as_it_is() {
    let directory = Stand::default().knows("id", "x", "x");
    let plain = Lookup {
        by: "id".to_owned(),
        value: "x".to_owned(),
        claims: None,
    };
    assert_eq!(
        found(
            Matcher::default()
                .resolve(&plain, &directory)
                .unwrap()
                .result
        ),
        "x"
    );
    let none = Lookup {
        by: "claims".to_owned(),
        value: "label".to_owned(),
        claims: None,
    };
    assert!(matches!(
        Matcher::default()
            .resolve(&none, &directory)
            .unwrap()
            .result,
        Match::NotFound
    ));
}

#[test]
fn a_filter_lookup_is_never_passed_through_to_the_directory() {
    let directory = Stand::default().knows("filter", "(uid=*)", "anyone");
    for lookup in [
        Lookup {
            by: "filter".to_owned(),
            value: "(uid=*)".to_owned(),
            claims: None,
        },
        // Even with claims: only a claims lookup is templated.
        Lookup {
            claims: Some(Claims::default()),
            by: "filter".to_owned(),
            value: "(uid=*)".to_owned(),
        },
    ] {
        let result = Matcher::default().resolve(&lookup, &directory).unwrap();
        assert!(matches!(result.result, Match::NotFound));
    }
    assert!(directory.asked().is_empty(), "the directory was not asked");
}

#[test]
fn a_realm_rule_keeps_only_values_of_its_domain_and_stripping_one_without_a_realm_is_refused() {
    let lookup = claims(&[("san.upn", &["Alice@CORP.example", "mallory@evil.example"])]);
    let directory = Stand::default()
        .knows("name", "Alice", "alice")
        .knows("name", "mallory", "mallory");
    let mut config = MatcherConfig::default();
    config.rule = vec![realm("name", "{san.upn|local}")];
    let result = Matcher::new(config)
        .unwrap()
        .resolve(&lookup, &directory)
        .unwrap();
    assert_eq!(found(result.result), "alice");
    assert_eq!(directory.asked(), [("name".to_owned(), "Alice".to_owned())]);

    let build = |rule: MatchRule| {
        let mut config = MatcherConfig::default();
        config.rule = vec![rule];
        Matcher::new(config)
    };
    assert!(build(MatchRule::new("name", "{san.upn|local}")).is_err());
    assert!(build(MatchRule::new("name", "{san.upn}").domain("corp.example")).is_err());
    assert!(build(MatchRule::new("name", "{san.upn|local}").domain("")).is_err());
    assert!(build(MatchRule::new("name", "{san.upn|local}").domain("a b")).is_err());
    assert!(build(MatchRule::new("name", "{san.upn|local}").pins("p")).is_err()); // no such source
}

#[test]
fn a_value_with_more_than_one_at_is_not_stripped_by_any_rule() {
    // The realm is what follows the last `@`; what is left of two is a name that holds an `@`, which a directory that searches
    // might still find as someone. A rule with a realm, with pins, and the `domain` filter alike get no candidate from it.
    let directory = Stand::default()
        .knows("name", "alice@evil", "alice")
        .knows("name", "corp.example", "corp")
        .knows("name", "evil@corp.example", "evil");
    let lookup = claims(&[("san.upn", &["alice@evil@corp.example"])]);
    let source = std::sync::Arc::new(Source::new(|_| Ok(PinCheck::Holds)));
    for rule in [
        MatchRule::new("name", "{san.upn|local}").domain("corp.example"),
        MatchRule::new("name", "{san.upn|local}").pins("table"),
        MatchRule::new("name", "{san.upn|domain}").pins("table"),
        MatchRule::new("name", "{san.upn|local|lower}").pins("table"),
    ] {
        let mut config = MatcherConfig::default();
        config.rule = vec![rule];
        let matcher = Matcher::builder(config)
            .pin_source("table", source.clone())
            .build()
            .unwrap();
        let result = matcher.resolve(&lookup, &directory).unwrap();
        assert!(matches!(result.result, Match::NotFound));
    }
    assert!(directory.asked().is_empty(), "the directory was not asked");
    // One `@` still strips.
    let mut config = MatcherConfig::default();
    config.rule = vec![realm("name", "{san.upn|local}")];
    let directory = Stand::default().knows("name", "alice", "alice");
    let one = claims(&[("san.upn", &["alice@corp.example"])]);
    let result = Matcher::new(config)
        .unwrap()
        .resolve(&one, &directory)
        .unwrap();
    assert_eq!(found(result.result), "alice");
}

#[test]
fn a_stripped_name_with_pins_needs_no_realm() {
    let source = std::sync::Arc::new(Source::new(|_| Ok(PinCheck::Holds)));
    let mut config = MatcherConfig::default();
    config.rule = vec![MatchRule::new("name", "{san.upn|local}").pins("table")];
    assert!(
        Matcher::builder(config)
            .pin_source("table", source)
            .build()
            .is_ok()
    );
}

#[test]
fn rules_that_cannot_work_are_refused_when_the_matcher_is_built() {
    let build = |by: &str, template: &str| {
        let mut config = MatcherConfig::default();
        config.rule = vec![MatchRule::new(by, template)];
        Matcher::new(config)
    };
    assert!(build("name", "{san.upn}").is_ok());
    for (by, template) in [
        ("login", "{san.upn}"),
        ("name", "constant"),
        ("name", "{san.upn"),
        ("name", "san.upn}"),
        ("name", "{}"),
        ("name", "{san.upn|shout}"),
        ("name", "{San Upn}"),
        ("filter", "uid={san.upn}"),
        ("filter", "((uid={san.upn})"),
        ("filter", "(uid={san.upn}))"),
        ("filter", ""),
    ] {
        assert!(build(by, template).is_err(), "{by} {template}");
    }
    let error = build("name", "{san.upn|shout}").unwrap_err().to_string();
    assert!(
        !error.contains("shout"),
        "an error never quotes the template: {error}"
    );
}

#[test]
fn too_many_candidates_from_several_claims_is_an_error() {
    let many: Vec<String> = (0..5).map(|n| format!("v{n}")).collect();
    let refs: Vec<&str> = many.iter().map(String::as_str).collect();
    let lookup = claims(&[("a", &refs), ("b", &refs)]);
    let result = matcher(&[("name", "{a}-{b}")]).resolve(&lookup, &Stand::default());
    assert!(result.is_err(), "25 candidates is past the bound of 16");
    let fine = claims(&[("a", &refs[..4]), ("b", &refs[..4])]);
    assert!(
        matcher(&[("name", "{a}-{b}")])
            .resolve(&fine, &Stand::default())
            .is_ok()
    );
}

#[test]
fn the_config_reads_defaults_and_refuses_unknown_keys() {
    use coqui_builder::Partial;
    let empty = Partial::<MatcherConfig>::new().build().unwrap();
    assert_eq!(empty.rule.len(), 2, "the default rules");
    let mut partial = Partial::<MatcherConfig>::new();
    assert!(partial.set("nonsense", "x").is_err());
    assert!(Matcher::new(empty).is_ok());
}

// ---- pin sources -------------------------------------------------------------------------

struct Source {
    answer: fn(&Person) -> Result<PinCheck, ProviderError>,
    asked: Mutex<Vec<String>>,
}

impl Source {
    fn new(answer: fn(&Person) -> Result<PinCheck, ProviderError>) -> Self {
        Self {
            answer,
            asked: Mutex::default(),
        }
    }
}

impl PinSource for Source {
    fn check(&self, person: &Person, pins: &PinSet) -> Result<PinCheck, ProviderError> {
        assert_eq!(pins.fingerprint.as_deref(), Some("sha256:aa"));
        self.asked.lock().unwrap().push(person.id.clone());
        (self.answer)(person)
    }
}

fn pinned(rules: Vec<MatchRule>, source: std::sync::Arc<Source>) -> Matcher {
    let mut config = MatcherConfig::default();
    config.rule = rules;
    Matcher::builder(config)
        .pin_source("mine", source)
        .build()
        .unwrap()
}

#[test]
fn a_pin_rule_names_a_candidate_first_and_only_then_asks_that_one_accounts_pins() {
    let lookup = claims(&[
        ("san.upn", &["alice@corp"]),
        ("fingerprint", &["sha256:aa"]),
    ]);
    let directory = Stand::default()
        .knows("name", "alice@corp", "alice")
        .knows("name", "bob@corp", "bob");

    let holds = std::sync::Arc::new(Source::new(|_| Ok(PinCheck::Holds)));
    let rules = vec![MatchRule::new("name", "{san.upn}").pins("mine")];
    let result = pinned(rules.clone(), holds.clone())
        .resolve(&lookup, &directory)
        .unwrap();
    assert_eq!(found(result.result), "alice");
    assert_eq!(
        *holds.asked.lock().unwrap(),
        ["alice"],
        "only the candidate is asked"
    );

    // A pin held by somebody else is no pin for the candidate.
    let absent = std::sync::Arc::new(Source::new(|_| Ok(PinCheck::Absent)));
    let result = pinned(rules.clone(), absent)
        .resolve(&lookup, &directory)
        .unwrap();
    assert!(matches!(result.result, Match::NotFound));

    // A source that refused says why, and the rule finds nobody.
    let refused = std::sync::Arc::new(Source::new(|_| {
        Ok(PinCheck::Refused(
            "the file is writable by its group".to_owned(),
        ))
    }));
    let result = pinned(rules.clone(), refused)
        .resolve(&lookup, &directory)
        .unwrap();
    assert!(matches!(result.result, Match::NotFound));
    assert_eq!(result.notes, ["the file is writable by its group"]);

    // The next rule is still tried after a rule whose pin was absent.
    let absent = std::sync::Arc::new(Source::new(|_| Ok(PinCheck::Absent)));
    let both = vec![
        MatchRule::new("name", "{san.upn}").pins("mine"),
        MatchRule::new("name", "{san.upn}"),
    ];
    let result = pinned(both, absent).resolve(&lookup, &directory).unwrap();
    assert_eq!(found(result.result), "alice");

    // A source that could not be read at all is an error, never a pass.
    let broken = std::sync::Arc::new(Source::new(|_| Err(error::internal("unreadable"))));
    assert!(pinned(rules, broken).resolve(&lookup, &directory).is_err());
}

#[test]
fn a_pin_rule_without_pins_in_the_claims_finds_nobody_and_a_missing_source_is_refused() {
    let directory = Stand::default().knows("name", "alice@corp", "alice");
    let holds = std::sync::Arc::new(Source::new(|_| Ok(PinCheck::Holds)));
    let rules = vec![MatchRule::new("name", "{san.upn}").pins("mine")];
    let no_pins = claims(&[("san.upn", &["alice@corp"])]);
    let result = pinned(rules, holds.clone())
        .resolve(&no_pins, &directory)
        .unwrap();
    assert!(matches!(result.result, Match::NotFound));
    assert!(holds.asked.lock().unwrap().is_empty());

    let mut config = MatcherConfig::default();
    config.rule = vec![MatchRule::new("name", "{san.upn}").pins("nobody")];
    assert!(
        Matcher::new(config).is_err(),
        "a rule names a source nobody gave"
    );
}

// ---- a small LDAP filter reader, to check what the library wrote -------------------------

/// `(attribute=value)` and nothing else: the value is returned as written (escaped).
fn single_assertion(filter: &str) -> (String, String) {
    let inner = filter
        .strip_prefix('(')
        .and_then(|rest| rest.strip_suffix(')'))
        .unwrap_or_else(|| panic!("not one parenthesised assertion: {filter}"));
    assert!(
        !inner.contains('(') && !inner.contains(')'),
        "a raw parenthesis in {filter}"
    );
    let (attribute, value) = inner.split_once('=').expect("an assertion has =");
    assert!(!attribute.contains('=') || attribute.contains(':'));
    (attribute.to_owned(), value.to_owned())
}

/// Reads `\xx` escapes back into text.
fn unescape(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'\\' {
            let hex = std::str::from_utf8(&bytes[at + 1..at + 3]).expect("two hex digits");
            out.push(u8::from_str_radix(hex, 16).expect("hex"));
            at += 3;
        } else {
            assert!(
                !matches!(bytes[at], b'*' | b'(' | b')' | 0),
                "raw metacharacter"
            );
            out.push(bytes[at]);
            at += 1;
        }
    }
    String::from_utf8(out).expect("utf-8")
}
