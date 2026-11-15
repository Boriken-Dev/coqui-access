//! The shared vectors, run against the reference evaluation. `policy.json` goes straight
//! through `SignInRules`; `flows.json` goes through a small stand-in consumer written from the
//! contract, which is also what a real consumer's endpoint has to reproduce.

use std::collections::BTreeSet;

use coqui_access::guatiao::FromValue;
use coqui_access::{Factor, Person, SignInContext, SignInDecision, SignInPolicy};
use coqui_access_signin::vectors::{FLOWS, POLICY};
use coqui_access_signin::{SignInConfig, SignInRules};
use guatiao_builder::Described;
use serde_json::Value as Json;

fn value(json: &Json) -> coqui_access::guatiao::Value {
    guatiao_serde::from_serde(&mut serde_json::Deserializer::from_str(&json.to_string()))
        .expect("the vector is a value")
}

fn rules(config: &Json) -> SignInRules {
    let config = Described::<SignInConfig>::from_value(&value(config))
        .expect("the config reads")
        .0;
    SignInRules::new(config).expect("the config builds")
}

fn names(decision: &SignInDecision) -> Vec<String> {
    decision
        .methods
        .iter()
        .map(|offer| offer.method.clone())
        .collect()
}

fn strings(json: &Json) -> Vec<String> {
    json.as_array()
        .expect("a list")
        .iter()
        .map(|item| item.as_str().expect("a string").to_owned())
        .collect()
}

#[test]
fn every_policy_case_gives_the_methods_and_completeness_it_expects() {
    let document: Json = serde_json::from_str(POLICY).unwrap();
    let cases = document["cases"].as_array().unwrap();
    assert!(cases.len() >= 30, "the vectors cover the evaluation");
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let policy = rules(&case["config"]);
        let context = SignInContext::from_value(&value(&case["context"]))
            .unwrap_or_else(|_| panic!("{name}: the context reads"));
        let decision = policy.decide(context).unwrap();
        let expect = &case["expect"];
        assert_eq!(names(&decision), strings(&expect["methods"]), "{name}");
        assert_eq!(decision.complete, expect["complete"] == true, "{name}");
        if let Some(providers) = expect.get("providers") {
            for (method, listed) in providers.as_object().unwrap() {
                let offer = decision
                    .methods
                    .iter()
                    .find(|offer| &offer.method == method)
                    .unwrap_or_else(|| panic!("{name}: {method} is offered"));
                assert_eq!(offer.providers, strings(listed), "{name}: providers");
            }
        }
    }
}

/// The stand-in consumer: the contract's six points over stand-in authenticators.
struct Consumer {
    policy: SignInRules,
    people: Json,
    /// A sign-in begun: who the first factor named and the steps passed.
    pending: Option<(Person, Vec<Factor>)>,
    /// The steps the last session was opened with.
    session: Option<(Person, Vec<Factor>)>,
    failures: u32,
    /// Failed second-factor attempts, per person id: the contract's counting.
    second_failures: std::collections::BTreeMap<String, u32>,
    recovery_used: bool,
}

/// Failed second-factor attempts the stand-in consumer allows a person.
const MOST_SECOND_FACTOR_FAILURES: u32 = 3;

struct Step {
    result: &'static str,
    methods: Vec<String>,
    calls: usize,
    asked: Vec<String>,
    throttled: bool,
}

impl Consumer {
    fn person(&self, name: &str) -> Option<Person> {
        let found = self.people.get(name)?;
        Some(Person {
            id: found["id"].as_str()?.to_owned(),
            name: found["name"].as_str()?.to_owned(),
            groups: strings(&found["groups"]),
            ..Person::default()
        })
    }

    fn context(
        &self,
        purpose: &str,
        address: Option<&str>,
        of: Option<&(Person, Vec<Factor>)>,
    ) -> SignInContext {
        SignInContext {
            purpose: purpose.to_owned(),
            address: address.map(str::to_owned),
            person: of.map(|(person, _)| person.clone()),
            done: of.map(|(_, done)| done.clone()).unwrap_or_default(),
            ..SignInContext::default()
        }
    }

    fn offer(&self, address: Option<&str>) -> Step {
        let decision = self
            .policy
            .decide(self.context("sign_in", address, self.pending.as_ref()))
            .unwrap();
        Step {
            result: "methods",
            methods: names(&decision),
            calls: 0,
            asked: Vec::new(),
            throttled: false,
        }
    }

    fn resume(&self, address: Option<&str>) -> Step {
        let complete = self.session.as_ref().is_some_and(|session| {
            self.policy
                .decide(self.context("resume", address, Some(session)))
                .unwrap()
                .complete
        });
        Step {
            result: if complete { "signed_in" } else { "failed" },
            methods: Vec::new(),
            calls: 0,
            asked: Vec::new(),
            throttled: false,
        }
    }

    fn present(&mut self, address: Option<&str>, method: &str, name: &str, secret: &str) -> Step {
        let mut step = Step {
            result: "refused_unasked",
            methods: Vec::new(),
            calls: 0,
            asked: Vec::new(),
            throttled: false,
        };
        // Point 2: a presented method is decided again on its own request.
        let decision = self
            .policy
            .decide(self.context("sign_in", address, self.pending.as_ref()))
            .unwrap();
        let Some(offer) = decision.methods.iter().find(|offer| offer.method == method) else {
            return step;
        };
        // Failures of a second factor are counted per person, whatever the address.
        let second = coqui_access::methods::NEEDS_ACCOUNT.contains(&method);
        let who = self.pending.as_ref().map(|(person, _)| person.id.clone());
        if second
            && who.as_ref().is_some_and(|id| {
                self.second_failures.get(id).copied().unwrap_or(0) >= MOST_SECOND_FACTOR_FAILURES
            })
        {
            step.result = "failed";
            step.throttled = true;
            return step;
        }
        // Point 3: only the offered providers are asked, in list order.
        let providers = if offer.providers.is_empty() {
            vec!["local".to_owned()]
        } else {
            offer.providers.clone()
        };
        let mut named: Option<(Person, Factor)> = None;
        for provider in &providers {
            step.calls += 1;
            step.asked.push(provider.clone());
            if let Some(person) = self.authenticate(method, provider, name, secret) {
                let factor = Factor {
                    method: method.to_owned(),
                    provider: Some(provider.clone()),
                    person: Some(person.id.clone()),
                };
                named = Some((person, factor));
                break;
            }
        }
        // Point 5: the next factor must name the same person.
        let mismatch = |(person, _): &(Person, Factor)| {
            self.pending
                .as_ref()
                .is_some_and(|(first, _)| first.id != person.id)
        };
        let Some((person, factor)) = named.filter(|found| !mismatch(found)) else {
            self.failures += 1;
            if let (true, Some(id)) = (second, who) {
                *self.second_failures.entry(id).or_insert(0) += 1;
            }
            step.result = "failed";
            step.throttled = true;
            return step;
        };
        if second {
            self.second_failures.remove(&person.id);
        }
        if method == "recovery_code" {
            self.recovery_used = true;
        }
        let mut done = self
            .pending
            .take()
            .map(|(_, done)| done)
            .unwrap_or_default();
        done.push(factor);
        // Point 4: a valid factor resolves to a person, and the policy decides again.
        let after = self
            .policy
            .decide(self.context("sign_in", address, Some(&(person.clone(), done.clone()))))
            .unwrap();
        if after.complete {
            self.session = Some((person, done));
            step.result = "signed_in";
        } else if !after.methods.is_empty() {
            self.pending = Some((person, done));
            step.result = "next";
            step.methods = names(&after);
        } else {
            self.failures += 1;
            step.result = "failed";
            step.throttled = true;
        }
        step
    }

    /// The stand-in authenticators.
    fn authenticate(
        &self,
        method: &str,
        provider: &str,
        name: &str,
        secret: &str,
    ) -> Option<Person> {
        match method {
            "password" if provider == "local" && name == "alice" && secret == "pw" => {
                self.person("alice")
            }
            "certificate" if name == "alice" || name == "bob" => self.person(name),
            "recovery_code" if secret == "RECOVER-1" && !self.recovery_used => {
                let (first, _) = self.pending.as_ref()?;
                (first.id == name).then(|| first.clone())
            }
            "totp" if secret == "123456" => {
                let (first, _) = self.pending.as_ref()?;
                (first.id == name).then(|| first.clone())
            }
            _ => None,
        }
    }
}

#[test]
fn every_flow_goes_as_the_stand_in_consumer_of_the_contract_does() {
    let document: Json = serde_json::from_str(FLOWS).unwrap();
    let flows = document["flows"].as_array().unwrap();
    let points: BTreeSet<i64> = flows
        .iter()
        .map(|flow| flow["point"].as_i64().unwrap())
        .collect();
    assert_eq!(
        points,
        BTreeSet::from([1, 2, 3, 4, 5, 6]),
        "a flow for each point of the contract"
    );
    for flow in flows {
        let name = flow["name"].as_str().unwrap();
        let mut consumer = Consumer {
            policy: rules(&flow["config"]),
            people: document["stand_ins"]["people"].clone(),
            pending: None,
            session: None,
            failures: 0,
            second_failures: std::collections::BTreeMap::new(),
            recovery_used: false,
        };
        for (index, step) in flow["steps"].as_array().unwrap().iter().enumerate() {
            let address = step.get("address").and_then(Json::as_str);
            let text = |key: &str| step.get(key).and_then(Json::as_str).unwrap_or_default();
            let done = match step["action"].as_str().unwrap() {
                "offer" => consumer.offer(address),
                "resume" => consumer.resume(address),
                "present" => {
                    consumer.present(address, text("method"), text("name"), text("secret"))
                }
                other => panic!("{name}: an action {other}"),
            };
            let expect = &step["expect"];
            let at = format!("{name}, step {index}");
            assert_eq!(done.result, expect["result"].as_str().unwrap(), "{at}");
            assert_eq!(done.calls as i64, expect["authenticator_calls"], "{at}");
            assert_eq!(done.throttled, expect["throttled"] == true, "{at}");
            if let Some(methods) = expect.get("methods") {
                assert_eq!(done.methods, strings(methods), "{at}");
            }
            if let Some(asked) = expect.get("asked") {
                assert_eq!(done.asked, strings(asked), "{at}");
            }
        }
    }
}
