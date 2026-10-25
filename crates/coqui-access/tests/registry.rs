//! A provider of every kind registers with a Guatiao registry and is served through it, so
//! the kinds, models and `describe` defaults work across the plugin boundary.

use std::collections::BTreeMap;

use coqui_access::guatiao::library::{ProviderError, Registry};
use coqui_access::guatiao::{Provider, Value};
use coqui_access::{
    AccountInfo, AccountPut, Accounts, Attempt, Authenticator, AuthorizationDecision,
    AuthorizationRequest, Authorizer, Description, Directory, Lookup, Person, PutOutcome, Verdict,
    Waiting, error, takes,
};

#[derive(Default, Provider)]
#[provider(Authenticator, Directory, Authorizer, Accounts)]
struct Mock;

impl Authenticator for Mock {
    fn authenticate(&self, attempt: Attempt) -> Result<Verdict, ProviderError> {
        let proxied = attempt
            .headers
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case("x-user") && value == "alice");
        Ok(if proxied || attempt.secret.as_deref() == Some("secret") {
            Verdict::Valid(Lookup {
                by: "name".to_owned(),
                value: "alice".to_owned(),
            })
        } else {
            Verdict::Invalid
        })
    }

    fn describe(&self) -> Result<Description, ProviderError> {
        Ok(Description {
            name: Some("Mock".to_owned()),
            takes: Some(takes::PASSWORD.to_owned()),
        })
    }
}

impl Directory for Mock {
    fn lookup(&self, lookup: Lookup) -> Result<Option<Person>, ProviderError> {
        Ok((lookup.value == "alice").then(|| Person {
            id: "person-alice".to_owned(),
            name: "alice".to_owned(),
            groups: vec!["staff".to_owned()],
            attributes: BTreeMap::from([("team".to_owned(), Value::default())]),
            ..Person::default()
        }))
    }
}

impl Authorizer for Mock {
    fn authorize(
        &self,
        request: AuthorizationRequest,
    ) -> Result<AuthorizationDecision, ProviderError> {
        Ok(AuthorizationDecision {
            allowed: request.action == "document.read"
                && request.person.groups.iter().any(|group| group == "staff"),
            limits: BTreeMap::new(),
        })
    }
}

impl Accounts for Mock {
    fn accounts(&self) -> Result<Vec<AccountInfo>, ProviderError> {
        Ok(vec![AccountInfo {
            id: "person-alice".to_owned(),
            name: "alice".to_owned(),
            ..AccountInfo::default()
        }])
    }

    fn put(&self, account: AccountPut) -> Result<PutOutcome, ProviderError> {
        Ok(PutOutcome {
            secret: account.secret.map(|_| "made".to_owned()),
        })
    }

    fn remove(&self, _name: String) -> Result<(), ProviderError> {
        Err(error::not_found("there is no such account"))
    }
}

coqui_access::guatiao::local_providers!(
    id = "coqui-access-test-providers",
    version = "0.0.0",
    providers = [Mock]
);

fn registry() -> Registry {
    let mut registry = Registry::new("coqui-access-test", "0.0.0");
    registry
        .register_local("coqui-access-test-providers", library)
        .unwrap();
    registry
}

#[test]
fn one_provider_serves_all_four_kinds_through_a_registry() {
    use coqui_access::guatiao::library::Kind;
    let registry = registry();
    for name in [
        <dyn Authenticator>::NAME,
        <dyn Directory>::NAME,
        <dyn Authorizer>::NAME,
        <dyn Accounts>::NAME,
    ] {
        assert_eq!(registry.providers(name).count(), 1, "{name}");
    }
    let id = registry
        .providers(<dyn Authenticator>::NAME)
        .next()
        .unwrap()
        .id()
        .to_string();

    let authenticator = registry
        .offer::<dyn Authenticator>(&id)
        .unwrap()
        .unwrap()
        .boxed()
        .unwrap();
    let directory = registry
        .offer::<dyn Directory>(&id)
        .unwrap()
        .unwrap()
        .boxed()
        .unwrap();
    let authorizer = registry
        .offer::<dyn Authorizer>(&id)
        .unwrap()
        .unwrap()
        .boxed()
        .unwrap();
    let accounts = registry
        .offer::<dyn Accounts>(&id)
        .unwrap()
        .unwrap()
        .boxed()
        .unwrap();

    // Headers cross as ordered pairs, a repeated name staying repeated.
    let Verdict::Valid(lookup) = authenticator
        .authenticate(Attempt {
            headers: vec![
                ("X-Other".to_owned(), "1".to_owned()),
                ("X-User".to_owned(), "alice".to_owned()),
            ],
            ..Attempt::default()
        })
        .unwrap()
    else {
        panic!("the header should authenticate");
    };
    let person = directory.lookup(lookup).unwrap().unwrap();
    assert_eq!(person.id, "person-alice");
    assert!(
        authorizer
            .authorize(AuthorizationRequest {
                person: person.clone(),
                action: "document.read".to_owned(),
                resource: "*".to_owned(),
            })
            .unwrap()
            .allowed
    );
    assert!(
        !authorizer
            .authorize(AuthorizationRequest {
                person,
                action: "document.write".to_owned(),
                resource: "*".to_owned(),
            })
            .unwrap()
            .allowed
    );
    assert_eq!(
        authenticator.describe().unwrap().takes.as_deref(),
        Some("password")
    );
    // `describe` has a default body: a directory that does not write one says nothing.
    assert_eq!(directory.describe().unwrap(), Description::default());
    assert_eq!(accounts.accounts().unwrap()[0].name, "alice");
    assert!(accounts.waiting().unwrap().is_empty());
    assert_eq!(
        accounts
            .put(AccountPut {
                secret: Some("x".to_owned()),
                ..AccountPut::default()
            })
            .unwrap()
            .secret
            .as_deref(),
        Some("made")
    );
    assert!(accounts.remove("alice".to_owned()).is_err());
    let _: Option<Waiting> = None;
}
