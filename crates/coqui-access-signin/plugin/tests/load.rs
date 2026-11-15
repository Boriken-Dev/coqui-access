//! The built library, mapped by a registry, serves `coqui_signin_rules` through the C ABI.

use std::path::PathBuf;

use coqui_access::guatiao::Alloc;
use coqui_access::guatiao::library::{Kind, Registry};
use coqui_access::{SignInContext, SignInPolicy};
use guatiao_serde::Presentation;
use guatiao_serde::text::json;

/// The cdylib this package builds, beside the test binary's own directory.
fn library() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let directory = exe.parent().unwrap().parent().unwrap();
    directory.join(format!(
        "{}coqui_access_signin_plugin{}",
        std::env::consts::DLL_PREFIX,
        std::env::consts::DLL_SUFFIX
    ))
}

#[test]
fn a_registry_maps_the_library_and_the_provider_decides_through_it() {
    let mut registry = Registry::new("coqui-access-signin-test", "0.0.0");
    let path = library();
    assert!(path.exists(), "the plugin is built beside the tests");
    registry.load_file(&path).unwrap();
    let provider = registry
        .provider("coqui_signin_rules")
        .expect("the library offers coqui_signin_rules");
    assert!(provider.supports(<dyn SignInPolicy as Kind>::NAME));

    let config = json::from_str(
        r#"{ "rule": [
            { "networks": ["10.0.0.0/8"], "allow": [["password"], ["certificate"]] },
            { "allow": [["certificate"]] } ] }"#,
        Alloc::rust(),
        Presentation::new(),
    )
    .unwrap();
    let policy = provider.instantiate::<dyn SignInPolicy>(&config).unwrap();
    let ask = |address: &str| {
        policy
            .decide(SignInContext {
                purpose: "sign_in".to_owned(),
                address: Some(address.to_owned()),
                ..SignInContext::default()
            })
            .unwrap()
            .methods
            .into_iter()
            .map(|offer| offer.method)
            .collect::<Vec<_>>()
    };
    assert_eq!(ask("10.1.2.3"), ["password", "certificate"]);
    assert_eq!(ask("203.0.113.7"), ["certificate"]);

    // A misspelled key is refused by the schema, never read as "no rule".
    let bad = json::from_str(r#"{ "rules": [] }"#, Alloc::rust(), Presentation::new()).unwrap();
    assert!(provider.instantiate::<dyn SignInPolicy>(&bad).is_err());
}
