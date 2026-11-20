//! The built library, mapped by a registry, serves `coqui_signin_rules` through the C ABI.

use std::path::PathBuf;
use std::process::Command;

use coqui_access::guatiao::Alloc;
use coqui_access::guatiao::library::{Kind, Registry};
use coqui_access::{SignInContext, SignInPolicy};
use guatiao_serde::Presentation;
use guatiao_serde::text::json;

/// The cdylib this package builds.
///
/// Cargo does not link a cdylib-only library into its own tests, so it is not always built for
/// them: build it here, which does nothing when it is current, and ask cargo where it put the
/// file rather than guess the layout of its output directories.
fn library() -> PathBuf {
    let target = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .parent()
        .expect("the target directory holds tmp")
        .to_path_buf();
    let mut build = Command::new(env!("CARGO"));
    build
        .args(["build", "--message-format=json", "--manifest-path"])
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
        .arg("--target-dir")
        .arg(&target);
    if !cfg!(debug_assertions) {
        build.arg("--release");
    }
    let output = build.output().expect("cargo runs");
    assert!(output.status.success(), "the plugin builds");
    String::from_utf8(output.stdout)
        .expect("cargo writes JSON")
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|message| message["reason"] == "compiler-artifact")
        .filter(|message| message["target"]["name"] == "coqui_access_signin_plugin")
        .flat_map(|message| message["filenames"].as_array().cloned().unwrap_or_default())
        .filter_map(|file| file.as_str().map(PathBuf::from))
        .find(|file| {
            file.extension()
                .is_some_and(|extension| extension == std::env::consts::DLL_EXTENSION)
        })
        .expect("cargo built the library")
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
