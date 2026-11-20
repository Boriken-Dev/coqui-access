//! The built library, mapped by a registry, serves the four kinds through the C ABI, and a
//! registration and a sign-in cross the instances a host builds, one per kind, through the files
//! they share.

#[path = "../../tests/support/mod.rs"]
mod support;

use std::path::{Path, PathBuf};
use std::process::Command;

use coqui_access::guatiao::library::{Kind, Registry};
use coqui_access::guatiao::{Alloc, Value};
use coqui_access::{
    AccountPut, Accounts, Attempt, Authenticator, ChallengeRequest, Challenger, Directory, Lookup,
    Verdict,
};
use guatiao_serde::Presentation;
use guatiao_serde::text::json;
use support::{Device, ORIGIN, RP_ID};

/// The cdylib this package builds.
///
/// Cargo does not link a cdylib-only library into its own tests, so it is not always built for
/// them: build it here, which does nothing when it is current, and ask cargo where it put the
/// file rather than guess the layout of its output directories.
fn library() -> PathBuf {
    let target = Path::new(env!("CARGO_TARGET_TMPDIR"))
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
        .filter(|message| message["target"]["name"] == "coqui_access_passkey_plugin")
        .flat_map(|message| message["filenames"].as_array().cloned().unwrap_or_default())
        .filter_map(|file| file.as_str().map(PathBuf::from))
        .find(|file| {
            file.extension()
                .is_some_and(|extension| extension == std::env::consts::DLL_EXTENSION)
        })
        .expect("cargo built the library")
}

fn config(text: &str) -> Value {
    json::from_str(text, Alloc::rust(), Presentation::new()).unwrap()
}

fn file_config(directory: &Path) -> Value {
    let path = directory.join("passkeys.toml");
    config(&format!(
        r#"{{ "source": {{ "file": {{ "path": {path:?}, "format": "toml" }} }},
              "rp_id": "{RP_ID}", "origins": ["{ORIGIN}"] }}"#,
        path = path.to_str().unwrap(),
    ))
}

#[tokio::test]
async fn a_registration_and_a_sign_in_cross_the_instances_through_the_files() {
    let mut registry = Registry::new("coqui-access-passkey-test", "0.0.0");
    registry.load_file(&library()).unwrap();
    let provider = registry
        .provider("coqui_access_passkey")
        .expect("the library offers coqui_access_passkey");
    for kind in [
        <dyn Authenticator as Kind>::NAME,
        <dyn Directory as Kind>::NAME,
        <dyn Accounts as Kind>::NAME,
        <dyn Challenger as Kind>::NAME,
    ] {
        assert!(provider.supports(kind), "{kind}");
    }

    let directory = tempfile::tempdir().unwrap();
    let config = file_config(directory.path());
    // One instance per kind, as a host builds them.
    let accounts = provider.instantiate::<dyn Accounts>(&config).unwrap();
    let challenger = provider.instantiate::<dyn Challenger>(&config).unwrap();
    let authenticator = provider.instantiate::<dyn Authenticator>(&config).unwrap();
    let people = provider.instantiate::<dyn Directory>(&config).unwrap();

    let mut device = Device::new();
    let options = accounts
        .put(AccountPut {
            name: "alice".to_owned(),
            ..AccountPut::default()
        })
        .unwrap()
        .secret
        .unwrap();
    let answer = device.register(ORIGIN, &options).await.unwrap();
    // The confirmation goes to another instance than the one that began.
    let confirming = provider.instantiate::<dyn Accounts>(&config).unwrap();
    confirming
        .put(AccountPut {
            name: "alice".to_owned(),
            secret: Some(answer),
            ..AccountPut::default()
        })
        .unwrap();
    assert_eq!(accounts.accounts().unwrap().len(), 1);

    let challenge = challenger
        .challenge(ChallengeRequest {
            peer: Some("192.0.2.7:4000".to_owned()),
            ..ChallengeRequest::default()
        })
        .unwrap();
    let answer = device
        .authenticate(ORIGIN, &challenge.options)
        .await
        .unwrap();
    let verdict = authenticator
        .authenticate(Attempt {
            challenge: Some(challenge.challenge),
            secret: Some(answer),
            ..Attempt::default()
        })
        .unwrap();
    let Verdict::Valid(lookup) = verdict else {
        panic!("{verdict:?}");
    };
    let person = people
        .lookup(Lookup {
            by: lookup.by,
            value: lookup.value,
            claims: None,
        })
        .unwrap()
        .unwrap();
    assert_eq!(person.name, "alice");

    // The files hold public keys and challenges and nothing that signs.
    for name in [
        "passkeys.toml",
        "passkeys.toml.pending",
        "passkeys.toml.ceremonies",
    ] {
        assert!(directory.path().join(name).exists(), "{name}");
    }
}

#[tokio::test]
async fn a_challenge_kept_in_memory_is_not_found_by_another_instance() {
    let mut registry = Registry::new("coqui-access-passkey-test", "0.0.0");
    registry.load_file(&library()).unwrap();
    let provider = registry.provider("coqui_access_passkey").unwrap();
    // No source: every instance has tables of its own, so nothing crosses between them.
    let config = config(&format!(
        r#"{{ "rp_id": "{RP_ID}", "origins": ["{ORIGIN}"] }}"#
    ));
    let accounts = provider.instantiate::<dyn Accounts>(&config).unwrap();
    let challenger = provider.instantiate::<dyn Challenger>(&config).unwrap();
    let authenticator = provider.instantiate::<dyn Authenticator>(&config).unwrap();

    let mut device = Device::new();
    let options = accounts
        .put(AccountPut {
            name: "alice".to_owned(),
            ..AccountPut::default()
        })
        .unwrap()
        .secret
        .unwrap();
    let answer = device.register(ORIGIN, &options).await.unwrap();
    accounts
        .put(AccountPut {
            name: "alice".to_owned(),
            secret: Some(answer),
            ..AccountPut::default()
        })
        .unwrap();
    let challenge = challenger.challenge(ChallengeRequest::default()).unwrap();
    let answer = device
        .authenticate(ORIGIN, &challenge.options)
        .await
        .unwrap();
    let verdict = authenticator
        .authenticate(Attempt {
            challenge: Some(challenge.challenge),
            secret: Some(answer),
            ..Attempt::default()
        })
        .unwrap();
    assert_eq!(verdict, Verdict::Unknown);
}

#[test]
fn a_misspelled_or_unusable_configuration_is_refused_never_read_as_the_default() {
    let mut registry = Registry::new("coqui-access-passkey-test", "0.0.0");
    registry.load_file(&library()).unwrap();
    let provider = registry.provider("coqui_access_passkey").unwrap();
    for bad in [
        // A misspelled key, a missing rp_id, an origin that could never sign anyone in, EdDSA.
        format!(r#"{{ "rp_ids": "{RP_ID}", "origins": ["{ORIGIN}"] }}"#),
        format!(r#"{{ "origins": ["{ORIGIN}"] }}"#),
        format!(r#"{{ "rp_id": "{RP_ID}", "origins": ["https://other.example"] }}"#),
        format!(r#"{{ "rp_id": "{RP_ID}", "origins": ["{ORIGIN}"], "algorithms": ["eddsa"] }}"#),
        format!(
            r#"{{ "rp_id": "{RP_ID}", "origins": ["{ORIGIN}"], "user_verification": "never" }}"#
        ),
        format!(r#"{{ "rp_id": "{RP_ID}" }}"#),
    ] {
        assert!(
            provider.instantiate::<dyn Accounts>(&config(&bad)).is_err(),
            "{bad}"
        );
    }
}
