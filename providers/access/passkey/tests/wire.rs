//! Whether 1Password's authenticator and client output reads in webauthn-rs-core, measured
//! with the library alone.

mod support;

use std::time::Duration;

use support::Device;
use url::Url;
use webauthn_rs_core::WebauthnCore;
use webauthn_rs_core::proto::{
    CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse, UserVerificationPolicy,
};

const ORIGIN: &str = "https://portal.example";

fn core() -> WebauthnCore {
    WebauthnCore::new_unsafe_experts_only(
        "Portal",
        "portal.example",
        vec![Url::parse(ORIGIN).unwrap()],
        Duration::from_secs(300),
        None,
        None,
    )
}

#[tokio::test]
async fn passkey_rs_output_reads_in_webauthn_rs_core_both_ways() {
    let core = core();
    let mut device = Device::new();

    let builder = core
        .new_challenge_register_builder(&[7; 16], "alice", "alice")
        .unwrap()
        .require_resident_key(true)
        .user_verification_policy(UserVerificationPolicy::Required);
    let (creation, state): (CreationChallengeResponse, _) =
        core.generate_challenge_register(builder).unwrap();
    let options = serde_json::to_string(&creation).unwrap();
    let made = device.register(ORIGIN, &options).await.unwrap();
    let register: RegisterPublicKeyCredential = serde_json::from_str(&made).unwrap();
    let credential = core.register_credential(&register, &state, None).unwrap();
    assert!(credential.user_verified);

    // Discoverable: an empty allow list, the credential chosen by the device.
    let builder = core
        .new_challenge_authenticate_builder(Vec::new(), Some(UserVerificationPolicy::Required))
        .unwrap();
    let (request, state): (RequestChallengeResponse, _) =
        core.generate_challenge_authenticate(builder).unwrap();
    let options = serde_json::to_string(&request).unwrap();
    let signed = device.authenticate(ORIGIN, &options).await.unwrap();
    let rsp: PublicKeyCredential = serde_json::from_str(&signed).unwrap();
    assert_eq!(rsp.get_user_unique_id(), Some(&[7u8; 16][..]));
    let result = core
        .authenticate_single_credential(&rsp, &state, &credential)
        .unwrap();
    assert!(result.user_verified());
}
