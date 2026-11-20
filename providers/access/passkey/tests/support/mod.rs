//! A software passkey device: 1Password's authenticator and client, with a store that holds
//! discoverable credentials, so a sign-in with no name typed can be tested.
#![allow(dead_code)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use passkey_authenticator::{
    Authenticator, CredentialStore, DiscoverabilitySupport, MockUserValidationMethod, StoreInfo,
    UserCheck,
};
use passkey_client::{Client, DefaultClientData};
use passkey_crypto::AvailableBackend;
use passkey_types::Passkey;
use passkey_types::ctap2::get_assertion::{
    Options as AssertionOptions, Request as AssertionRequest,
};
use passkey_types::ctap2::make_credential::{
    Options, PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity,
};
use passkey_types::ctap2::{Aaguid, Ctap2Error, StatusCode};
use passkey_types::webauthn::{
    CredentialCreationOptions, CredentialRequestOptions, PublicKeyCredentialDescriptor,
};
use sha2::{Digest, Sha256};
use url::Url;

/// The relying party id and the origin the tests sign in from.
pub const RP_ID: &str = "portal.example";
pub const ORIGIN: &str = "https://portal.example";

/// Every credential the device holds, found by relying party, id and user handle.
#[derive(Clone, Default)]
pub struct Store(Arc<Mutex<Vec<Passkey>>>, Arc<AtomicBool>);

impl Store {
    /// Makes the device find its credentials for any relying party id, as a tampered one would.
    pub fn ignore_rp(&self, ignore: bool) {
        self.1.store(ignore, Ordering::SeqCst);
    }

    /// Sets the signature counter every credential holds (the next assertion says one more).
    pub fn set_counter(&self, counter: u32) {
        for key in self
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter_mut()
        {
            key.counter = Some(counter);
        }
    }

    pub fn len(&self) -> usize {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).len()
    }

    pub fn ids(&self) -> Vec<Vec<u8>> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|key| key.credential_id.to_vec())
            .collect()
    }
}

#[async_trait::async_trait]
impl CredentialStore for Store {
    type PasskeyItem = Passkey;

    async fn find_credentials(
        &self,
        ids: Option<&[PublicKeyCredentialDescriptor]>,
        rp_id: &str,
        user_handle: Option<&[u8]>,
    ) -> Result<Vec<Passkey>, StatusCode> {
        let held = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let found: Vec<Passkey> = held
            .iter()
            .filter(|key| self.1.load(Ordering::SeqCst) || key.rp_id == rp_id)
            .filter(|key| match ids {
                Some(ids) if !ids.is_empty() => ids.iter().any(|id| *id.id == *key.credential_id),
                _ => true,
            })
            .filter(|key| {
                user_handle.is_none_or(|handle| {
                    key.user_handle.as_ref().is_some_and(|own| **own == *handle)
                })
            })
            .cloned()
            .collect();
        if found.is_empty() {
            Err(Ctap2Error::NoCredentials.into())
        } else {
            Ok(found)
        }
    }

    async fn save_credential(
        &mut self,
        cred: Passkey,
        _user: PublicKeyCredentialUserEntity,
        _rp: PublicKeyCredentialRpEntity,
        _options: Options,
    ) -> Result<(), StatusCode> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(cred);
        Ok(())
    }

    async fn update_credential(&mut self, cred: &Passkey) -> Result<(), StatusCode> {
        let mut held = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(own) = held
            .iter_mut()
            .find(|key| key.credential_id == cred.credential_id)
        {
            *own = cred.clone();
        }
        Ok(())
    }

    async fn get_info(&self) -> StoreInfo {
        StoreInfo {
            discoverability: DiscoverabilitySupport::Full,
        }
    }
}

type Soft =
    Client<Store, MockUserValidationMethod, AvailableBackend, public_suffix::PublicSuffixList, ()>;

/// A person's device: it verifies the person whenever the relying party asks.
pub struct Device {
    client: Soft,
    pub store: Store,
}

fn user() -> MockUserValidationMethod {
    let mut user = MockUserValidationMethod::new();
    user.expect_is_verification_enabled()
        .returning(|| Some(true));
    user.expect_is_presence_enabled().returning(|| true);
    user.expect_check_user().returning(|_, _, verification| {
        Ok(UserCheck {
            presence: true,
            verification,
        })
    });
    user
}

impl Device {
    pub fn new() -> Self {
        let store = Store::default();
        let client = Client::new(Authenticator::new(
            Aaguid::new_empty(),
            store.clone(),
            user(),
            AvailableBackend,
        ));
        Self { client, store }
    }

    /// What `navigator.credentials.create` answers (as `toJSON()`), for the options text a
    /// provider made, from `origin`.
    pub async fn register(&mut self, origin: &str, options: &str) -> Result<String, String> {
        let options: CredentialCreationOptions =
            serde_json::from_str(options).map_err(|error| format!("options: {error}"))?;
        let origin = Url::parse(origin).map_err(|error| error.to_string())?;
        let made = self
            .client
            .register(&origin, options, DefaultClientData)
            .await
            .map_err(|error| format!("{error:?}"))?;
        serde_json::to_string(&made).map_err(|error| error.to_string())
    }

    /// What `navigator.credentials.get` answers (as `toJSON()`).
    pub async fn authenticate(&mut self, origin: &str, options: &str) -> Result<String, String> {
        let options: CredentialRequestOptions =
            serde_json::from_str(options).map_err(|error| format!("options: {error}"))?;
        let origin = Url::parse(origin).map_err(|error| error.to_string())?;
        let made = self
            .client
            .authenticate(&origin, options, DefaultClientData)
            .await
            .map_err(|error| format!("{error:?}"))?;
        serde_json::to_string(&made).map_err(|error| error.to_string())
    }
}

/// The client data a browser would write.
pub fn client_data(kind: &str, challenge: &str, origin: &str, cross_origin: bool) -> String {
    format!(
        "{{\"type\":\"{kind}\",\"challenge\":\"{challenge}\",\"origin\":\"{origin}\",\"crossOrigin\":{cross_origin}}}"
    )
}

/// The challenge of sign-in or registration options, unpadded base64url.
pub fn challenge_of(options: &str) -> String {
    let value: serde_json::Value = serde_json::from_str(options).unwrap();
    value["publicKey"]["challenge"].as_str().unwrap().to_owned()
}

impl Device {
    /// An assertion the authenticator signs over `client_data` for `rp_id` whatever the client
    /// data says, as `toJSON()` writes it: what a page that is not the relying party's, or a
    /// browser that cheats, would send. The credentials offered are `allow` (any when empty).
    pub async fn raw_assertion(
        &mut self,
        rp_id: &str,
        client_data: &str,
        allow: &[Vec<u8>],
    ) -> Result<String, String> {
        let b64 = |bytes: &[u8]| data_encoding::BASE64URL_NOPAD.encode(bytes);
        let hash = Sha256::digest(client_data.as_bytes()).to_vec();
        let allow_list = (!allow.is_empty()).then(|| {
            allow
                .iter()
                .map(|id| PublicKeyCredentialDescriptor {
                    ty: passkey_types::webauthn::PublicKeyCredentialType::PublicKey,
                    id: id.clone().into(),
                    transports: None,
                })
                .collect()
        });
        let response = self
            .client
            .authenticator_mut()
            .get_assertion(AssertionRequest {
                rp_id: rp_id.to_owned(),
                client_data_hash: hash.into(),
                allow_list,
                extensions: None,
                options: AssertionOptions { up: true, uv: true },
                pin_auth: None,
                pin_protocol: None,
            })
            .await
            .map_err(|status| format!("{status:?}"))?;
        let id = response
            .credential
            .map(|credential| credential.id.to_vec())
            .ok_or("no credential")?;
        let mut answer = serde_json::json!({
            "id": b64(&id),
            "rawId": b64(&id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64(client_data.as_bytes()),
                "authenticatorData": b64(&response.auth_data.to_vec()),
                "signature": b64(&response.signature),
            },
        });
        if let Some(user) = response.user {
            answer["response"]["userHandle"] = b64(&user.id).into();
        }
        Ok(answer.to_string())
    }
}
