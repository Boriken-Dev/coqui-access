//! A software passkey device: 1Password's authenticator and client, with a store that holds
//! discoverable credentials, so a sign-in with no name typed can be tested.
#![allow(dead_code)]

use std::sync::{Arc, Mutex, PoisonError};

use passkey_authenticator::{
    Authenticator, CredentialStore, DiscoverabilitySupport, MockUserValidationMethod, StoreInfo,
    UserCheck,
};
use passkey_client::{Client, DefaultClientData};
use passkey_crypto::AvailableBackend;
use passkey_types::Passkey;
use passkey_types::ctap2::make_credential::{
    Options, PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity,
};
use passkey_types::ctap2::{Aaguid, Ctap2Error, StatusCode};
use passkey_types::webauthn::{
    CredentialCreationOptions, CredentialRequestOptions, PublicKeyCredentialDescriptor,
};
use url::Url;

/// The relying party id and the origin the tests sign in from.
pub const RP_ID: &str = "portal.example";
pub const ORIGIN: &str = "https://portal.example";

/// Every credential the device holds, found by relying party, id and user handle.
#[derive(Clone, Default)]
pub struct Store(Arc<Mutex<Vec<Passkey>>>);

impl Store {
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
            .filter(|key| key.rp_id == rp_id)
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
