//! Sign-in: the challenge a consumer asks for and the signed answer it presents.

use coqui_access::CredentialInfo;
use webauthn_rs_core::proto::Credential;

use crate::records::StoredCredential;

/// A passkey as [`AccountInfo::credentials`](coqui_access::AccountInfo::credentials) lists it.
/// A passkey is synced when its authenticator says it may exist on several devices.
pub(crate) fn info(stored: &StoredCredential) -> CredentialInfo {
    CredentialInfo {
        id: stored.id.clone(),
        label: stored.label.clone(),
        made_unix: Some(stored.made_unix),
        used_unix: stored.used_unix,
        synced: serde_json::from_str::<Credential>(&stored.key)
            .ok()
            .map(|credential| credential.backup_eligible),
        disabled: Some(stored.disabled),
    }
}
