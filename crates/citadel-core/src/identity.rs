//! Bridge the M1 device identity into OpenMLS.
//!
//! A device's Ed25519 signing key (generated on-device, held in the OS keychain,
//! never serialized to the network — INV-2) is the MLS leaf signature key. The
//! MLS **basic credential** contents are the serialized `citadel-proto`
//! [`DeviceCredential`] from M1, so a joiner can extract a member's credential
//! and verify it against the KT log (INV-4, see [`crate::credential`]).

use crate::crypto::Provider;
use citadel_proto::credential::DeviceCredential;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::types::SignatureScheme;

/// Errors bridging a device identity into MLS.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("device signing key does not match the credential's device_pubkey")]
    KeyMismatch,
    #[error("serializing the device credential failed: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("storing the signature key failed")]
    Store,
}

/// This device's MLS identity: the signer plus the credential it presents.
pub struct DeviceIdentity {
    /// MLS leaf signer (the device Ed25519 key). Passed explicitly to every
    /// group operation; never leaves the process (INV-2).
    pub signer: SignatureKeyPair,
    /// Credential + public key presented in KeyPackages and leaves.
    pub credential_with_key: CredentialWithKey,
    /// The M1 credential whose serialization is the credential identity bytes.
    pub device_credential: DeviceCredential,
}

impl DeviceIdentity {
    /// Build from the M1 device credential and the device's raw Ed25519 key
    /// (32-byte seed + 32-byte public). The public key must match the
    /// credential's `device_pubkey` (a key the enroller does not hold is inert).
    pub fn from_parts(
        provider: &Provider,
        device_credential: DeviceCredential,
        signing_key: [u8; 32],
        public_key: [u8; 32],
    ) -> Result<Self, IdentityError> {
        if public_key != device_credential.tbs.device_pubkey.0 {
            return Err(IdentityError::KeyMismatch);
        }
        let signer = SignatureKeyPair::from_raw(
            SignatureScheme::ED25519,
            signing_key.to_vec(),
            public_key.to_vec(),
        );
        signer
            .store(provider.storage())
            .map_err(|_| IdentityError::Store)?;

        let identity_bytes = serde_json::to_vec(&device_credential)?;
        let credential = BasicCredential::new(identity_bytes);
        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: signer.public().into(),
        };
        Ok(Self {
            signer,
            credential_with_key,
            device_credential,
        })
    }

    /// Generate one KeyPackage bound to this identity for the one-time pool
    /// (F1 step 4 / F2 target fetch). The private init/encryption keys are stored
    /// in the provider; only the public `KeyPackage` is published.
    pub fn new_key_package(&self, provider: &Provider) -> KeyPackage {
        KeyPackage::builder()
            .build(
                crate::crypto::CIPHERSUITE,
                provider,
                &self.signer,
                self.credential_with_key.clone(),
            )
            .expect("key package generation")
            .key_package()
            .clone()
    }
}
