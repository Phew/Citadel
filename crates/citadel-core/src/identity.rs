//! Bridge the M1 device identity into OpenMLS.
//!
//! A device's Ed25519 signing key is generated on-device, held in the OS
//! keychain, and never serialized to the network under INV-2. It is the MLS leaf
//! signature key. The MLS **basic credential** contents are the serialized `citadel-proto`
//! [`DeviceCredential`] from M1, so a joiner can extract a member's credential
//! and verify it against the KT log (INV-4, see [`crate::credential`]).

use crate::credential::{verify_device_credential_signature, CredentialError};
use crate::crypto::Provider;
use citadel_proto::credential::DeviceCredential;
use ed25519_dalek::{Signer as DalekSigner, SigningKey};
use openmls::prelude::*;
use openmls_traits::{
    signatures::{Signer as OpenMlsSigner, SignerError},
    types::SignatureScheme,
};
use zeroize::Zeroizing;

/// Errors bridging a device identity into MLS.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("device signing seed does not derive the supplied public key")]
    SuppliedPublicKeyMismatch,
    #[error("device signing key does not match the credential's device public key")]
    CredentialPublicKeyMismatch,
    #[error("device credential is invalid: {0}")]
    Credential(#[from] CredentialError),
    #[error("serializing the device credential failed: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("creating the MLS KeyPackage failed: {0}")]
    KeyPackage(#[from] KeyPackageNewError),
}

pub(crate) struct DeviceSigner {
    signing_key: SigningKey,
}

impl OpenMlsSigner for DeviceSigner {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        Ok(self.signing_key.sign(payload).to_bytes().to_vec())
    }

    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

/// This device's MLS identity: the signer plus the credential it presents.
pub struct DeviceIdentity {
    /// MLS leaf signer (the device Ed25519 key). Passed explicitly to every
    /// group operation; never leaves the process (INV-2).
    pub(crate) signer: DeviceSigner,
    /// Credential + public key presented in KeyPackages and leaves.
    pub(crate) credential_with_key: CredentialWithKey,
    /// The M1 credential whose serialization is the credential identity bytes.
    pub device_credential: DeviceCredential,
}

impl DeviceIdentity {
    /// Build from the M1 device credential and the device's Ed25519 key. The
    /// seed is transferred in a zeroizing owner, and its derived public key
    /// must match both the supplied public key and the credential binding.
    pub fn from_parts(
        device_credential: DeviceCredential,
        signing_key: Zeroizing<[u8; 32]>,
        public_key: [u8; 32],
    ) -> Result<Self, IdentityError> {
        let signing_key = SigningKey::from_bytes(&signing_key);
        let derived_public_key = signing_key.verifying_key().to_bytes();
        if derived_public_key != public_key {
            return Err(IdentityError::SuppliedPublicKeyMismatch);
        }
        if derived_public_key != device_credential.tbs.device_pubkey.0 {
            return Err(IdentityError::CredentialPublicKeyMismatch);
        }
        verify_device_credential_signature(&device_credential)?;
        let signer = DeviceSigner { signing_key };

        let identity_bytes = serde_json::to_vec(&device_credential)?;
        let credential = BasicCredential::new(identity_bytes);
        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: derived_public_key.as_slice().into(),
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
    pub fn new_key_package(&self, provider: &Provider) -> Result<KeyPackage, IdentityError> {
        let bundle = KeyPackage::builder().build(
            crate::crypto::CIPHERSUITE,
            provider,
            &self.signer,
            self.credential_with_key.clone(),
        )?;
        Ok(bundle.key_package().clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::make_identity;

    #[test]
    fn rejects_signing_seed_that_does_not_derive_supplied_public_key() {
        let existing = make_identity();
        let result = DeviceIdentity::from_parts(
            existing.identity.device_credential,
            Zeroizing::new([0x31; 32]),
            [0x42; 32],
        );
        let Err(error) = result else {
            panic!("inconsistent raw keypair must fail at construction");
        };
        assert!(matches!(error, IdentityError::SuppliedPublicKeyMismatch));
    }

    #[test]
    fn rejects_signing_key_not_bound_by_device_credential() {
        let existing = make_identity();
        let signing_key = SigningKey::from_bytes(&[0x53; 32]);
        let result = DeviceIdentity::from_parts(
            existing.identity.device_credential,
            Zeroizing::new(signing_key.to_bytes()),
            signing_key.verifying_key().to_bytes(),
        );
        let Err(error) = result else {
            panic!("credential must bind the derived device public key");
        };
        assert!(matches!(error, IdentityError::CredentialPublicKeyMismatch));
    }

    #[test]
    fn rejects_forged_device_credential_signature() {
        let existing = make_identity();
        let signing_seed = existing.identity.signer.signing_key.to_bytes();
        let public_key = existing
            .identity
            .signer
            .signing_key
            .verifying_key()
            .to_bytes();
        let mut credential = existing.identity.device_credential;
        credential.signature = citadel_proto::credential::Signature([0; 64]);

        let result =
            DeviceIdentity::from_parts(credential, Zeroizing::new(signing_seed), public_key);
        let Err(error) = result else {
            panic!("forged device credential signature must fail at construction");
        };
        assert!(matches!(
            error,
            IdentityError::Credential(CredentialError::BadIdentitySignature)
        ));
    }
}
