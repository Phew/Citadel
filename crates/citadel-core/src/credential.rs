//! Client-side verification of member credentials against the KT log (INV-4).
//!
//! Every member of a group a client joins is verified before the group is
//! accepted: the member's basic-credential bytes must deserialize to a
//! `citadel-proto` [`DeviceCredential`], the credential's identity signature
//! must verify under its `identity_pubkey`, AND that identity must have a
//! verified KT inclusion proof. The KT proof source (auth-service `GET
//! /v1/kt/proof`, verified with `kt-log`) is injected via [`IdentityVerifier`]
//! so this logic is testable without a live log and the harness can supply the
//! real verifier for the adversarial suite.

use citadel_proto::credential::DeviceCredential;
use citadel_proto::ids::AccountId;
use citadel_proto::IdentityPublicKey;
use ed25519_dalek::{Signature, VerifyingKey};

/// Verifies that an account identity key is the one the KT log attests (INV-4).
/// The real implementation fetches the inclusion proof for the account's KT leaf
/// and verifies it against a pinned signed tree head; a test double can trust a
/// fixed set.
pub trait IdentityVerifier {
    /// True iff `identity_pubkey` is exactly the key the KT log binds to
    /// `account_id` (verified inclusion proof against a trusted tree head).
    fn is_kt_attested(&self, account_id: AccountId, identity_pubkey: &IdentityPublicKey) -> bool;
}

/// Why a member credential was rejected. Any failure aborts the join (INV-4).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CredentialError {
    #[error("credential bytes are not a valid DeviceCredential")]
    Malformed,
    #[error("identity signature does not verify under the credential's identity key")]
    BadIdentitySignature,
    #[error("identity key is not attested by the KT log for this account")]
    NotKtAttested,
}

/// Verify one member's credential bytes (the contents of its MLS basic
/// credential). Returns the parsed [`DeviceCredential`] only if it is
/// well-formed, self-consistent (identity signature valid), and KT-attested.
pub fn verify_member_credential(
    credential_bytes: &[u8],
    verifier: &impl IdentityVerifier,
) -> Result<DeviceCredential, CredentialError> {
    let cred: DeviceCredential =
        serde_json::from_slice(credential_bytes).map_err(|_| CredentialError::Malformed)?;

    // (1) The account identity key signed this device binding.
    let vk = VerifyingKey::from_bytes(&cred.tbs.identity_pubkey.0)
        .map_err(|_| CredentialError::BadIdentitySignature)?;
    let sig = Signature::from_bytes(&cred.signature.0);
    vk.verify_strict(&cred.tbs.signing_input(), &sig)
        .map_err(|_| CredentialError::BadIdentitySignature)?;

    // (2) That identity key is the one the KT log attests for the account.
    if !verifier.is_kt_attested(cred.tbs.account_id, &cred.tbs.identity_pubkey) {
        return Err(CredentialError::NotKtAttested);
    }
    Ok(cred)
}

#[cfg(test)]
mod tests {
    use super::*;
    use citadel_proto::credential::{DeviceCredentialTbs, DevicePublicKey, Signature as ProtoSig};
    use citadel_proto::ids::DeviceId;
    use ed25519_dalek::{Signer, SigningKey};

    /// Test verifier trusting exactly one (account, identity) pair.
    struct TrustOne(AccountId, IdentityPublicKey);
    impl IdentityVerifier for TrustOne {
        fn is_kt_attested(&self, a: AccountId, k: &IdentityPublicKey) -> bool {
            a == self.0 && k.0 == self.1 .0
        }
    }

    fn signed_credential(
        identity: &SigningKey,
    ) -> (DeviceCredential, AccountId, IdentityPublicKey) {
        let account_id = AccountId::new();
        let id_pub = IdentityPublicKey(identity.verifying_key().to_bytes());
        let tbs = DeviceCredentialTbs {
            account_id,
            device_id: DeviceId::new(),
            identity_pubkey: id_pub,
            device_pubkey: DevicePublicKey([9u8; 32]),
            issued_at: 1_700_000_000,
        };
        let sig = identity.sign(&tbs.signing_input());
        let cred = DeviceCredential {
            tbs,
            signature: ProtoSig(sig.to_bytes()),
        };
        (cred, account_id, id_pub)
    }

    #[test]
    fn accepts_valid_kt_attested_credential() {
        let id = SigningKey::from_bytes(&[3u8; 32]);
        let (cred, acct, idpub) = signed_credential(&id);
        let bytes = serde_json::to_vec(&cred).unwrap();
        let ok = verify_member_credential(&bytes, &TrustOne(acct, idpub));
        assert_eq!(ok.unwrap().tbs.account_id, acct);
    }

    #[test]
    fn rejects_non_kt_attested_identity() {
        // Valid signature, but the verifier does not attest this identity.
        let id = SigningKey::from_bytes(&[4u8; 32]);
        let (cred, _acct, _idpub) = signed_credential(&id);
        let bytes = serde_json::to_vec(&cred).unwrap();
        let other = AccountId::new();
        let err = verify_member_credential(&bytes, &TrustOne(other, IdentityPublicKey([0u8; 32])));
        assert_eq!(err, Err(CredentialError::NotKtAttested));
    }

    #[test]
    fn rejects_forged_identity_signature() {
        let id = SigningKey::from_bytes(&[5u8; 32]);
        let (mut cred, acct, idpub) = signed_credential(&id);
        cred.signature = ProtoSig([0u8; 64]); // not a valid signature
        let bytes = serde_json::to_vec(&cred).unwrap();
        let err = verify_member_credential(&bytes, &TrustOne(acct, idpub));
        assert_eq!(err, Err(CredentialError::BadIdentitySignature));
    }
}
