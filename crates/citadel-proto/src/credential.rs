//! Credential formats binding device keys to account identity keys (F1).
//!
//! v1 uses MLS basic credentials whose contents are the serialized
//! [`DeviceCredential`] below. Verification is client-side against the KT log
//! (INV-4): a credential is trusted only if its identity key has a verified
//! KT inclusion proof AND its signature verifies over [`DeviceCredential::signing_input`].
//!
//! Signing inputs are deterministic, domain-separated byte encodings —
//! length-prefixed fields, big-endian lengths. This is serialization, not a
//! crypto primitive (INV-10). Golden-byte tests below pin the encoding;
//! changing it is a wire break requiring an ADR.

use crate::bytes::{b64fixed32, b64fixed64};
use crate::ids::{AccountId, DeviceId};
use serde::{Deserialize, Serialize};

/// Domain separation tag for device credential signatures.
/// The version lives in the tag: bumping the format means a new tag.
pub const DEVICE_CREDENTIAL_DOMAIN: &str = "citadel/v1/device-credential";

/// Domain separation tag for device-enrollment endorsements
/// (an existing device signing a new device's credential, F1 additional-device flow).
pub const DEVICE_ENDORSEMENT_DOMAIN: &str = "citadel/v1/device-endorsement";

/// Ed25519 public key of an account identity. Appended to the KT log at registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IdentityPublicKey(#[serde(with = "b64fixed32")] pub [u8; 32]);

/// Ed25519 public key of an enrolled device (MLS leaf signature key binding).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DevicePublicKey(#[serde(with = "b64fixed32")] pub [u8; 32]);

/// Detached Ed25519 signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Signature(#[serde(with = "b64fixed64")] pub [u8; 64]);

/// The signed portion of a device credential: binds `device_pubkey` to the
/// account's `identity_pubkey`. Signed by the account identity key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCredentialTbs {
    pub account_id: AccountId,
    pub device_id: DeviceId,
    pub identity_pubkey: IdentityPublicKey,
    pub device_pubkey: DevicePublicKey,
    /// Unix seconds. Informational; expiry/revocation authority is the
    /// devices table plus MLS Remove, not this timestamp.
    pub issued_at: i64,
}

impl DeviceCredentialTbs {
    /// Deterministic bytes the identity key signs.
    ///
    /// Layout: domain tag (u16-BE length || bytes), then account_id (16B UUID),
    /// device_id (16B UUID), identity_pubkey (32B), device_pubkey (32B),
    /// issued_at (i64-BE). All fields fixed-width, so no field-level length
    /// prefixes are needed beyond the tag.
    pub fn signing_input(&self) -> Vec<u8> {
        let tag = DEVICE_CREDENTIAL_DOMAIN.as_bytes();
        let mut out = Vec::with_capacity(2 + tag.len() + 16 + 16 + 32 + 32 + 8);
        out.extend_from_slice(&(tag.len() as u16).to_be_bytes());
        out.extend_from_slice(tag);
        out.extend_from_slice(self.account_id.as_uuid().as_bytes());
        out.extend_from_slice(self.device_id.as_uuid().as_bytes());
        out.extend_from_slice(&self.identity_pubkey.0);
        out.extend_from_slice(&self.device_pubkey.0);
        out.extend_from_slice(&self.issued_at.to_be_bytes());
        out
    }
}

/// A complete device credential: TBS + identity-key signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCredential {
    #[serde(flatten)]
    pub tbs: DeviceCredentialTbs,
    /// Ed25519 signature by `identity_pubkey` over `tbs.signing_input()`.
    pub signature: Signature,
}

/// Endorsement of a new device's credential by an already-enrolled device
/// (F1 additional-device enrollment). The server requires this before
/// accepting a second or later device; clients additionally verify the
/// credential itself against KT (INV-4).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceEndorsement {
    /// The endorsing (existing) device.
    pub endorsing_device_id: DeviceId,
    /// Ed25519 signature by the endorsing device key over
    /// `endorsement_signing_input(&new_credential)`.
    pub signature: Signature,
}

/// Deterministic bytes an existing device signs to endorse a new credential:
/// domain tag (u16-BE length || bytes) || the new credential's full signing
/// input || the identity signature over it (64B). Endorsing a credential
/// therefore commits to the exact credential bytes, including its signature.
pub fn endorsement_signing_input(new_credential: &DeviceCredential) -> Vec<u8> {
    let tag = DEVICE_ENDORSEMENT_DOMAIN.as_bytes();
    let inner = new_credential.tbs.signing_input();
    let mut out = Vec::with_capacity(2 + tag.len() + inner.len() + 64);
    out.extend_from_slice(&(tag.len() as u16).to_be_bytes());
    out.extend_from_slice(tag);
    out.extend_from_slice(&inner);
    out.extend_from_slice(&new_credential.signature.0);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn fixed_tbs() -> DeviceCredentialTbs {
        DeviceCredentialTbs {
            account_id: AccountId::from_uuid(Uuid::from_bytes([0xAA; 16])),
            device_id: DeviceId::from_uuid(Uuid::from_bytes([0xBB; 16])),
            identity_pubkey: IdentityPublicKey([0x01; 32]),
            device_pubkey: DevicePublicKey([0x02; 32]),
            issued_at: 1_700_000_000,
        }
    }

    #[test]
    fn signing_input_is_deterministic_and_pinned() {
        let tbs = fixed_tbs();
        let a = tbs.signing_input();
        let b = tbs.signing_input();
        assert_eq!(a, b);

        // Golden prefix: 2-byte BE tag length then the tag itself.
        let tag = DEVICE_CREDENTIAL_DOMAIN.as_bytes();
        assert_eq!(&a[..2], &(tag.len() as u16).to_be_bytes());
        assert_eq!(&a[2..2 + tag.len()], tag);
        // Total length is fully determined by the fixed-width layout.
        assert_eq!(a.len(), 2 + tag.len() + 16 + 16 + 32 + 32 + 8);
        // Trailing 8 bytes are issued_at in BE.
        assert_eq!(&a[a.len() - 8..], &1_700_000_000i64.to_be_bytes());
    }

    #[test]
    fn distinct_fields_produce_distinct_inputs() {
        let base = fixed_tbs();
        let mut other = fixed_tbs();
        other.device_pubkey = DevicePublicKey([0x03; 32]);
        assert_ne!(base.signing_input(), other.signing_input());
    }

    #[test]
    fn credential_json_roundtrip() {
        let cred = DeviceCredential {
            tbs: fixed_tbs(),
            signature: Signature([0x5A; 64]),
        };
        let json = serde_json::to_string(&cred).unwrap();
        let back: DeviceCredential = serde_json::from_str(&json).unwrap();
        assert_eq!(cred, back);
    }

    #[test]
    fn endorsement_input_commits_to_inner_signature() {
        let cred_a = DeviceCredential {
            tbs: fixed_tbs(),
            signature: Signature([0x5A; 64]),
        };
        let cred_b = DeviceCredential {
            tbs: fixed_tbs(),
            signature: Signature([0x5B; 64]),
        };
        assert_ne!(
            endorsement_signing_input(&cred_a),
            endorsement_signing_input(&cred_b)
        );
    }
}
