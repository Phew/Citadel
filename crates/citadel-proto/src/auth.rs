//! Request/response bodies for auth-service endpoints (F1, PLAN.md §8).
//!
//! Token issuance is device-key challenge-response; no passwords in v1.
//! Everything here is metadata or public-key material — never private keys
//! (INV-2) and never plaintext content (INV-1).

use crate::bytes::b64vec;
use crate::credential::{DeviceCredential, DeviceEndorsement, IdentityPublicKey, Signature};
use crate::ids::{AccountId, DeviceId};
use crate::kt::SignedTreeHead;
use serde::{Deserialize, Serialize};

/// Domain separation tag for auth challenge signatures.
pub const AUTH_CHALLENGE_DOMAIN: &str = "citadel/v1/auth-challenge";

// ---------- POST /v1/accounts ----------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterAccountRequest {
    pub handle: String,
    pub identity_pubkey: IdentityPublicKey,
    /// The first device's credential, signed by `identity_pubkey`.
    pub first_device: DeviceCredential,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterAccountResponse {
    pub account_id: AccountId,
    pub device_id: DeviceId,
    /// Index of this account's identity-key leaf in the KT log.
    pub kt_leaf_index: u64,
    /// Server-assigned append timestamp stamped into this account's `KtLeaf`
    /// (Unix seconds). The client cannot know it a priori, yet it is part of
    /// `KtLeaf::leaf_bytes()`, so the F1 step-5 self-inclusion check needs it
    /// to rebuild the leaf and reproduce its hash — the other leaf fields
    /// (`account_id`, handle, `identity_pubkey`) the client already holds.
    /// See docs/protocol/auth.md §3 step B.
    pub kt_appended_at: i64,
    /// Tree head signed after the append; the client verifies its own
    /// inclusion proof against this before trusting registration (F1 step 5).
    pub kt_tree_head: SignedTreeHead,
}

// ---------- POST /v1/devices ----------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollDeviceRequest {
    /// New device credential, signed by the account identity key.
    pub credential: DeviceCredential,
    /// Endorsement by an existing enrolled device (required for every device
    /// after the first; F1 additional-device flow).
    pub endorsement: DeviceEndorsement,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollDeviceResponse {
    pub device_id: DeviceId,
}

// ---------- KeyPackages ----------

/// POST /v1/devices/{id}/key-packages — replenish the one-time pool.
/// Packages are opaque MLS KeyPackage bytes (TLS serialization); the server
/// stores and hands them out, it does not parse them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishKeyPackagesRequest {
    pub packages: Vec<KeyPackageBytes>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KeyPackageBytes(#[serde(with = "b64vec")] pub Vec<u8>);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishKeyPackagesResponse {
    /// Unconsumed pool size after this publish.
    pub pool_size: u32,
}

/// GET /v1/accounts/{id}/key-packages — consuming fetch, one package per
/// active device. Consumption is transactional server-side: a package is
/// returned to exactly one caller ever (M1 AC, property-tested by K3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchKeyPackagesResponse {
    pub packages: Vec<DeviceKeyPackage>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceKeyPackage {
    pub device_id: DeviceId,
    pub package: KeyPackageBytes,
}

// ---------- POST /v1/auth/challenge, /v1/auth/verify ----------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeRequest {
    pub device_id: DeviceId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeResponse {
    /// Server-generated random challenge (>= 32 bytes from OS CSPRNG, INV-9).
    #[serde(with = "b64vec")]
    pub challenge: Vec<u8>,
    /// Unix seconds; challenge is single-use and expires.
    pub expires_at: i64,
}

/// Deterministic bytes the device key signs to answer a challenge:
/// domain tag (u16-BE length || bytes) || device_id (16B) ||
/// challenge (u16-BE length || bytes). Binding the device_id prevents a
/// MITM relaying one device's challenge to another.
pub fn challenge_signing_input(device_id: DeviceId, challenge: &[u8]) -> Vec<u8> {
    let tag = AUTH_CHALLENGE_DOMAIN.as_bytes();
    let mut out = Vec::with_capacity(2 + tag.len() + 16 + 2 + challenge.len());
    out.extend_from_slice(&(tag.len() as u16).to_be_bytes());
    out.extend_from_slice(tag);
    out.extend_from_slice(device_id.as_uuid().as_bytes());
    out.extend_from_slice(&(challenge.len() as u16).to_be_bytes());
    out.extend_from_slice(challenge);
    out
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyRequest {
    pub device_id: DeviceId,
    /// The challenge bytes being answered (server matches against issued state).
    #[serde(with = "b64vec")]
    pub challenge: Vec<u8>,
    /// Ed25519 signature by the device key over `challenge_signing_input(...)`.
    pub signature: Signature,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyResponse {
    /// Opaque bearer token.
    pub token: String,
    /// Unix seconds.
    pub expires_at: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn challenge_input_binds_device_id() {
        let c = b"random-challenge-bytes-0123456789";
        let d1 = DeviceId::from_uuid(Uuid::from_bytes([1; 16]));
        let d2 = DeviceId::from_uuid(Uuid::from_bytes([2; 16]));
        assert_ne!(
            challenge_signing_input(d1, c),
            challenge_signing_input(d2, c)
        );
    }

    #[test]
    fn register_request_roundtrip() {
        use crate::credential::{DeviceCredentialTbs, DevicePublicKey};
        let req = RegisterAccountRequest {
            handle: "alice".into(),
            identity_pubkey: IdentityPublicKey([1; 32]),
            first_device: DeviceCredential {
                tbs: DeviceCredentialTbs {
                    account_id: AccountId::from_uuid(Uuid::from_bytes([0; 16])),
                    device_id: DeviceId::from_uuid(Uuid::from_bytes([9; 16])),
                    identity_pubkey: IdentityPublicKey([1; 32]),
                    device_pubkey: DevicePublicKey([2; 32]),
                    issued_at: 0,
                },
                signature: Signature([7; 64]),
            },
        };
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(
            serde_json::from_str::<RegisterAccountRequest>(&json).unwrap(),
            req
        );
    }
}
