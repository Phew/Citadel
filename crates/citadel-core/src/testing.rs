//! Test helpers for fabricating self-consistent device identities.
//!
//! Behind the `testing` feature so the harness (K3) and the adversarial suite
//! (Opus, `test-harness/adversarial`) can build valid — and deliberately
//! invalid — identities against the same code the client uses. Not compiled
//! into release clients.

use crate::credential::IdentityVerifier;
use crate::crypto::Provider;
use crate::identity::DeviceIdentity;
use citadel_proto::credential::{
    DeviceCredential, DeviceCredentialTbs, DevicePublicKey, Signature as ProtoSig,
};
use citadel_proto::ids::{AccountId, DeviceId};
use citadel_proto::IdentityPublicKey;
use ed25519_dalek::{Signer, SigningKey};
use uuid::Uuid;

/// A fabricated identity plus the material a test verifier needs.
pub struct TestIdentity {
    pub identity: DeviceIdentity,
    pub account_id: AccountId,
    pub identity_pubkey: IdentityPublicKey,
}

fn random_seed() -> [u8; 32] {
    // Two v4 UUIDs (OS CSPRNG) give 32 random bytes — test-only key material.
    let mut seed = [0u8; 32];
    seed[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    seed[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    seed
}

/// Build a valid, KT-consistent device identity: a fresh account identity key
/// signs a fresh device credential, exactly as M1 registration/enrollment would.
pub fn make_identity(provider: &Provider) -> TestIdentity {
    let identity_key = SigningKey::from_bytes(&random_seed());
    let device_key = SigningKey::from_bytes(&random_seed());

    let account_id = AccountId::new();
    let identity_pubkey = IdentityPublicKey(identity_key.verifying_key().to_bytes());
    let device_pubkey = DevicePublicKey(device_key.verifying_key().to_bytes());

    let tbs = DeviceCredentialTbs {
        account_id,
        device_id: DeviceId::new(),
        identity_pubkey,
        device_pubkey,
        issued_at: 1_700_000_000,
    };
    let sig = identity_key.sign(&tbs.signing_input());
    let device_credential = DeviceCredential {
        tbs,
        signature: ProtoSig(sig.to_bytes()),
    };

    let identity = DeviceIdentity::from_parts(
        provider,
        device_credential,
        device_key.to_bytes(),
        device_key.verifying_key().to_bytes(),
    )
    .expect("valid identity");

    TestIdentity {
        identity,
        account_id,
        identity_pubkey,
    }
}

/// An [`IdentityVerifier`] that attests an explicit allow-list of
/// `(account, identity)` pairs. Omitting a pair models a non-KT-attested
/// identity (the adversarial swapped-KeyPackage case).
#[derive(Default)]
pub struct AllowList(pub Vec<(AccountId, [u8; 32])>);

impl AllowList {
    pub fn trusting(ids: &[&TestIdentity]) -> Self {
        Self(
            ids.iter()
                .map(|t| (t.account_id, t.identity_pubkey.0))
                .collect(),
        )
    }
}

impl IdentityVerifier for AllowList {
    fn is_kt_attested(&self, account_id: AccountId, identity_pubkey: &IdentityPublicKey) -> bool {
        self.0
            .iter()
            .any(|(a, k)| *a == account_id && *k == identity_pubkey.0)
    }
}
