//! Deterministic Ed25519 signers for tests: client-side key material.
//!
//! Server-side service crates are confined to the citadel-service-crypto
//! facade (AGENTS.md rule 6, ADR-0002 §4 rev 2 — normal, dev, and build
//! dependencies alike), so a service test that needs a *client* signature
//! (device key answering an auth challenge, identity key signing a device
//! credential) cannot pull a signing crate itself. The harness is the
//! client-side toolkit and is out of the confinement check's scope; tests
//! take their signer from here.
//!
//! Deterministic seeds: tests must be reproducible byte-for-byte.

use ed25519_dalek::{Signer, SigningKey};

/// An Ed25519 signer standing in for a client-held key (device key or
/// account identity key) in tests.
pub struct TestSigner {
    signing: SigningKey,
}

impl TestSigner {
    /// Derive a signer from a fixed 32-byte seed (any bytes; they are test
    /// key material, never production secrets).
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(&seed),
        }
    }

    /// The Ed25519 public key (e.g. a row's `device_pubkey`).
    pub fn public_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// Ed25519 signature over `message`.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing.sign(message).to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_verify_under_public_key() {
        let signer = TestSigner::from_seed([0x42; 32]);
        let msg = b"citadel test message";
        let sig = signer.sign(msg);
        citadel_service_crypto::verify(&signer.public_key(), msg, &sig)
            .expect("own signature verifies");
        citadel_service_crypto::verify(&signer.public_key(), b"other", &sig)
            .expect_err("wrong message rejected");
    }

    #[test]
    fn deterministic_per_seed() {
        let a = TestSigner::from_seed([0x01; 32]);
        let b = TestSigner::from_seed([0x01; 32]);
        assert_eq!(a.public_key(), b.public_key());
        assert_eq!(a.sign(b"x"), b.sign(b"x"));
    }
}
