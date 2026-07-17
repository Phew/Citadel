//! citadel-service-crypto: the ONLY cryptography surface for server-side
//! services (AGENTS.md rule 6).
//!
//! Exactly three capabilities, by design:
//!   1. [`verify`] — Ed25519 signature verification
//!   2. [`sha256`] — SHA-256 digest
//!   3. [`random_bytes`] — OS-CSPRNG bytes (INV-9)
//!
//! Deliberately absent, and to stay absent: signing, key generation,
//! encryption, decryption, KDFs, MACs. Services have no keys (INV-2) and no
//! plaintext (INV-1); a service that seems to need a fourth capability is a
//! design smell — escalate via docs/issues/, do not extend this crate.
//!
//! All primitives come from vetted implementations (ed25519-dalek, sha2,
//! getrandom); nothing here implements crypto (INV-10). deny.toml bans
//! direct crypto dependencies in service crates so this facade is the choke
//! point auditors read.

use ed25519_dalek::{Signature, VerifyingKey};

/// Error surface of the facade. Small on purpose.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// Public key bytes are not a valid Ed25519 point.
    #[error("invalid Ed25519 public key")]
    InvalidPublicKey,
    /// Signature did not verify over the given message.
    #[error("signature verification failed")]
    VerificationFailed,
    /// The OS CSPRNG failed. Callers must treat this as fatal, never fall
    /// back to a weaker source (INV-9).
    #[error("OS CSPRNG failure: {0}")]
    RngFailure(String),
}

/// Verify a detached Ed25519 signature.
///
/// `public_key`: 32-byte Ed25519 public key. `signature`: 64-byte detached
/// signature. `message`: exact signed bytes (callers build these from the
/// deterministic signing inputs defined in citadel-proto — never re-derive
/// them ad hoc).
///
/// Uses `verify_strict`, which additionally rejects small-order/mixed-order
/// public key and R components. Cheap insurance against signature
/// malleability classes; identity keys and device keys are honest-client
/// generated, so strictness costs nothing.
pub fn verify(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), CryptoError> {
    let key = VerifyingKey::from_bytes(public_key).map_err(|_| CryptoError::InvalidPublicKey)?;
    let sig = Signature::from_bytes(signature);
    key.verify_strict(message, &sig)
        .map_err(|_| CryptoError::VerificationFailed)
}

/// SHA-256 digest of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Fill `buf` with bytes from the operating system CSPRNG (INV-9).
///
/// This is the only sanctioned randomness source for services (auth
/// challenges, invite codes, token material). Never `rand::thread_rng` in
/// service code.
pub fn random_bytes(buf: &mut [u8]) -> Result<(), CryptoError> {
    getrandom::getrandom(buf).map_err(|e| CryptoError::RngFailure(e.to_string()))
}

/// Convenience: N random bytes from the OS CSPRNG as a fixed array.
pub fn random_array<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut out = [0u8; N];
    random_bytes(&mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn keypair() -> SigningKey {
        SigningKey::generate(&mut rand::rngs::OsRng)
    }

    #[test]
    fn verify_accepts_valid_signature() {
        let sk = keypair();
        let msg = b"citadel/v1/test message";
        let sig = sk.sign(msg);
        verify(sk.verifying_key().as_bytes(), msg, &sig.to_bytes())
            .expect("valid signature must verify");
    }

    #[test]
    fn verify_rejects_wrong_message_wrong_key_and_flipped_bit() {
        let sk = keypair();
        let msg = b"original";
        let sig = sk.sign(msg).to_bytes();
        let pk = *sk.verifying_key().as_bytes();

        // Wrong message.
        assert!(matches!(
            verify(&pk, b"tampered", &sig),
            Err(CryptoError::VerificationFailed)
        ));
        // Wrong key.
        let other_pk = *keypair().verifying_key().as_bytes();
        assert!(verify(&other_pk, msg, &sig).is_err());
        // Flipped signature bit.
        let mut bad_sig = sig;
        bad_sig[0] ^= 0x01;
        assert!(verify(&pk, msg, &bad_sig).is_err());
    }

    #[test]
    fn verify_rejects_invalid_public_key_bytes() {
        // All-0xFF is not a valid curve point encoding.
        let bad_pk = [0xFF; 32];
        let r = verify(&bad_pk, b"m", &[0; 64]);
        assert!(matches!(
            r,
            Err(CryptoError::InvalidPublicKey) | Err(CryptoError::VerificationFailed)
        ));
    }

    #[test]
    fn sha256_matches_known_vector() {
        // NIST vector: SHA-256("abc")
        let d = sha256(b"abc");
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(d, expected);
    }

    #[test]
    fn random_bytes_fills_and_varies() {
        let a: [u8; 32] = random_array().unwrap();
        let b: [u8; 32] = random_array().unwrap();
        // 2^-256 false-failure probability is acceptable.
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);
    }
}
