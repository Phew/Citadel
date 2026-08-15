//! The database encryption key (ADR-0007 §2).
//!
//! Exactly 32 uniformly random bytes, generated **once** through the OpenMLS
//! RustCrypto provider's OS-backed random source (INV-9). It is never derived
//! from a password, an account identifier, a device key, a machine identifier,
//! or any other low-entropy input, and it is never derived from — or used to
//! derive — either signing seed.
//!
//! Citadel encodes it in exactly one place: the SQLCipher boundary, as the
//! canonical raw-key form `x'<64 lowercase hex characters>'`. That fixed
//! representation is what makes SQLCipher bypass its passphrase KDF, so there
//! is no application-level KDF anywhere in this crate; SQLCipher keeps
//! responsibility for its internal page and HMAC key schedule.

use openmls_rust_crypto::RustCrypto;
use openmls_traits::random::OpenMlsRand;
use zeroize::Zeroizing;

/// A 32-byte SQLCipher database encryption key.
///
/// There is deliberately no `Display`, no `Debug` field exposure, and no
/// `Serialize`: ADR-0007 §6 forbids serializing this value to server storage,
/// telemetry, logs, crash reports, or the database itself, and the cheapest way
/// to keep that true is for the type to have no way to say it.
pub struct DatabaseEncryptionKey(Zeroizing<[u8; 32]>);

impl std::fmt::Debug for DatabaseEncryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DatabaseEncryptionKey(<redacted>)")
    }
}

/// Generating the key failed, which means the OS random source failed.
#[derive(Debug, thiserror::Error)]
#[error("the OS random source did not produce a database encryption key: {0}")]
pub struct KeyGenerationError(String);

impl DatabaseEncryptionKey {
    /// Generate a new key from the provider's OS-backed CSPRNG.
    ///
    /// INV-9: randomness comes from the provider, never from `rand::thread_rng`
    /// or any application-side construction.
    pub fn generate() -> Result<Self, KeyGenerationError> {
        let rand = RustCrypto::default();
        let bytes: [u8; 32] = rand
            .random_array()
            .map_err(|error| KeyGenerationError(format!("{error:?}")))?;
        Ok(Self(Zeroizing::new(bytes)))
    }

    /// Adopt a key read from the OS credential store.
    pub fn from_bytes(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self(bytes)
    }

    /// The raw bytes, for writing to the credential store only.
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The canonical SQLCipher raw-key literal, `x'<64 lowercase hex>'`.
    ///
    /// Built by hand rather than through a hex crate so the intermediate lives
    /// in a zeroizing owner from its first byte: a `String` returned by a
    /// formatting helper would be a plain heap allocation holding the key in
    /// printable form.
    pub(crate) fn raw_key_literal(&self) -> Zeroizing<String> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut literal = Zeroizing::new(String::with_capacity(3 + 64));
        literal.push_str("x'");
        for byte in self.0.iter() {
            literal.push(HEX[(byte >> 4) as usize] as char);
            literal.push(HEX[(byte & 0x0f) as usize] as char);
        }
        literal.push('\'');
        literal
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_key_literal_is_the_canonical_lowercase_hex_form() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0x00;
        bytes[1] = 0x0f;
        bytes[2] = 0xf0;
        bytes[31] = 0xab;
        let key = DatabaseEncryptionKey::from_bytes(Zeroizing::new(bytes));
        let literal = key.raw_key_literal();
        assert_eq!(literal.len(), 3 + 64, "x' + 64 hex + '");
        assert!(literal.starts_with("x'") && literal.ends_with('\''));
        assert!(literal.starts_with("x'000ff0"), "{}", &*literal);
        assert!(literal.ends_with("ab'"), "{}", &*literal);
        assert!(
            literal[2..literal.len() - 1]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "hex must be lowercase with no separators"
        );
    }

    #[test]
    fn generated_keys_are_distinct_and_not_all_zero() {
        let a = DatabaseEncryptionKey::generate().expect("os csprng");
        let b = DatabaseEncryptionKey::generate().expect("os csprng");
        assert_ne!(a.as_bytes(), b.as_bytes());
        assert_ne!(a.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn debug_never_prints_key_material() {
        let key = DatabaseEncryptionKey::from_bytes(Zeroizing::new([0xCD; 32]));
        let rendered = format!("{key:?}");
        assert_eq!(rendered, "DatabaseEncryptionKey(<redacted>)");
        assert!(!rendered.contains("cd"));
    }
}
