//! Linux freedesktop Secret Service adapter (ADR-0007 §2).
//!
//! Uses `keyring` 3.6.3's **concrete** synchronous Secret Service builder
//! (`keyring::secret_service::default_credential_builder`) rather than
//! `keyring::Entry::new`. The default builder resolves at runtime and can fall
//! back to keyring's mock store when a native feature is absent, which would
//! silently move the database encryption key into process memory.
//!
//! ## Diffie-Hellman, and exactly how it is enforced
//!
//! ADR-0007 §2 requires the D-Bus session to use Diffie-Hellman encryption and
//! rejects a `Plain` negotiation. In keyring 3.6.3 that is **not** a runtime
//! negotiation this adapter can inspect — it is a compile-time selection:
//!
//! ```text
//! keyring-3.6.3/src/secret_service.rs:140-143
//!     #[cfg(any(feature = "crypto-rust", feature = "crypto-openssl"))]
//!     let session_type = EncryptionType::Dh;
//!     #[cfg(not(any(feature = "crypto-rust", feature = "crypto-openssl")))]
//!     let session_type = EncryptionType::Plain;
//! ```
//!
//! So the enforcement mechanism is the mandatory `crypto-rust` feature pinned in
//! this crate's `Cargo.toml`, and the mechanism that *checks* it is
//! [`crate::store::credentials::secret_service::tests::secret_service_session_is_diffie_hellman_not_plain`],
//! which reads the resolved feature graph rather than trusting the manifest.
//! Saying this precisely matters: keyring 3.6.3 exposes no API that would let
//! this adapter observe the negotiated session type at runtime, and claiming a
//! runtime check that does not exist is the defect class this project keeps
//! finding.

use super::{require_32, CredentialStore, CredentialStoreError, SecretItem, SERVICE};
use keyring::credential::{Credential, CredentialBuilderApi};
use keyring::secret_service::default_credential_builder;
use keyring::Error as KeyringError;
use zeroize::Zeroizing;

/// freedesktop Secret Service items in the user's default collection.
pub struct NativeCredentialStore {
    /// Always [`SERVICE`] in production; tests substitute a unique service so
    /// they cannot touch a live profile.
    service: String,
}

impl NativeCredentialStore {
    /// The production store, under the one fixed service identity.
    pub fn new() -> Self {
        Self {
            service: SERVICE.to_string(),
        }
    }

    /// A store under an isolated service identity, for tests driving the real
    /// backend. Not compiled into production builds.
    #[cfg(any(test, feature = "testing"))]
    pub fn with_isolated_service(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    fn credential(&self, item: SecretItem) -> Result<Box<Credential>, CredentialStoreError> {
        default_credential_builder()
            .build(None, &self.service, item.item_name())
            .map_err(|error| classify(error, item))
    }
}

impl Default for NativeCredentialStore {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialStore for NativeCredentialStore {
    fn read(&self, item: SecretItem) -> Result<Option<Zeroizing<[u8; 32]>>, CredentialStoreError> {
        match self.credential(item)?.get_secret() {
            // Wrapped in a zeroizing owner immediately; `secret` is moved in.
            Ok(secret) => require_32(item, Zeroizing::new(secret)).map(Some),
            Err(KeyringError::NoEntry) => Ok(None),
            Err(error) => Err(classify(error, item)),
        }
    }

    fn write(&self, item: SecretItem, secret: &[u8; 32]) -> Result<(), CredentialStoreError> {
        self.credential(item)?
            .set_secret(secret)
            .map_err(|error| classify(error, item))
    }

    fn delete(&self, item: SecretItem) -> Result<(), CredentialStoreError> {
        match self.credential(item)?.delete_credential() {
            // Absent is destruction's post-condition, so it is success.
            Ok(()) | Err(KeyringError::NoEntry) => Ok(()),
            Err(error) => Err(classify(error, item)),
        }
    }

    fn backend_name(&self) -> &'static str {
        "freedesktop-secret-service"
    }
}

fn classify(error: KeyringError, item: SecretItem) -> CredentialStoreError {
    match error {
        // A locked collection that the user did not unlock, and a missing
        // service, both arrive here; the message carries which.
        KeyringError::NoStorageAccess(inner) => CredentialStoreError::Locked(inner.to_string()),
        KeyringError::PlatformFailure(inner) => {
            CredentialStoreError::Unavailable(inner.to_string())
        }
        // Never resolved by picking one of them.
        KeyringError::Ambiguous(_) => CredentialStoreError::Duplicate(item.item_name()),
        KeyringError::BadEncoding(bytes) => CredentialStoreError::Malformed {
            item: item.item_name(),
            found: bytes.len(),
        },
        other => CredentialStoreError::Backend(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Drives the real Secret Service under a service identity no production
    /// build uses, so an interrupted run cannot touch a live profile.
    fn isolated() -> NativeCredentialStore {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        NativeCredentialStore::with_isolated_service(format!(
            "Citadel-test-{}-{n}",
            std::process::id()
        ))
    }

    /// ADR-0007 §2's Diffie-Hellman requirement, checked against the RESOLVED
    /// feature graph rather than against this crate's manifest text. It fails if
    /// a dependency change or a `--no-default-features` invocation ever drops
    /// `crypto-rust`, which is the moment keyring silently selects
    /// `EncryptionType::Plain` at `secret_service.rs:143`.
    ///
    /// Ignored by default because it shells out to cargo; the store-evidence CI
    /// job runs it with `--include-ignored`.
    #[test]
    #[ignore = "requires cargo and a populated registry; run by the store-evidence CI job"]
    fn secret_service_session_is_diffie_hellman_not_plain() {
        let output = std::process::Command::new(env!("CARGO"))
            .args([
                "tree",
                "--package",
                "citadel-core",
                "--edges",
                "features",
                "--invert",
                "keyring",
                "--target",
                "x86_64-unknown-linux-gnu",
            ])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .output()
            .expect("cargo tree must run");
        assert!(
            output.status.success(),
            "cargo tree failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let tree = String::from_utf8_lossy(&output.stdout);
        assert!(
            tree.contains("crypto-rust"),
            "keyring must resolve with the crypto-rust feature, or the Secret Service \
             session silently negotiates EncryptionType::Plain \
             (keyring-3.6.3/src/secret_service.rs:143). Resolved graph:\n{tree}"
        );
    }

    /// Exercises the REAL Secret Service. Ignored by default: `cargo test` on a
    /// machine with no D-Bus session must not appear to cover this. The
    /// store-evidence CI job provisions `dbus-run-session` plus gnome-keyring
    /// and runs it with `--include-ignored`, so it is never silently skipped
    /// where it is claimed as evidence (AGENTS.md rule 4).
    #[test]
    #[ignore = "requires a D-Bus session and a Secret Service implementation; provisioned by the store-evidence CI job"]
    fn native_backend_roundtrips_and_deletes() {
        let store = isolated();
        let item = SecretItem::DatabaseEncryptionKey;
        let secret = [0xA7u8; 32];

        store.write(item, &secret).expect("write");
        let read = store
            .read(item)
            .expect("read")
            .expect("present after write");
        assert_eq!(&read[..], &secret[..]);
        assert_eq!(store.backend_name(), "freedesktop-secret-service");

        store.delete(item).expect("delete");
        assert!(store.read(item).expect("read after delete").is_none());
        store
            .delete(item)
            .expect("deleting an absent entry is success");
    }

    #[test]
    #[ignore = "requires a D-Bus session and a Secret Service implementation; provisioned by the store-evidence CI job"]
    fn the_three_items_do_not_alias_each_other() {
        let store = isolated();
        store
            .write(SecretItem::DatabaseEncryptionKey, &[0x11; 32])
            .expect("write dek");
        store
            .write(SecretItem::DeviceSigningSeed, &[0x22; 32])
            .expect("write device seed");

        assert_eq!(
            &store
                .read(SecretItem::DatabaseEncryptionKey)
                .expect("read")
                .expect("present")[..],
            &[0x11u8; 32][..]
        );
        assert_eq!(
            &store
                .read(SecretItem::DeviceSigningSeed)
                .expect("read")
                .expect("present")[..],
            &[0x22u8; 32][..]
        );
        assert!(store
            .read(SecretItem::AccountIdentitySigningSeed)
            .expect("read")
            .is_none());

        for item in SecretItem::ALL {
            let _ = store.delete(item);
        }
    }

    #[test]
    fn production_store_uses_the_one_fixed_service_identity() {
        assert_eq!(NativeCredentialStore::new().service, SERVICE);
    }
}
