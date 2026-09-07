//! macOS Keychain Services adapter (ADR-0007 §2).
//!
//! Uses `keyring` 3.6.3's **concrete** Apple-native builder
//! (`keyring::macos::default_credential_builder`) rather than
//! `keyring::Entry::new`. That distinction is the point: the default builder
//! resolves at runtime and can fall back to keyring's mock store when a native
//! feature is absent, which would silently move the database encryption key
//! into process memory. Naming the concrete builder makes an unsupported
//! configuration a build error instead.
//!
//! Items are legacy generic-password items in the login keychain
//! (`MacKeychainDomain::User`), which are non-synchronizing: keyring 3.6.3 talks
//! to `SecKeychain*`, and iCloud Keychain synchronization applies to
//! `kSecAttrSynchronizable` data-protection items, which this path never
//! creates.
//!
//! Compiled and exercised by the `store-macos` CI job (`macos-latest`), which
//! runs the `#[ignore]`d tests below against the real login keychain with
//! `--include-ignored`, the same way `store-evidence` drives the Secret
//! Service adapter on Linux. Until 2026-09-06 no CI job compiled this file;
//! its first execution anywhere was on that date, on a developer Mac.
//! ADR-0007's `store_release_uses_only_the_target_native_credential_backend`
//! (release profile, all three desktop targets) remains PR #80's.

use super::{require_32, CredentialStore, CredentialStoreError, SecretItem, SERVICE};
// Same trait-object reasoning as the Secret Service adapter:
// `keyring::macos::default_credential_builder` returns `Box<CredentialBuilder>`
// (`keyring-3.6.3/src/macos.rs:179`), and `CredentialBuilder` is the alias
// `dyn CredentialBuilderApi + Send + Sync` (`credential.rs:183`), so `.build()`
// needs no trait import. The identical import on the Linux adapter was an
// unused-import error under `-D warnings`; this one is corrected by inspection
// against the pinned source, because no CI job compiles this file.
use keyring::credential::Credential;
use keyring::macos::default_credential_builder;
use keyring::Error as KeyringError;
use zeroize::Zeroizing;

/// macOS login-keychain generic passwords.
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

    /// A store under a caller-chosen service identity, for hosts that keep
    /// more than one profile per OS user (each profile then owns its own
    /// three entries). Production hosts default to [`SERVICE`]; tests use a
    /// per-process identity so they cannot touch a live profile.
    pub fn with_service(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    /// Alias kept for the existing conformance tests.
    #[cfg(any(test, feature = "testing"))]
    pub fn with_isolated_service(service: impl Into<String>) -> Self {
        Self::with_service(service)
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
            // Wrapped in a zeroizing owner immediately; `secret` itself is the
            // only plain `Vec<u8>` and it is moved, not copied.
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
        "macos-keychain-services"
    }
}

fn classify(error: KeyringError, item: SecretItem) -> CredentialStoreError {
    match error {
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

    /// Drives the real login keychain under a service identity no production
    /// build uses, so an interrupted run cannot touch a live profile.
    fn isolated() -> NativeCredentialStore {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        NativeCredentialStore::with_isolated_service(format!(
            "Citadel-test-{}-{n}",
            std::process::id()
        ))
    }

    /// Exercises the REAL Keychain. Ignored by default so `cargo test` on a
    /// machine whose login keychain is locked, or on a headless session, does
    /// not appear to cover this. The store-macos CI job provisions an unlocked
    /// default keychain and runs it with `--include-ignored`, so it is never
    /// silently skipped where it is claimed as evidence (AGENTS.md rule 4).
    #[test]
    #[ignore = "requires an unlocked login keychain; provisioned by the store-macos CI job"]
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
        assert_eq!(store.backend_name(), "macos-keychain-services");

        // Replacement, not duplication: a second write must leave exactly one
        // item, which the read then returns without an Ambiguous error.
        let replaced = [0x5Cu8; 32];
        store.write(item, &replaced).expect("overwrite");
        assert_eq!(
            &store.read(item).expect("read").expect("present")[..],
            &replaced[..]
        );

        store.delete(item).expect("delete");
        assert!(store.read(item).expect("read after delete").is_none());
        store
            .delete(item)
            .expect("deleting an absent entry is success");
    }

    #[test]
    #[ignore = "requires an unlocked login keychain; provisioned by the store-macos CI job"]
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

    /// A stored value that is not 32 bytes is not one this contract wrote,
    /// and must surface as `Malformed` rather than be truncated or padded.
    #[test]
    #[ignore = "requires an unlocked login keychain; provisioned by the store-macos CI job"]
    fn a_foreign_sized_entry_is_malformed_not_coerced() {
        let store = isolated();
        let item = SecretItem::DeviceSigningSeed;
        store
            .credential(item)
            .expect("credential")
            .set_secret(&[0x01; 31])
            .expect("write a 31-byte value through the raw keyring credential");
        let result = store.read(item);
        assert!(
            matches!(
                result,
                Err(CredentialStoreError::Malformed { found: 31, .. })
            ),
            "expected Malformed{{found: 31}}, got {result:?}"
        );
        store.delete(item).expect("cleanup");
    }

    #[test]
    fn production_store_uses_the_one_fixed_service_identity() {
        assert_eq!(NativeCredentialStore::new().service, SERVICE);
    }
}
