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
//! **Not compiled by any CI job in this repository today** — every workflow in
//! `.github/workflows/ci.yml` runs on `ubuntu-latest`. ADR-0007's
//! `store_release_uses_only_the_target_native_credential_backend` is what
//! covers this adapter, and that test needs a macOS runner that does not exist
//! yet. Treat this file as unexercised until it does.

use super::{require_32, CredentialStore, CredentialStoreError, SecretItem, SERVICE};
use keyring::credential::{Credential, CredentialBuilderApi};
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
