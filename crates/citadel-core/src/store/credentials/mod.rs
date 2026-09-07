//! The OS credential-store contract (ADR-0007 §2).
//!
//! At rest the database encryption key exists **only** as a binary secret in the
//! current OS user's credential store. Nothing here reads an environment
//! variable, a file, command output, Linux keyutils, or a process-memory store,
//! and nothing falls back to one: on an unsupported target the crate does not
//! compile, and a missing native backend is a build error rather than a
//! degraded run.
//!
//! | Platform | Backend | Contract |
//! |---|---|---|
//! | Windows | Credential Manager | per-user generic credentials, `CRED_PERSIST_LOCAL_MACHINE`; enterprise roaming forbidden |
//! | macOS | Keychain Services | non-synchronizing generic-password items in the login keychain |
//! | Linux | freedesktop Secret Service | items in the user's default collection; a locked collection may prompt |
//!
//! A credential-store double exists only under test configuration
//! ([`double`]), and only so injected failure states can be exercised without a
//! real backend. It is behind `cfg(any(test, feature = "testing"))`, so it is
//! not in the production dependency graph at all.

use zeroize::Zeroizing;

#[cfg(any(test, feature = "testing"))]
pub mod double;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::NativeCredentialStore;

#[cfg(target_os = "macos")]
mod apple;
#[cfg(target_os = "macos")]
pub use apple::NativeCredentialStore;

#[cfg(target_os = "linux")]
mod secret_service;
#[cfg(target_os = "linux")]
pub use secret_service::NativeCredentialStore;

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
compile_error!(
    "citadel-core's local encrypted client store supports only the ADR-0007 §2 desktop targets \
     (Windows, macOS, Linux). Supporting another target requires extending the release matrix \
     and its evidence first — it must not silently fall back to a non-OS-backed key store."
);

/// The one fixed, non-empty service identity for every Citadel credential-store
/// item. ADR-0007 §2 pins one local device profile per OS user for v1.
pub const SERVICE: &str = "Citadel";

/// Every secret Citadel keeps outside the encrypted database.
///
/// The three are independent: each present value is exactly 32 independently
/// generated random bytes and **no value is derived from another**. They also
/// have different lifecycles — the database encryption key follows store
/// creation, the signing seeds follow registration and enrollment — which is
/// why an absent signing seed is not a store-state error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecretItem {
    /// The 32-byte SQLCipher database encryption key. Every profile has one.
    DatabaseEncryptionKey,
    /// The account identity signing seed. Only the profile that created and
    /// retains the account identity holds this; an additional device profile
    /// does **not** copy it merely to satisfy this contract.
    AccountIdentitySigningSeed,
    /// The device signing seed, present after enrollment.
    DeviceSigningSeed,
}

impl SecretItem {
    /// The per-profile item identity within [`SERVICE`]. Distinct per item so a
    /// read for one secret can never return another.
    pub const fn item_name(self) -> &'static str {
        match self {
            SecretItem::DatabaseEncryptionKey => "profile-v1.database-encryption-key",
            SecretItem::AccountIdentitySigningSeed => "profile-v1.account-identity-signing-seed",
            SecretItem::DeviceSigningSeed => "profile-v1.device-signing-seed",
        }
    }

    /// All three, in destruction order. Local profile destruction attempts every
    /// deletion and reports a structured partial failure rather than stopping at
    /// the first error, so it needs a stable enumeration.
    pub const ALL: [SecretItem; 3] = [
        SecretItem::DatabaseEncryptionKey,
        SecretItem::DeviceSigningSeed,
        SecretItem::AccountIdentitySigningSeed,
    ];
}

/// Every way the OS credential store can refuse. ADR-0007 §2: all of them fail
/// closed, and none of them is ever answered by generating a replacement.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CredentialStoreError {
    /// The backend service is not running or not reachable. On Linux this is
    /// the headless case, which is unsupported for the production store.
    #[error("the OS credential store is unavailable: {0}")]
    Unavailable(String),

    /// The item or its collection is locked and the user did not authorize.
    #[error("the OS credential store is locked and was not unlocked: {0}")]
    Locked(String),

    /// More than one entry matched. Never resolved by picking one.
    #[error("duplicate credential entries for {0}")]
    Duplicate(&'static str),

    /// The entry exists but is not exactly 32 bytes, so it is not a value this
    /// contract ever wrote.
    #[error("credential entry for {item} is malformed: expected 32 bytes, found {found}")]
    Malformed {
        /// Which item.
        item: &'static str,
        /// Length actually returned.
        found: usize,
    },

    /// The entry exists but this process may not read it.
    #[error("credential entry for {0} is inaccessible")]
    Inaccessible(&'static str),

    /// The Secret Service session negotiated the `Plain` algorithm. ADR-0007 §2
    /// makes Diffie-Hellman mandatory, so this is a refusal and not a warning.
    #[error("the Secret Service session did not negotiate Diffie-Hellman encryption")]
    PlainSessionRejected,

    /// Anything the backend reported that does not classify above.
    #[error("credential store backend: {0}")]
    Backend(String),
}

/// The narrow surface the store needs from an OS credential store.
///
/// Read returns `Ok(None)` **only** for a genuinely absent entry. Every other
/// condition — unavailable, locked, duplicate, malformed, inaccessible — is an
/// error, because ADR-0007 §2's startup state machine branches on absence and
/// must never confuse "not there" with "could not look".
pub trait CredentialStore: Send + Sync {
    /// Read one 32-byte secret. `Ok(None)` means absent, nothing else does.
    fn read(&self, item: SecretItem) -> Result<Option<Zeroizing<[u8; 32]>>, CredentialStoreError>;

    /// Write one 32-byte secret, replacing any existing value for that item.
    fn write(&self, item: SecretItem, secret: &[u8; 32]) -> Result<(), CredentialStoreError>;

    /// Delete one secret. Deleting an absent entry is success: destruction's
    /// post-condition is "confirmed absent", not "was present and removed".
    fn delete(&self, item: SecretItem) -> Result<(), CredentialStoreError>;

    /// The concrete backend actually in use, for release conformance evidence.
    /// A mock or unsupported backend must be distinguishable from a real one
    /// **by the running program**, not by reading the build configuration.
    fn backend_name(&self) -> &'static str;
}

/// Reject a blob that is not exactly the 32 bytes this contract writes.
pub(crate) fn require_32(
    item: SecretItem,
    blob: Zeroizing<Vec<u8>>,
) -> Result<Zeroizing<[u8; 32]>, CredentialStoreError> {
    if blob.len() != 32 {
        return Err(CredentialStoreError::Malformed {
            item: item.item_name(),
            found: blob.len(),
        });
    }
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&blob[..]);
    Ok(out)
}
