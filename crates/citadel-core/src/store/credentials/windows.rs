//! Windows Credential Manager adapter (ADR-0007 §2).
//!
//! This calls `CredReadW`, `CredWriteW`, and `CredDeleteW` directly instead of
//! going through `keyring` 3.6.3, for one specific reason: keyring hard-codes
//! `CRED_PERSIST_ENTERPRISE` (`keyring-3.6.3/src/windows.rs:246`), and
//! ADR-0007 §2 forbids enterprise roaming for these secrets. A roaming
//! credential would follow the user to another machine while the encrypted
//! database did not, which is a key-escrow surface this design does not accept.
//!
//! The read path is the delicate part. `CredReadW` allocates a `CREDENTIALW`
//! that the caller must release with `CredFree`, and `windows-sys` 0.61.2
//! exposes no wipe binding for it. So the returned pointer goes into an RAII
//! owner whose `Drop` builds a checked mutable slice over `CredentialBlob`,
//! zeroizes it, and only then calls `CredFree`. That happens on **every** exit
//! path, including a malformed length and a failed copy, because those are
//! exactly the paths a hand-written `CredFree` call gets wrong.

use super::{require_32, CredentialStore, CredentialStoreError, SecretItem, SERVICE};
use windows_sys::Win32::Foundation::{GetLastError, ERROR_NOT_FOUND};
use windows_sys::Win32::Security::Credentials::{
    CredDeleteW, CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_PERSIST_LOCAL_MACHINE,
    CRED_TYPE_GENERIC,
};
use zeroize::{Zeroize, Zeroizing};

/// Windows Credential Manager, per-user generic credentials.
#[derive(Debug, Clone)]
pub struct NativeCredentialStore {
    /// Always [`SERVICE`] in production. Tests substitute a unique service so
    /// they can exercise the real backend without any possibility of reading or
    /// deleting a live profile's secrets.
    service: String,
}

impl NativeCredentialStore {
    /// The production store, under the one fixed service identity.
    pub fn new() -> Self {
        Self {
            service: SERVICE.to_string(),
        }
    }

    /// A store under an isolated service identity, for tests that must drive the
    /// real OS backend. Not compiled into production builds.
    #[cfg(any(test, feature = "testing"))]
    pub fn with_isolated_service(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    /// `Service:item` as a NUL-terminated UTF-16 target name.
    fn target_name(&self, item: SecretItem) -> Vec<u16> {
        format!("{}:{}", self.service, item.item_name())
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect()
    }
}

impl Default for NativeCredentialStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Owns the `CREDENTIALW` that `CredReadW` allocated.
///
/// `Drop` wipes the credential blob before releasing it. Wiping in `Drop`
/// rather than at the end of the happy path is the whole point: an early return
/// on a malformed length must not leave 32 bytes of key material in a heap
/// block that `CredFree` merely returns to the allocator.
struct CredentialHandle(*mut CREDENTIALW);

impl CredentialHandle {
    /// A read-only view of the credential blob, or `None` if the OS handed back
    /// a null pointer with a non-zero length (a broken API contract, not a state
    /// this code tries to interpret).
    fn blob(&self) -> Option<&[u8]> {
        // SAFETY: `self.0` was checked non-null at construction, and `CredReadW`
        // guarantees the `CREDENTIALW` stays valid until `CredFree`, which only
        // `Drop` calls.
        let credential = unsafe { &*self.0 };
        let len = credential.CredentialBlobSize as usize;
        if credential.CredentialBlob.is_null() {
            return if len == 0 { Some(&[]) } else { None };
        }
        // SAFETY: the OS reports `CredentialBlobSize` bytes at `CredentialBlob`;
        // the borrow cannot outlive this owner.
        Some(unsafe { std::slice::from_raw_parts(credential.CredentialBlob, len) })
    }
}

impl Drop for CredentialHandle {
    fn drop(&mut self) {
        // SAFETY: as in `blob`; this runs exactly once, immediately before the
        // matching `CredFree`.
        unsafe {
            let credential = &mut *self.0;
            let len = credential.CredentialBlobSize as usize;
            if !credential.CredentialBlob.is_null() && len > 0 {
                std::slice::from_raw_parts_mut(credential.CredentialBlob, len).zeroize();
            }
            CredFree(self.0 as *const core::ffi::c_void);
        }
    }
}

impl CredentialStore for NativeCredentialStore {
    fn read(&self, item: SecretItem) -> Result<Option<Zeroizing<[u8; 32]>>, CredentialStoreError> {
        let target = self.target_name(item);
        let mut raw: *mut CREDENTIALW = std::ptr::null_mut();
        // SAFETY: `target` is NUL-terminated and outlives the call, and `raw` is
        // a valid out-pointer. On success the allocation is handed straight to
        // `CredentialHandle`, so it can neither leak nor be freed twice.
        let ok = unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut raw) };
        if ok == 0 {
            // SAFETY: reads the calling thread's last-error code.
            let code = unsafe { GetLastError() };
            return if code == ERROR_NOT_FOUND {
                Ok(None)
            } else {
                Err(classify(code, item))
            };
        }
        if raw.is_null() {
            return Err(CredentialStoreError::Backend(
                "CredReadW reported success with a null credential".into(),
            ));
        }
        let handle = CredentialHandle(raw);
        let Some(blob) = handle.blob() else {
            return Err(CredentialStoreError::Backend(
                "CredReadW returned a null blob with a non-zero length".into(),
            ));
        };
        // Copied straight into a zeroizing owner: no ordinary `Vec<u8>` or
        // `String` intermediate exists anywhere on this path.
        let mut copied = Zeroizing::new(vec![0u8; blob.len()]);
        copied.copy_from_slice(blob);
        // Wipe and free BEFORE the length check, so a malformed entry cannot
        // return early past the wipe.
        drop(handle);
        require_32(item, copied).map(Some)
    }

    fn write(&self, item: SecretItem, secret: &[u8; 32]) -> Result<(), CredentialStoreError> {
        let mut target = self.target_name(item);
        let mut username: Vec<u16> = self
            .service
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut blob = Zeroizing::new(secret.to_vec());
        let credential = CREDENTIALW {
            Flags: 0,
            Type: CRED_TYPE_GENERIC,
            TargetName: target.as_mut_ptr(),
            Comment: std::ptr::null_mut(),
            // SAFETY: an all-zero FILETIME is a valid ignored input to
            // CredWriteW, which sets the real value itself.
            LastWritten: unsafe { std::mem::zeroed() },
            CredentialBlobSize: blob.len() as u32,
            CredentialBlob: blob.as_mut_ptr(),
            // ADR-0007 §2: local machine, never CRED_PERSIST_ENTERPRISE.
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            AttributeCount: 0,
            Attributes: std::ptr::null_mut(),
            TargetAlias: std::ptr::null_mut(),
            UserName: username.as_mut_ptr(),
        };
        // SAFETY: every pointer field points into a live local that outlives the
        // call, and `CredWriteW` copies what it needs before returning.
        let ok = unsafe { CredWriteW(&credential, 0) };
        if ok == 0 {
            // SAFETY: reads the calling thread's last-error code.
            return Err(classify(unsafe { GetLastError() }, item));
        }
        Ok(())
    }

    fn delete(&self, item: SecretItem) -> Result<(), CredentialStoreError> {
        let target = self.target_name(item);
        // SAFETY: `target` is NUL-terminated and outlives the call.
        let ok = unsafe { CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) };
        if ok == 0 {
            // SAFETY: reads the calling thread's last-error code.
            let code = unsafe { GetLastError() };
            // Absent is destruction's post-condition, so it is success.
            if code == ERROR_NOT_FOUND {
                return Ok(());
            }
            return Err(classify(code, item));
        }
        Ok(())
    }

    fn backend_name(&self) -> &'static str {
        "windows-credential-manager"
    }
}

/// `ERROR_ACCESS_DENIED`. Not re-exported by the `windows-sys` feature set in
/// use; pinning the numeric value is narrower than widening that feature set.
const ERROR_ACCESS_DENIED: u32 = 5;
/// `ERROR_INVALID_PARAMETER`.
const ERROR_INVALID_PARAMETER: u32 = 87;

fn classify(code: u32, item: SecretItem) -> CredentialStoreError {
    match code {
        ERROR_ACCESS_DENIED => CredentialStoreError::Inaccessible(item.item_name()),
        ERROR_INVALID_PARAMETER => CredentialStoreError::Backend(format!(
            "Windows Credential Manager rejected the request ({code})"
        )),
        other => CredentialStoreError::Backend(format!("Windows error {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Every test drives the REAL Credential Manager under a service identity
    /// that no production build ever uses, so a failed or interrupted run can
    /// never read or delete a live profile's secrets.
    fn isolated() -> NativeCredentialStore {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        NativeCredentialStore::with_isolated_service(format!(
            "Citadel-test-{}-{n}",
            std::process::id()
        ))
    }

    fn cleanup(store: &NativeCredentialStore) {
        for item in SecretItem::ALL {
            let _ = store.delete(item);
        }
    }

    #[test]
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

        store.delete(item).expect("delete");
        assert!(store.read(item).expect("read after delete").is_none());
        store
            .delete(item)
            .expect("deleting an absent entry is success");
        cleanup(&store);
    }

    #[test]
    fn absent_entry_reads_as_none_not_as_an_error() {
        let store = isolated();
        assert!(store
            .read(SecretItem::AccountIdentitySigningSeed)
            .expect("absent must not be an error")
            .is_none());
        cleanup(&store);
    }

    #[test]
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
        cleanup(&store);
    }

    #[test]
    fn a_wrong_length_entry_is_malformed_rather_than_truncated() {
        // Written through the raw API on purpose: the typed `write` cannot
        // produce this state, but a foreign writer or a corrupted store can, and
        // the contract is that it is refused rather than silently padded.
        let store = isolated();
        let item = SecretItem::DeviceSigningSeed;
        let mut target = store.target_name(item);
        let mut username: Vec<u16> = store
            .service
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut blob = vec![1u8; 16];
        let credential = CREDENTIALW {
            Flags: 0,
            Type: CRED_TYPE_GENERIC,
            TargetName: target.as_mut_ptr(),
            Comment: std::ptr::null_mut(),
            // SAFETY: as in `write`.
            LastWritten: unsafe { std::mem::zeroed() },
            CredentialBlobSize: blob.len() as u32,
            CredentialBlob: blob.as_mut_ptr(),
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            AttributeCount: 0,
            Attributes: std::ptr::null_mut(),
            TargetAlias: std::ptr::null_mut(),
            UserName: username.as_mut_ptr(),
        };
        // SAFETY: as in `write`.
        assert_ne!(unsafe { CredWriteW(&credential, 0) }, 0, "raw write");

        let result = store.read(item);
        cleanup(&store);
        assert!(
            matches!(
                result,
                Err(CredentialStoreError::Malformed { found: 16, .. })
            ),
            "a 16-byte entry must be Malformed, got {result:?}"
        );
    }

    #[test]
    fn production_store_uses_the_one_fixed_service_identity() {
        assert_eq!(NativeCredentialStore::new().service, SERVICE);
        assert_eq!(
            NativeCredentialStore::new().backend_name(),
            "windows-credential-manager"
        );
    }
}
