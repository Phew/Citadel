//! A credential-store double, for test configuration only.
//!
//! ADR-0007 §2 permits exactly one thing here: injecting success and error
//! states that a real backend produces rarely or not on demand — a locked
//! collection, a duplicate entry, a malformed blob, an unavailable service.
//! Everything else about the store contract is exercised against the real
//! backend.
//!
//! It is behind `cfg(any(test, feature = "testing"))`, so it is not in the
//! production dependency graph and cannot be selected at runtime by
//! configuration, an environment variable, or a fallback path.
//! [`CredentialStore::backend_name`] returns `"test-double"` so a release
//! conformance test can prove by *running* which backend it got, rather than by
//! reading the build configuration.

use super::{CredentialStore, CredentialStoreError, SecretItem};
use std::collections::HashMap;
use std::sync::Mutex;
use zeroize::Zeroizing;

/// What the double should do instead of succeeding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Injected {
    /// The backend service is not reachable.
    Unavailable,
    /// The item or collection is locked and not unlocked.
    Locked,
    /// More than one entry matched.
    Duplicate,
    /// The entry exists with the wrong length.
    Malformed(usize),
    /// The entry exists but may not be read.
    Inaccessible,
}

/// Which call the injection applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Call {
    /// [`CredentialStore::read`].
    Read,
    /// [`CredentialStore::write`].
    Write,
    /// [`CredentialStore::delete`].
    Delete,
}

#[derive(Default)]
struct State {
    entries: HashMap<SecretItem, [u8; 32]>,
    injections: HashMap<(SecretItem, Call), Injected>,
    reads: u32,
    writes: u32,
    deletes: u32,
}

/// An in-memory credential store for tests.
#[derive(Default)]
pub struct CredentialStoreDouble {
    state: Mutex<State>,
}

impl CredentialStoreDouble {
    /// An empty double: every item absent, nothing injected.
    pub fn new() -> Self {
        Self::default()
    }

    /// Pre-seed an item, as if a previous run had written it.
    pub fn seed(&self, item: SecretItem, secret: [u8; 32]) {
        self.state
            .lock()
            .expect("double")
            .entries
            .insert(item, secret);
    }

    /// Make the next and every subsequent `call` on `item` fail as `injected`.
    pub fn inject(&self, item: SecretItem, call: Call, injected: Injected) {
        self.state
            .lock()
            .expect("double")
            .injections
            .insert((item, call), injected);
    }

    /// Stop injecting for `item`/`call`.
    pub fn clear_injection(&self, item: SecretItem, call: Call) {
        self.state
            .lock()
            .expect("double")
            .injections
            .remove(&(item, call));
    }

    /// Whether an item is currently present.
    pub fn contains(&self, item: SecretItem) -> bool {
        self.state
            .lock()
            .expect("double")
            .entries
            .contains_key(&item)
    }

    /// `(reads, writes, deletes)`, so a test can prove that first-run creation
    /// wrote the key **and read it back** before installing the database.
    pub fn call_counts(&self) -> (u32, u32, u32) {
        let state = self.state.lock().expect("double");
        (state.reads, state.writes, state.deletes)
    }

    fn injected(&self, item: SecretItem, call: Call) -> Option<Injected> {
        self.state
            .lock()
            .expect("double")
            .injections
            .get(&(item, call))
            .cloned()
    }
}

fn to_error(injected: Injected, item: SecretItem) -> CredentialStoreError {
    match injected {
        Injected::Unavailable => CredentialStoreError::Unavailable("injected".into()),
        Injected::Locked => CredentialStoreError::Locked("injected".into()),
        Injected::Duplicate => CredentialStoreError::Duplicate(item.item_name()),
        Injected::Malformed(found) => CredentialStoreError::Malformed {
            item: item.item_name(),
            found,
        },
        Injected::Inaccessible => CredentialStoreError::Inaccessible(item.item_name()),
    }
}

impl CredentialStore for CredentialStoreDouble {
    fn read(&self, item: SecretItem) -> Result<Option<Zeroizing<[u8; 32]>>, CredentialStoreError> {
        self.state.lock().expect("double").reads += 1;
        if let Some(injected) = self.injected(item, Call::Read) {
            return Err(to_error(injected, item));
        }
        Ok(self
            .state
            .lock()
            .expect("double")
            .entries
            .get(&item)
            .map(|secret| Zeroizing::new(*secret)))
    }

    fn write(&self, item: SecretItem, secret: &[u8; 32]) -> Result<(), CredentialStoreError> {
        self.state.lock().expect("double").writes += 1;
        if let Some(injected) = self.injected(item, Call::Write) {
            return Err(to_error(injected, item));
        }
        self.state
            .lock()
            .expect("double")
            .entries
            .insert(item, *secret);
        Ok(())
    }

    fn delete(&self, item: SecretItem) -> Result<(), CredentialStoreError> {
        self.state.lock().expect("double").deletes += 1;
        if let Some(injected) = self.injected(item, Call::Delete) {
            return Err(to_error(injected, item));
        }
        self.state.lock().expect("double").entries.remove(&item);
        Ok(())
    }

    fn backend_name(&self) -> &'static str {
        "test-double"
    }
}
