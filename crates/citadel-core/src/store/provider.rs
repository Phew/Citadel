//! The Citadel OpenMLS provider over an encrypted SQLite connection
//! (ADR-0007 §1).
//!
//! It combines two things that already exist and writes neither: OpenMLS's
//! `RustCrypto` for cryptography and randomness (INV-9, INV-10 — no MLS
//! primitive is replaced), and OpenMLS's published
//! `openmls_sqlite_storage::SqliteStorageProvider` for the versioned storage
//! trait. Alternative 4 rejected hand-writing that trait: a local duplicate
//! would create avoidable secret-deletion and upgrade risk in exactly the code
//! that deletes MLS secrets.
//!
//! ## Why it borrows the connection
//!
//! `SqliteStorageProvider<C, ConnectionRef: Borrow<Connection>>` accepts any
//! `ConnectionRef` that borrows a connection, and `rusqlite::Transaction`
//! dereferences to its connection. So a provider built from `&*transaction`
//! and the application's own statements execute inside **one caller-owned
//! transaction**, which is what makes ADR-0007 §5's atomic units atomic.
//!
//! ADR-0007 §1 is explicit that this is a type-level argument and not build
//! evidence. The evidence is
//! `store_provider_and_application_share_one_transaction` in `store::tests`,
//! which mutates both schemas inside one transaction and proves an injected
//! failure rolls both back together.

use super::codec::CitadelOpenMlsJsonCodecV1;
use openmls_rust_crypto::RustCrypto;
use openmls_sqlite_storage::SqliteStorageProvider;
use openmls_traits::OpenMlsProvider;
use rusqlite::Connection;

/// The OpenMLS storage provider bound to Citadel's pinned codec.
pub type CitadelStorage<'a> = SqliteStorageProvider<CitadelOpenMlsJsonCodecV1, &'a Connection>;

/// The provider passed to every OpenMLS call made inside a store transaction.
///
/// It is deliberately short-lived and borrows: there is no long-lived provider
/// object holding a connection, because ADR-0007 §5 makes the database the
/// source of truth and a long-lived in-memory group non-authoritative.
pub struct StoreProvider<'a> {
    crypto: RustCrypto,
    storage: CitadelStorage<'a>,
}

impl<'a> StoreProvider<'a> {
    /// Build a provider over a borrowed connection.
    ///
    /// Pass `&*transaction` to put OpenMLS's writes inside that transaction.
    pub fn new(connection: &'a Connection) -> Self {
        Self {
            crypto: RustCrypto::default(),
            storage: SqliteStorageProvider::new(connection),
        }
    }
}

impl<'a> OpenMlsProvider for StoreProvider<'a> {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    // `OpenMlsProvider` itself has no lifetime parameter, but an *impl* may,
    // and an associated type may use it. So the storage type carries the
    // connection borrow honestly and nothing here needs `unsafe`.
    type StorageProvider = CitadelStorage<'a>;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}
