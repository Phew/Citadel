//! Operation identity, request fingerprints, the monotonic sequence, and the
//! bounded outcome ring (ADR-0007 §5).
//!
//! Every state-changing public core operation carries an opaque 16-byte
//! [`OperationId`] that **its caller** generates and retains before entering
//! the actor. The actor never assigns or substitutes one. That is not
//! bureaucracy: it is the only way a caller that dies between commit and result
//! delivery can ask, after restart, whether its own mutation applied.
//!
//! The ledger row and the mutation share one transaction, so an absent ledger
//! row is proof the mutation did not apply. That equivalence is the whole
//! crash-recovery argument, and it is why the ledger row is written inside the
//! atomic unit rather than alongside it.
//!
//! Retention is deliberately asymmetric:
//!
//! - **Ledger rows are never pruned.** They are what makes a replayed operation
//!   ID fail as expired instead of being applied a second time.
//! - **Outcome payloads are pruned** outside the newest 256 sequences, so a
//!   long-lived profile does not accumulate unbounded returned bytes.
//!
//! The cost is stated in ADR-0007's Consequences and is real: an old known
//! operation ID returns [`StoreError::OperationReceiptExpired`] rather than its
//! original result. Domain deduplication (delivery dedup keys, pending
//! transmission identities) lives in its own rows and is not pruned by this
//! ring.

use super::error::StoreError;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::random::OpenMlsRand;
use openmls_traits::types::HashType;
use rusqlite::{OptionalExtension, Transaction};
use serde::Serialize;

/// How many operation outcomes stay replayable.
pub const RETAINED_OUTCOMES: i64 = 256;

/// The domain prefix hashed into every request fingerprint. It exists so a
/// fingerprint can never collide with a hash of anything else Citadel computes,
/// including the storage codec's bytes.
const FINGERPRINT_DOMAIN: &[u8] = b"citadel-operation-request-v1";

/// A caller-generated 16-byte operation identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OperationId([u8; 16]);

impl OperationId {
    /// Generate one from the OS CSPRNG through the OpenMLS provider (INV-9).
    ///
    /// Callers generate and **retain** this before submitting the mutation. A
    /// transport adapter keeps it with its delivery identity; an interactive
    /// caller that intends to retry after restart must persist it itself.
    pub fn generate() -> Result<Self, StoreError> {
        let rand = RustCrypto::default();
        let bytes: [u8; 16] = rand.random_array().map_err(|error| {
            StoreError::Migration(format!("OS random source failed: {error:?}"))
        })?;
        Ok(Self(bytes))
    }

    /// Adopt an identifier the caller already holds, e.g. after a restart.
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The raw identifier.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// The kinds of state-changing operation the store serializes. Each is one of
/// ADR-0007 §5's atomic units.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationKind {
    /// Create a group: OpenMLS group state plus conversation.
    CreateGroup,
    /// Add members: pending OpenMLS state plus exact outbound commit and Welcome.
    AddMembers,
    /// Join from a Welcome: group state plus conversation and pending delivery.
    JoinFromWelcome,
    /// Send: advanced sender state, plaintext row, ciphertext, idempotency key.
    Send,
    /// Receive an application message: advanced receiver state plus the
    /// deduplicated plaintext row.
    ReceiveApplication,
    /// Receive a commit: merged group state plus received sequence metadata.
    ReceiveCommit,
    /// Accept a KT advancement: verified head plus the anti-rollback checkpoint.
    AcceptKtHead,
    /// Prepare a self-update: pending state plus exact outbound bytes.
    PrepareSelfUpdate,
    /// Confirm a prepared update: pending removal plus the OpenMLS merge.
    ConfirmSelfUpdate,
    /// Abort a prepared update: pending removal plus the OpenMLS rollback.
    AbortSelfUpdate,
}

impl OperationKind {
    /// The stable string written to the ledger. Not derived from the Rust
    /// identifier, so renaming a variant cannot silently change stored data.
    pub const fn as_str(self) -> &'static str {
        match self {
            OperationKind::CreateGroup => "create_group",
            OperationKind::AddMembers => "add_members",
            OperationKind::JoinFromWelcome => "join_from_welcome",
            OperationKind::Send => "send",
            OperationKind::ReceiveApplication => "receive_application",
            OperationKind::ReceiveCommit => "receive_commit",
            OperationKind::AcceptKtHead => "accept_kt_head",
            OperationKind::PrepareSelfUpdate => "prepare_self_update",
            OperationKind::ConfirmSelfUpdate => "confirm_self_update",
            OperationKind::AbortSelfUpdate => "abort_self_update",
        }
    }
}

/// The canonical fingerprint of one operation request.
///
/// Serializes the kind and every typed request field with the same pinned
/// deterministic JSON rules as the storage codec, prefixes the domain string,
/// and hashes with SHA-256 through the existing RustCrypto primitive (INV-10:
/// no Citadel-authored primitive).
pub fn fingerprint<R: Serialize>(kind: OperationKind, request: &R) -> Result<Vec<u8>, StoreError> {
    let ordered = serde_json::to_value(request)
        .map_err(|error| StoreError::Codec(super::codec::CodecError::Json(error)))?;
    let body = serde_json::to_vec(&ordered)
        .map_err(|error| StoreError::Codec(super::codec::CodecError::Json(error)))?;

    let mut input =
        Vec::with_capacity(FINGERPRINT_DOMAIN.len() + 1 + kind.as_str().len() + body.len());
    input.extend_from_slice(FINGERPRINT_DOMAIN);
    input.push(0x1f); // separator, so kind and body cannot run together
    input.extend_from_slice(kind.as_str().as_bytes());
    input.push(0x1f);
    input.extend_from_slice(&body);

    RustCrypto::default()
        .hash(HashType::Sha2_256, &input)
        .map_err(|error| StoreError::Migration(format!("sha-256 unavailable: {error:?}")))
}

/// What a matching, still-retained ledger row returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetainedOutcome {
    /// The typed result discriminator, e.g. `"sent"`.
    pub kind: String,
    /// The exact bytes the original call returned.
    pub bytes: Vec<u8>,
}

/// The result of checking an operation ID before doing any work.
#[derive(Debug)]
pub enum LedgerCheck {
    /// Not seen before; the caller may proceed with the mutation.
    Fresh,
    /// Seen, matching, and its outcome is still retained: return this and do
    /// **not** mutate.
    Replay(RetainedOutcome),
}

/// Look up `operation_id` and classify it. Never mutates.
pub fn check_operation(
    transaction: &Transaction<'_>,
    operation_id: OperationId,
    kind: OperationKind,
    request_fingerprint: &[u8],
) -> Result<LedgerCheck, StoreError> {
    let row = transaction
        .query_row(
            "SELECT kind, fingerprint, outcome_kind, outcome_bytes
               FROM citadel_operation_ledger WHERE operation_id = ?1",
            [operation_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                ))
            },
        )
        .optional()?;

    let Some((stored_kind, stored_fingerprint, outcome_kind, outcome_bytes)) = row else {
        return Ok(LedgerCheck::Fresh);
    };

    // A changed kind or changed request fields under the same ID is a caller
    // bug or an attack; either way it is refused without mutation.
    if stored_kind != kind.as_str() || stored_fingerprint != request_fingerprint {
        return Err(StoreError::OperationIdConflict);
    }

    match (outcome_kind, outcome_bytes) {
        (Some(kind), Some(bytes)) => Ok(LedgerCheck::Replay(RetainedOutcome { kind, bytes })),
        // The row proves the operation committed; the payload has been pruned.
        // Returning "expired" rather than re-applying is the point.
        _ => Err(StoreError::OperationReceiptExpired),
    }
}

/// Allocate the next sequence, write the ledger row and its outcome, then prune
/// outcome payloads outside the retained ring.
///
/// Called inside the same transaction as the mutation, so allocation, ledger
/// row, outcome, and mutation commit or roll back together.
pub fn record_outcome(
    transaction: &Transaction<'_>,
    operation_id: OperationId,
    kind: OperationKind,
    request_fingerprint: &[u8],
    outcome: &RetainedOutcome,
) -> Result<i64, StoreError> {
    let high_water: i64 = transaction.query_row(
        "SELECT high_water FROM citadel_operation_sequence WHERE id = 1",
        [],
        |row| row.get(0),
    )?;
    // Checked increment. i64::MAX is the representable ceiling in SQLite's
    // INTEGER, and ADR-0007 §5 requires exhaustion to fail closed rather than
    // wrap into a sequence that has already been used.
    let sequence = high_water
        .checked_add(1)
        .ok_or(StoreError::OperationSequenceExhausted)?;

    transaction.execute(
        "UPDATE citadel_operation_sequence SET high_water = ?1 WHERE id = 1",
        [sequence],
    )?;
    transaction.execute(
        "INSERT INTO citadel_operation_ledger
             (operation_id, sequence, kind, fingerprint, outcome_kind, outcome_bytes, committed_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            operation_id.as_bytes().as_slice(),
            sequence,
            kind.as_str(),
            request_fingerprint,
            outcome.kind,
            outcome.bytes,
            super::schema::now_unix_seconds(),
        ],
    )?;

    // Prune payloads only. The ledger rows stay so an old ID can still be
    // recognised and refused.
    transaction.execute(
        "UPDATE citadel_operation_ledger
            SET outcome_kind = NULL, outcome_bytes = NULL
          WHERE sequence <= ?1 AND outcome_kind IS NOT NULL",
        [sequence - RETAINED_OUTCOMES],
    )?;

    Ok(sequence)
}

/// The current high-water sequence, for evidence and diagnostics.
pub fn high_water(transaction: &Transaction<'_>) -> Result<i64, StoreError> {
    Ok(transaction.query_row(
        "SELECT high_water FROM citadel_operation_sequence WHERE id = 1",
        [],
        |row| row.get(0),
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;

    #[derive(Serialize)]
    struct Request {
        group: [u8; 4],
        body: Vec<u8>,
    }

    #[test]
    fn fingerprint_is_stable_and_field_sensitive() {
        let a = Request {
            group: [1, 2, 3, 4],
            body: vec![9],
        };
        let b = Request {
            group: [1, 2, 3, 4],
            body: vec![9],
        };
        let c = Request {
            group: [1, 2, 3, 4],
            body: vec![10],
        };
        let fa = fingerprint(OperationKind::Send, &a).expect("hash");
        let fb = fingerprint(OperationKind::Send, &b).expect("hash");
        let fc = fingerprint(OperationKind::Send, &c).expect("hash");
        assert_eq!(fa, fb);
        assert_ne!(fa, fc);
        assert_eq!(fa.len(), 32, "SHA-256");
    }

    #[test]
    fn fingerprint_separates_kind_from_body() {
        let request = Request {
            group: [0; 4],
            body: vec![],
        };
        assert_ne!(
            fingerprint(OperationKind::Send, &request).expect("hash"),
            fingerprint(OperationKind::ReceiveApplication, &request).expect("hash"),
            "the same request under a different kind must fingerprint differently"
        );
    }

    #[test]
    fn operation_ids_are_distinct() {
        let a = OperationId::generate().expect("csprng");
        let b = OperationId::generate().expect("csprng");
        assert_ne!(a, b);
        assert_ne!(a.as_bytes(), &[0u8; 16]);
    }

    #[test]
    fn operation_kind_strings_are_unique_and_stable() {
        let kinds = [
            OperationKind::CreateGroup,
            OperationKind::AddMembers,
            OperationKind::JoinFromWelcome,
            OperationKind::Send,
            OperationKind::ReceiveApplication,
            OperationKind::ReceiveCommit,
            OperationKind::AcceptKtHead,
            OperationKind::PrepareSelfUpdate,
            OperationKind::ConfirmSelfUpdate,
            OperationKind::AbortSelfUpdate,
        ];
        let mut seen = std::collections::HashSet::new();
        for kind in kinds {
            assert!(seen.insert(kind.as_str()), "duplicate: {}", kind.as_str());
        }
        assert_eq!(seen.len(), 10);
    }
}
