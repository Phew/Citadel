//! Rewriting every codec-encoded provider value from one codec to another
//! (ADR-0007 §1).
//!
//! ADR-0007 §1: "A future codec migration must retain the old decoder, decode
//! every old provider row, encode it with the new codec, and update the
//! identifier last in one transaction." This module is that primitive. No
//! production path in a v1 build calls it, because v1 is the only codec a v1
//! build knows; `store::tests` drives it against a test v2 codec so the
//! mechanism is proven before a real v2 exists, rather than written under
//! release pressure when one does.
//!
//! # What is rewritten
//!
//! `openmls_sqlite_storage` 0.2.0 encodes **keys as well as entities** through
//! the [`Codec`] (its `wrappers.rs`: `KeyRefWrapper`, `EntityRefWrapper`,
//! `EntitySliceWrapper`), so every `BLOB` column of every provider table is
//! codec-encoded, primary keys included, and every one of them is rewritten.
//! [`PROVIDER_CODEC_COLUMNS`] pins that column set. Before touching a row the
//! migration compares the live schema against the pin: an upstream provider
//! release that adds a table or a blob column would otherwise leave rows in
//! the old codec behind a metadata row claiming the new one, which is exactly
//! the silent corruption ADR-0007 §1 exists to prevent. A mismatch fails
//! closed before the first `UPDATE`.
//!
//! # Intermediate representation
//!
//! Values cross between codecs as `serde_json::Value`, so both codecs must be
//! self-describing. A future codec that is not (a binary format without
//! embedded field names) needs a typed per-entity migration instead. That is
//! a new ADR, not a flag here.
//!
//! # Atomicity
//!
//! The caller owns the transaction. Every rewrite and the final metadata
//! update execute on it, so an error at any point (a value that does not
//! decode, an encoder failure, a schema mismatch) leaves the database exactly
//! as it was once the transaction is rolled back or dropped.
//! `store_codec_migration_failure_rolls_back_rows_and_identifier` in
//! `store::tests` is the evidence.

use super::codec::{CODEC_BOUND_VERSIONS, CODEC_ID};
use super::error::StoreError;
use super::schema::{meta_key, read_metadata};
use openmls_sqlite_storage::Codec;
use rusqlite::{Connection, ToSql, Transaction};
use std::collections::BTreeSet;
use zeroize::Zeroizing;

/// The identifier and bound-version tuple a codec writes to
/// `citadel_store_meta` (ADR-0007 §1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodecIdentity {
    /// The `codec_id` metadata value.
    pub id: &'static str,
    /// The `codec_bound_versions` metadata value.
    pub bound_versions: &'static str,
}

/// The identity of [`super::codec::CitadelOpenMlsJsonCodecV1`].
pub const CODEC_V1: CodecIdentity = CodecIdentity {
    id: CODEC_ID,
    bound_versions: CODEC_BOUND_VERSIONS,
};

/// The provider's own migration history table: the one `openmls_` table that
/// holds no codec-encoded value.
pub const PROVIDER_HISTORY_TABLE: &str = "openmls_sqlite_storage_migrations";

/// Every codec-encoded column in `openmls_sqlite_storage` 0.2.0's schema,
/// which is exactly its `BLOB` columns. Tables in name order.
pub const PROVIDER_CODEC_COLUMNS: &[(&str, &[&str])] = &[
    ("openmls_encryption_keys", &["public_key", "key_pair"]),
    (
        "openmls_epoch_keys_pairs",
        &["group_id", "epoch_id", "key_pairs"],
    ),
    ("openmls_group_data", &["group_id", "group_data"]),
    ("openmls_key_packages", &["key_package_ref", "key_package"]),
    ("openmls_own_leaf_nodes", &["group_id", "leaf_node"]),
    (
        "openmls_proposals",
        &["group_id", "proposal_ref", "proposal"],
    ),
    ("openmls_psks", &["psk_id", "psk_bundle"]),
    ("openmls_signature_keys", &["public_key", "signature_key"]),
];

/// What a completed migration rewrote.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CodecMigrationReport {
    /// Provider tables visited: always every pinned table, empty ones included.
    pub tables: usize,
    /// Rows rewritten.
    pub rows: usize,
    /// Individual values re-encoded across all rows and columns.
    pub values: usize,
}

/// Verify that the live provider schema is exactly the pinned one: the same
/// table set, and per table the same `BLOB` column set.
pub fn verify_provider_schema(connection: &Connection) -> Result<(), StoreError> {
    let live: BTreeSet<String> = {
        let mut statement = connection.prepare(
            "SELECT name FROM sqlite_master
             WHERE type = 'table' AND substr(name, 1, 8) = 'openmls_'",
        )?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        rows.collect::<Result<_, _>>()?
    };
    let mut pinned: BTreeSet<String> = PROVIDER_CODEC_COLUMNS
        .iter()
        .map(|(table, _)| (*table).to_string())
        .collect();
    pinned.insert(PROVIDER_HISTORY_TABLE.to_string());
    if live != pinned {
        return Err(StoreError::CodecMigration(format!(
            "provider tables differ from the pinned schema: live {live:?}, pinned {pinned:?}"
        )));
    }

    for (table, columns) in PROVIDER_CODEC_COLUMNS {
        let blob_columns: BTreeSet<String> = {
            let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
            let rows = statement.query_map([], |row| {
                Ok((row.get::<_, String>(1)?, row.get::<_, String>(2)?))
            })?;
            rows.collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .filter(|(_, declared)| declared.eq_ignore_ascii_case("BLOB"))
                .map(|(name, _)| name)
                .collect()
        };
        let pinned_columns: BTreeSet<String> =
            columns.iter().map(|column| (*column).to_string()).collect();
        if blob_columns != pinned_columns {
            return Err(StoreError::CodecMigration(format!(
                "{table}: blob columns differ from the pinned codec columns: \
                 live {blob_columns:?}, pinned {pinned_columns:?}"
            )));
        }
    }
    Ok(())
}

/// Rewrite every provider value from `From` to `To` inside `transaction`,
/// then update the codec identity **last**.
///
/// The database must currently claim `from`; anything else is refused before
/// any row is read. Returns what was rewritten so a caller can assert the
/// count it expected rather than trusting an `Ok`.
pub fn migrate_codec<From: Codec, To: Codec>(
    transaction: &Transaction<'_>,
    from: CodecIdentity,
    to: CodecIdentity,
) -> Result<CodecMigrationReport, StoreError> {
    if from == to {
        return Err(StoreError::CodecMigration(
            "source and target codec identities are equal".into(),
        ));
    }

    // 1. The store must be in the codec the caller says it is in.
    let live_id = read_metadata(transaction, meta_key::CODEC_ID)?;
    if live_id.as_deref() != Some(from.id) {
        return Err(StoreError::UnsupportedCodec {
            found: live_id.unwrap_or_else(|| "<absent>".into()),
            expected: from.id.to_string(),
        });
    }
    let live_bound = read_metadata(transaction, meta_key::CODEC_BOUND_VERSIONS)?;
    if live_bound.as_deref() != Some(from.bound_versions) {
        return Err(StoreError::UnsupportedCodec {
            found: live_bound.unwrap_or_else(|| "<absent>".into()),
            expected: from.bound_versions.to_string(),
        });
    }

    // 2. The schema must be the one this pin enumerates.
    verify_provider_schema(transaction)?;

    // 3. Rewrite every value of every row. Rows are read fully before any
    //    update so no cursor is open over a table being modified.
    let mut report = CodecMigrationReport::default();
    for (table, columns) in PROVIDER_CODEC_COLUMNS {
        report.tables += 1;
        let select = format!(
            "SELECT rowid, {} FROM {table} ORDER BY rowid",
            columns.join(", ")
        );
        let rows: Vec<(i64, Vec<Zeroizing<Vec<u8>>>)> = {
            let mut statement = transaction.prepare(&select)?;
            let rows = statement.query_map([], |row| {
                let rowid: i64 = row.get(0)?;
                let mut blobs = Vec::with_capacity(columns.len());
                for index in 0..columns.len() {
                    blobs.push(Zeroizing::new(row.get::<_, Vec<u8>>(index + 1)?));
                }
                Ok((rowid, blobs))
            })?;
            rows.collect::<Result<_, _>>()?
        };

        let assignments = columns
            .iter()
            .enumerate()
            .map(|(index, column)| format!("{column} = ?{}", index + 1))
            .collect::<Vec<_>>()
            .join(", ");
        let update = format!(
            "UPDATE {table} SET {assignments} WHERE rowid = ?{}",
            columns.len() + 1
        );
        let mut statement = transaction.prepare(&update)?;

        for (rowid, blobs) in rows {
            let mut rewritten: Vec<Zeroizing<Vec<u8>>> = Vec::with_capacity(blobs.len());
            for (column, bytes) in columns.iter().zip(blobs.iter()) {
                let value: serde_json::Value = From::from_slice(bytes).map_err(|error| {
                    StoreError::CodecMigration(format!(
                        "{table}.{column} rowid {rowid}: {} decode: {error}",
                        from.id
                    ))
                })?;
                let encoded = To::to_vec(&value).map_err(|error| {
                    StoreError::CodecMigration(format!(
                        "{table}.{column} rowid {rowid}: {} encode: {error}",
                        to.id
                    ))
                })?;
                rewritten.push(Zeroizing::new(encoded));
                report.values += 1;
            }
            let mut params: Vec<&dyn ToSql> = rewritten
                .iter()
                .map(|bytes| &**bytes as &dyn ToSql)
                .collect();
            params.push(&rowid);
            let changed = statement.execute(params.as_slice())?;
            if changed != 1 {
                return Err(StoreError::CodecMigration(format!(
                    "{table} rowid {rowid}: update changed {changed} rows"
                )));
            }
            report.rows += 1;
        }
    }

    // 4. The identity moves last, so a store that is interrupted anywhere
    //    above still claims (and still is) `from`.
    for (key, value) in [
        (meta_key::CODEC_ID, to.id),
        (meta_key::CODEC_BOUND_VERSIONS, to.bound_versions),
    ] {
        let changed = transaction.execute(
            "UPDATE citadel_store_meta SET value = ?2 WHERE key = ?1",
            rusqlite::params![key, value],
        )?;
        if changed != 1 {
            return Err(StoreError::CodecMigration(format!(
                "metadata row {key} was not updated ({changed} rows changed)"
            )));
        }
    }
    Ok(report)
}
