//! PostgreSQL evidence dump for the canary scan.
//!
//! Enumerates every base table in the `public` schema and renders each row
//! as text via `to_jsonb`, so the scan covers current AND future tables with
//! no per-table code. `bytea` renders as `\x<hex>` inside JSON — the canary
//! module's hex encoding catches plaintext hidden in binary columns.
//!
//! Coverage is part of the verdict: a scan that read zero tables or zero
//! rows proves nothing and must fail loudly (PLAN.md §13).

use anyhow::{Context, Result};
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};

use crate::canary::{scan_text, CanaryHit};

/// Admin connection for evidence scans. `CITADEL_DATABASE_URL` overrides the
/// compose default. This is a scanner credential, never used by services.
pub async fn connect() -> Result<PgPool> {
    let url = std::env::var("CITADEL_DATABASE_URL")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "postgres://citadel:citadel@127.0.0.1:5432/citadel".to_string());
    PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .context("connect to PostgreSQL for canary scan — is the stack up? Scans fail loudly without infrastructure")
}

/// What the DB scan covered.
#[derive(Clone, Debug, Default)]
pub struct DbCoverage {
    pub tables_scanned: usize,
    pub rows_scanned: usize,
}

/// All base tables in the public schema, deterministically ordered.
pub async fn list_tables(pool: &PgPool) -> Result<Vec<String>> {
    let rows = sqlx::query(
        "SELECT table_name FROM information_schema.tables \
         WHERE table_schema = 'public' AND table_type = 'BASE TABLE' \
         ORDER BY table_name",
    )
    .fetch_all(pool)
    .await
    .context("enumerate public tables")?;
    Ok(rows.iter().map(|r| r.get::<String, _>(0)).collect())
}

/// Scan every row of every public table for canaries. Returns coverage and
/// accumulates hits. Table names come from our own information_schema but
/// are quoted defensively regardless.
pub async fn scan_all_tables(
    pool: &PgPool,
    canaries: &[String],
    hits: &mut Vec<CanaryHit>,
) -> Result<DbCoverage> {
    let mut coverage = DbCoverage::default();
    for table in list_tables(pool).await? {
        coverage.tables_scanned += 1;
        let quoted = format!("\"{}\"", table.replace('"', "\"\""));
        let rows = sqlx::query(&format!("SELECT to_jsonb(t)::text FROM {quoted} t"))
            .fetch_all(pool)
            .await
            .with_context(|| format!("dump table {table}"))?;
        for (i, row) in rows.iter().enumerate() {
            coverage.rows_scanned += 1;
            let text: String = row.get(0);
            scan_text(
                &format!("db table {table} row {}", i + 1),
                &text,
                canaries,
                hits,
            );
        }
    }
    Ok(coverage)
}

/// Quote a SQL string literal (for the scanner's control-table writes).
pub fn sql_string_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}
