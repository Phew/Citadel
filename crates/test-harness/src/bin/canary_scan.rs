//! canary-scan: the no-plaintext scan (PLAN.md §10/§13; M1 exit requirement).
//!
//! Phase 1 (`inject`): push unique canary strings through client-facing
//! request paths where plaintext must never persist or be logged, and record
//! every attempt in a manifest.
//!
//! Phase 2 (`verify`): scan ALL server-side evidence — every PostgreSQL
//! table in the public schema and every captured container log stream — for
//! the manifest's canaries (raw, hex, and base64 encodings). A self-test
//! control canary is planted in a scratch table and a synthetic log line and
//! MUST be found, proving the scanner can actually detect before its "clean"
//! verdict means anything (§13: green means the property was exercised).
//!
//! Exit codes: 0 = clean and proven; 1 = canary found in evidence
//! (plaintext-handling bug); 2 = scan could not prove itself (infra down,
//! injection failed, control missed, or zero evidence coverage).
//!
//! Injection points cover the paths that exist in M1. Every new endpoint
//! that accepts client data MUST add an injection point here (see
//! docs/backlog.md for the M2+ message-path extension).

use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::process::ExitCode;
use test_harness::canary::{self, CanaryHit, CanaryManifest, CanaryRecord};
use test_harness::dbscan;
use test_harness::stack::{probe_client, require_stack, StackEndpoints};

const EXIT_CLEAN: u8 = 0;
const EXIT_VIOLATION: u8 = 1;
const EXIT_UNPROVEN: u8 = 2;

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some((command, rest)) = args.split_first() else {
        eprintln!("usage: canary-scan inject --out <manifest.json> | canary-scan verify --manifest <file> --logs <file>... [--report <file>]");
        return ExitCode::from(EXIT_UNPROVEN);
    };
    let result = match command.as_str() {
        "inject" => inject(rest).await.map(|_| Verdict::Clean),
        "verify" => verify(rest).await,
        other => {
            eprintln!("unknown subcommand {other:?}");
            return ExitCode::from(EXIT_UNPROVEN);
        }
    };
    match result {
        Ok(Verdict::Clean) => ExitCode::from(EXIT_CLEAN),
        Ok(Verdict::Violation) => ExitCode::from(EXIT_VIOLATION),
        Err(e) => {
            eprintln!("canary-scan could not prove its verdict: {e:#}");
            ExitCode::from(EXIT_UNPROVEN)
        }
    }
}

enum Verdict {
    Clean,
    Violation,
}

// ---------- inject ----------

async fn inject(args: &[String]) -> Result<()> {
    let out = flag_value(args, "--out").context("inject requires --out <manifest.json>")?;
    let http = probe_client()?;
    let endpoints = require_stack(&http).await?;

    let points = injection_points(&endpoints);
    let run_id = uuid::Uuid::new_v4().simple().to_string();
    let values = canary::generate(&run_id, points.len());
    let mut records = Vec::new();

    for (i, (point, request)) in points.into_iter().enumerate() {
        let value = values[i].clone();
        let status = match request {
            Probe::PostBody { base, path } => {
                let body =
                    serde_json::json!({ "canary": value, "note": "deliberate canary probe" });
                http.post(format!("{base}{path}"))
                    .json(&body)
                    .send()
                    .await
                    .with_context(|| format!("inject canary into {point}"))?
                    .status()
            }
            Probe::GetHeader { base, path } => http
                .get(format!("{base}{path}"))
                .header("x-citadel-canary", &value)
                .send()
                .await
                .with_context(|| format!("inject canary into {point}"))?
                .status(),
        };
        records.push(CanaryRecord {
            value,
            injection_point: point,
            http_status: status.as_u16(),
        });
    }

    let manifest = CanaryManifest {
        run_id,
        canaries: records,
    };
    std::fs::write(&out, serde_json::to_string_pretty(&manifest)?)
        .with_context(|| format!("write manifest {out}"))?;
    println!(
        "injected {} canaries (run {}); manifest at {out}",
        manifest.canaries.len(),
        manifest.run_id
    );
    Ok(())
}

enum Probe {
    PostBody { base: String, path: &'static str },
    GetHeader { base: String, path: &'static str },
}

/// One (description, request) pair per injection point. Canary channels are
/// bodies and headers ONLY: paths and query strings are request metadata
/// that standard middleware legitimately logs, so they are never canary
/// channels (a hit there would be a false positive by design).
fn injection_points(endpoints: &StackEndpoints) -> Vec<(String, Probe)> {
    let mut points = Vec::new();
    for (name, base) in endpoints.all() {
        points.push((
            format!("{name} POST /v1/canary-probe (body)"),
            Probe::PostBody {
                base: base.to_string(),
                path: "/v1/canary-probe",
            },
        ));
        points.push((
            format!("{name} GET /health (x-citadel-canary header)"),
            Probe::GetHeader {
                base: base.to_string(),
                path: "/health",
            },
        ));
    }
    points
}

// ---------- verify ----------

#[derive(Serialize)]
struct ScanReport {
    run_id: String,
    verdict: &'static str,
    db_tables_scanned: usize,
    db_rows_scanned: usize,
    log_files_scanned: usize,
    log_lines_scanned: usize,
    control_db_found: bool,
    control_log_found: bool,
    violations: Vec<CanaryHit>,
}

impl ScanReport {
    fn emit(&self, report_path: Option<&str>) -> Result<()> {
        let text = serde_json::to_string_pretty(self)?;
        println!("{text}");
        if let Some(p) = report_path {
            std::fs::write(p, &text).with_context(|| format!("write report {p}"))?;
        }
        Ok(())
    }
}

async fn verify(args: &[String]) -> Result<Verdict> {
    let manifest_path =
        flag_value(args, "--manifest").context("verify requires --manifest <file>")?;
    let log_paths = flag_values(args, "--logs");
    if log_paths.is_empty() {
        bail!("verify requires at least one --logs <file> (container log capture)");
    }
    let report_path = flag_value(args, "--report");

    let manifest: CanaryManifest = serde_json::from_str(
        &std::fs::read_to_string(&manifest_path)
            .with_context(|| format!("read manifest {manifest_path}"))?,
    )
    .context("parse manifest")?;
    if manifest.canaries.is_empty() {
        bail!("manifest has no canaries — injection never happened; verdict would be vacuous");
    }
    if !manifest.canaries.iter().all(|c| c.http_status > 0) {
        bail!("manifest records injections that got no HTTP response; verdict would be vacuous");
    }

    let pool = dbscan::connect().await?;

    // --- Self-test control: plant a detectable canary in a scratch table and
    // a synthetic log line. If the scanner can't find these, its "clean"
    // verdict is worthless and the run fails loudly.
    let control = format!("{}-{}-control", canary::CANARY_MARKER, manifest.run_id);
    sqlx::query("CREATE TABLE IF NOT EXISTS canary_scan_control (value text NOT NULL)")
        .execute(&pool)
        .await
        .context("create control table")?;
    sqlx::query("DELETE FROM canary_scan_control")
        .execute(&pool)
        .await
        .context("clear control table")?;
    sqlx::query(&format!(
        "INSERT INTO canary_scan_control (value) VALUES ({})",
        dbscan::sql_string_literal(&control)
    ))
    .execute(&pool)
    .await
    .context("plant control canary")?;

    let control_canaries = [control.clone()];
    let mut control_db_hits = Vec::new();
    dbscan::scan_all_tables(&pool, &control_canaries, &mut control_db_hits).await?;
    let control_db_found = control_db_hits
        .iter()
        .any(|h| h.location.starts_with("db table canary_scan_control"));

    let control_log_line = format!("canary-scan control log line: {control}\n");
    let mut control_log_hits = Vec::new();
    canary::scan_text(
        "control log",
        &control_log_line,
        &control_canaries,
        &mut control_log_hits,
    );
    let control_log_found = !control_log_hits.is_empty();

    // --- Evidence scan: manifest canaries over every table and log file.
    let evidence_canaries: Vec<String> =
        manifest.canaries.iter().map(|c| c.value.clone()).collect();
    let mut violations = Vec::new();
    let db_coverage = dbscan::scan_all_tables(&pool, &evidence_canaries, &mut violations).await?;

    let mut log_lines = 0usize;
    for path in &log_paths {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("read log capture {path}"))?;
        log_lines += text.lines().count();
        canary::scan_text(path, &text, &evidence_canaries, &mut violations);
    }

    // Best-effort cleanup of the control table before reporting.
    if let Err(e) = sqlx::query("DROP TABLE IF EXISTS canary_scan_control")
        .execute(&pool)
        .await
    {
        eprintln!("warning: could not drop control table: {e:#}");
    }

    let mut report = ScanReport {
        run_id: manifest.run_id.clone(),
        verdict: "unproven",
        db_tables_scanned: db_coverage.tables_scanned,
        db_rows_scanned: db_coverage.rows_scanned,
        log_files_scanned: log_paths.len(),
        log_lines_scanned: log_lines,
        control_db_found,
        control_log_found,
        violations,
    };

    // Coverage gates: a scan that saw nothing proves nothing.
    if report.db_tables_scanned == 0 || report.db_rows_scanned == 0 {
        report.emit(report_path.as_deref())?;
        bail!("DB scan covered zero tables/rows — no evidence, no verdict");
    }
    if report.log_lines_scanned == 0 {
        report.emit(report_path.as_deref())?;
        bail!("log captures contained zero lines — no evidence, no verdict");
    }
    if !report.control_db_found || !report.control_log_found {
        report.emit(report_path.as_deref())?;
        bail!(
            "control canary not detected (db: {}, log: {}) — scanner is broken, verdict would be vacuous",
            report.control_db_found,
            report.control_log_found
        );
    }

    if report.violations.is_empty() {
        report.verdict = "clean";
        report.emit(report_path.as_deref())?;
        println!(
            "canary scan CLEAN: {} canaries, {} tables/{} rows, {} log lines, controls proven",
            evidence_canaries.len(),
            report.db_tables_scanned,
            report.db_rows_scanned,
            report.log_lines_scanned
        );
        Ok(Verdict::Clean)
    } else {
        report.verdict = "violation";
        report.emit(report_path.as_deref())?;
        eprintln!(
            "canary scan found {} plaintext violation(s); see report",
            report.violations.len()
        );
        Ok(Verdict::Violation)
    }
}

// ---------- tiny arg helpers ----------

fn flag_value(args: &[String], flag: &str) -> Option<String> {
    flag_values(args, flag).into_iter().next()
}

fn flag_values(args: &[String], flag: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == flag {
            if let Some(v) = it.next() {
                out.push(v.clone());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoints() -> StackEndpoints {
        StackEndpoints {
            auth: "http://auth".into(),
            delivery: "http://delivery".into(),
            directory: "http://directory".into(),
            blobstore: "http://blobstore".into(),
        }
    }

    #[test]
    fn injection_points_cover_every_service_twice_with_unique_names() {
        let points = injection_points(&endpoints());
        assert_eq!(points.len(), 8, "4 services x 2 probes (body, header)");
        let mut names: Vec<&str> = points.iter().map(|(n, _)| n.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(
            names.len(),
            points.len(),
            "manifest injection-point names must be unique"
        );
    }

    #[test]
    fn injection_points_keep_canaries_out_of_urls() {
        // Hard convention: canaries travel in bodies and headers ONLY.
        // Paths/query strings are request metadata that standard middleware
        // legitimately logs (TraceLayer), so a canary there makes the scan
        // report a false violation. Paths must stay static and query-free.
        for (name, probe) in injection_points(&endpoints()) {
            let (base, path) = match &probe {
                Probe::PostBody { base, path } => (base, path),
                Probe::GetHeader { base, path } => (base, path),
            };
            assert!(
                base.starts_with("http"),
                "{name}: base {base} is not a service URL"
            );
            assert!(
                !path.contains(['?', '&', '#', '%']),
                "{name}: path {path} must be static and query-free"
            );
            assert!(
                matches!(*path, "/v1/canary-probe" | "/health"),
                "{name}: unexpected path {path}; new injection points extend this test"
            );
        }
    }

    #[test]
    fn flag_helpers_collect_repeated_and_first_values() {
        let args: Vec<String> = ["--logs", "a", "--logs", "b", "--report", "r"]
            .into_iter()
            .map(String::from)
            .collect();
        assert_eq!(flag_values(&args, "--logs"), vec!["a", "b"]);
        assert_eq!(flag_value(&args, "--logs"), Some("a".into()));
        assert_eq!(flag_value(&args, "--report"), Some("r".into()));
        assert_eq!(flag_value(&args, "--manifest"), None);
    }

    #[test]
    fn flag_value_at_end_without_value_is_absent() {
        let args: Vec<String> = ["--logs"].into_iter().map(String::from).collect();
        assert_eq!(flag_value(&args, "--logs"), None);
        // A token that looks like a flag is still consumed as a value; the
        // verify() stage's file reads then fail loudly, which is the
        // intended behavior for malformed invocations.
        let args: Vec<String> = ["--logs", "--report"]
            .into_iter()
            .map(String::from)
            .collect();
        assert_eq!(flag_value(&args, "--logs"), Some("--report".into()));
    }
}
