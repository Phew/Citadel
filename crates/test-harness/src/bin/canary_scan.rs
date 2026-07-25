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
//! Injection points cover the paths that exist in M1+M2 (M2: the
//! delivery-service message path, ADR-0005 — including an authenticated
//! probe that must die in `SubmitMessageRequest::validate`). Every new
//! endpoint that accepts client data MUST add an injection point here.

use anyhow::{bail, Context, Result};
use base64::Engine as _;
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

    // The authenticated message-path probe needs a real bearer token (the
    // submit endpoint validates auth before the body): register a throwaway
    // account/device and run the ADR-0003 §1–§2 flow. If this fails the run
    // is unproven, matching the fail-loudly convention.
    let delivery_token = delivery_probe_token(&http, &endpoints.auth).await?;

    let points = injection_points(&endpoints, &delivery_token);
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
            Probe::PostJson { base, path, body } => http
                .post(format!("{base}{path}"))
                .json(&body(&value))
                .send()
                .await
                .with_context(|| format!("inject canary into {point}"))?
                .status(),
            Probe::PostJsonAuthed {
                base,
                path,
                body,
                token,
            } => http
                .post(format!("{base}{path}"))
                .bearer_auth(token)
                .json(&body(&value))
                .send()
                .await
                .with_context(|| format!("inject canary into {point}"))?
                .status(),
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
    PostBody {
        base: String,
        path: &'static str,
    },
    /// Endpoint-shaped JSON body built from the canary value, for real
    /// endpoints whose inputs are rejected before storage (the canary must
    /// then provably appear nowhere).
    PostJson {
        base: String,
        path: &'static str,
        body: fn(&str) -> serde_json::Value,
    },
    /// Same as PostJson, but with a bearer token so the probe passes the
    /// endpoint's auth check and exercises what lies BEHIND it (the M2
    /// submit path's validation).
    PostJsonAuthed {
        base: String,
        path: &'static str,
        body: fn(&str) -> serde_json::Value,
        token: String,
    },
    GetHeader {
        base: String,
        path: &'static str,
    },
}

/// One (description, request) pair per injection point. Canary channels are
/// bodies and headers ONLY: paths and query strings are request metadata
/// that standard middleware legitimately logs, so they are never canary
/// channels (a hit there would be a false positive by design).
///
/// `delivery_token` is a real bearer token (see `delivery_probe_token`) for
/// the probe that must pass the submit endpoint's auth gate.
fn injection_points(endpoints: &StackEndpoints, delivery_token: &str) -> Vec<(String, Probe)> {
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

    // M1 auth-service endpoints (ADR-0003). Only REJECTED inputs carry
    // canaries here: the canary stands in for plaintext content, so it may
    // only flow through fields the server must never store — a scan hit
    // means rejected input was persisted. (A registration handle is stored
    // plaintext BY DESIGN — handles are public metadata, not content — so
    // the handle canary rides a 65-byte handle that ADR-0003 §6 rejects.)
    let auth = endpoints.auth.to_string();
    points.push((
        "auth-service POST /v1/accounts (65-byte handle, rejected)".to_string(),
        Probe::PostJson {
            base: auth.clone(),
            path: "/v1/accounts",
            body: |canary| {
                let b64 = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
                serde_json::json!({
                    // Canaries are [A-Za-z0-9-]; padding pushes past the
                    // 64-byte cap so registration MUST reject before storage.
                    "handle": format!("{canary}-{}", "x".repeat(64)),
                    "identity_pubkey": b64(&[0u8; 32]),
                    "first_device": {
                        "account_id": uuid::Uuid::nil(),
                        "device_id": uuid::Uuid::nil(),
                        "identity_pubkey": b64(&[0u8; 32]),
                        "device_pubkey": b64(&[0u8; 32]),
                        "issued_at": 0,
                        "signature": b64(&[0u8; 64]),
                    },
                })
            },
        },
    ));
    points.push((
        "auth-service POST /v1/auth/verify (client-sent challenge, never stored)".to_string(),
        Probe::PostJson {
            base: auth.clone(),
            path: "/v1/auth/verify",
            body: |canary| {
                serde_json::json!({
                    "device_id": uuid::Uuid::nil(),
                    // The client-sent challenge is compared, never stored.
                    "challenge": base64::engine::general_purpose::STANDARD.encode(canary),
                    "signature": base64::engine::general_purpose::STANDARD.encode([0u8; 64]),
                })
            },
        },
    ));
    points.push((
        "auth-service POST /v1/devices/<nil>/key-packages (101-package batch, rejected)"
            .to_string(),
        Probe::PostJson {
            base: auth.clone(),
            path: "/v1/devices/00000000-0000-0000-0000-000000000000/key-packages",
            body: |canary| {
                let pkg = base64::engine::general_purpose::STANDARD.encode(canary);
                // 101 > ADR-0003 §4's 100-package cap: rejected before the
                // store layer, so the canary bytes may never reach a table.
                serde_json::json!({ "packages": vec![pkg; 101] })
            },
        },
    ));
    points.push((
        "auth-service POST /v1/devices (endorsement signature, unauthenticated)".to_string(),
        Probe::PostJson {
            base: auth,
            path: "/v1/devices",
            body: |canary| {
                let b64 = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
                // Canary rides the endorsement signature field (padded to
                // the 64-byte shape). Enrollment is authenticated
                // (ADR-0004 §1), so with no bearer token this is rejected
                // before any storage — a scan hit means rejected bytes
                // were persisted.
                let mut sig = [0u8; 64];
                sig[..canary.len()].copy_from_slice(canary.as_bytes());
                serde_json::json!({
                    "credential": {
                        "account_id": uuid::Uuid::nil(),
                        "device_id": uuid::Uuid::nil(),
                        "identity_pubkey": b64(&[0u8; 32]),
                        "device_pubkey": b64(&[0u8; 32]),
                        "issued_at": 0,
                        "signature": b64(&[0u8; 64]),
                    },
                    "endorsement": {
                        "endorsing_device_id": uuid::Uuid::nil(),
                        "signature": b64(&sig),
                    },
                })
            },
        },
    ));

    // M2 delivery-service message path (ADR-0005; the no-plaintext canary
    // extends to group_messages/welcome_deliveries, ADR-0005 §2). Both
    // variants are rejected BEFORE the store layer, so a correct server
    // yields zero DB hits for them: the authenticated probe dies in
    // `SubmitMessageRequest::validate` (a pre-assigned seq is the server's
    // job, never the client's), the unauthenticated one at the 401 auth
    // gate. Only sloppy request-body logging could leak either canary.
    let delivery = endpoints.delivery.to_string();
    points.push((
        "delivery-service POST /v1/groups/<nil>/messages (pre-assigned seq, validate() rejects)"
            .to_string(),
        Probe::PostJsonAuthed {
            base: delivery.clone(),
            path: SUBMIT_PROBE_PATH,
            body: submit_probe_body,
            token: delivery_token.to_string(),
        },
    ));
    points.push((
        "delivery-service POST /v1/groups/<nil>/messages (unauthenticated, 401)".to_string(),
        Probe::PostJson {
            base: delivery,
            path: SUBMIT_PROBE_PATH,
            body: submit_probe_body,
        },
    ));
    points
}

/// The message-path probe path: a fixed nil group id keeps the path static
/// and query-free (canaries travel in bodies/headers only).
const SUBMIT_PROBE_PATH: &str = "/v1/groups/00000000-0000-0000-0000-000000000000/messages";

/// The message-path probe body (ADR-0005 §1): a SubmitMessageRequest whose
/// envelope carries a PRE-ASSIGNED seq, so `SubmitMessageRequest::validate`
/// MUST reject it with invalid_request before the store layer — the canary
/// riding `payload_b64` may then provably appear nowhere server-side.
fn submit_probe_body(canary: &str) -> serde_json::Value {
    serde_json::json!({
        "envelope": {
            "version": 1,
            "kind": "application",
            "group_id": uuid::Uuid::nil(),
            "epoch": 0,
            "seq": 7,
            "payload_b64": base64::engine::general_purpose::STANDARD.encode(canary),
        },
        "idempotency_key": uuid::Uuid::nil(),
    })
}

/// Register a throwaway account + first device and authenticate it
/// (ADR-0003 §1–§2, §6), so the authenticated message-path probe passes the
/// submit endpoint's auth gate and reaches the validation that must reject
/// it. Without this token the authenticated probe would be a second
/// unauthenticated probe and prove nothing new.
async fn delivery_probe_token(http: &reqwest::Client, auth_base: &str) -> Result<String> {
    use citadel_proto::auth::{
        challenge_signing_input, ChallengeRequest, ChallengeResponse, RegisterAccountRequest,
        RegisterAccountResponse, VerifyRequest, VerifyResponse,
    };
    use citadel_proto::credential::{
        DeviceCredential, DeviceCredentialTbs, DevicePublicKey, IdentityPublicKey, Signature,
    };
    use citadel_proto::ids::{AccountId, DeviceId};
    use test_harness::client::TestClient;
    use test_harness::testkeys::TestSigner;

    let client = TestClient::new(http.clone(), auth_base);
    let identity = TestSigner::from_seed([0xD1; 32]);
    let device_key = TestSigner::from_seed([0xD2; 32]);
    let tbs = DeviceCredentialTbs {
        account_id: AccountId::new(),
        device_id: DeviceId::new(),
        identity_pubkey: IdentityPublicKey(identity.public_key()),
        device_pubkey: DevicePublicKey(device_key.public_key()),
        issued_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before epoch")
            .as_secs() as i64,
    };
    let signature = Signature(identity.sign(&tbs.signing_input()));
    let req = RegisterAccountRequest {
        handle: format!("canary-probe-{}", uuid::Uuid::new_v4().simple()),
        identity_pubkey: tbs.identity_pubkey,
        first_device: DeviceCredential { tbs, signature },
    };
    let resp = client
        .post_json::<_, RegisterAccountResponse>("/v1/accounts", &req)
        .await
        .map_err(|e| anyhow::anyhow!("register canary-probe account: {e}"))?;
    let device_id = resp.device_id;

    let challenge = client
        .post_json::<_, ChallengeResponse>("/v1/auth/challenge", &ChallengeRequest { device_id })
        .await
        .map_err(|e| anyhow::anyhow!("canary-probe challenge: {e}"))?;
    let verify = client
        .post_json::<_, VerifyResponse>(
            "/v1/auth/verify",
            &VerifyRequest {
                device_id,
                challenge: challenge.challenge.clone(),
                signature: Signature(
                    device_key.sign(&challenge_signing_input(device_id, &challenge.challenge)),
                ),
            },
        )
        .await
        .map_err(|e| anyhow::anyhow!("canary-probe verify: {e}"))?;
    Ok(verify.token)
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
        let points = injection_points(&endpoints(), "test-token");
        assert_eq!(
            points.len(),
            14,
            "4 services x 2 probes (body, header) + 4 auth-service endpoint probes \
             + 2 delivery-service message-path probes (ADR-0005)"
        );
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
        for (name, probe) in injection_points(&endpoints(), "test-token") {
            let (base, path) = match &probe {
                Probe::PostBody { base, path } => (base, path),
                Probe::PostJson { base, path, .. } => (base, path),
                Probe::PostJsonAuthed { base, path, .. } => (base, path),
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
                matches!(
                    *path,
                    "/v1/canary-probe"
                        | "/health"
                        | "/v1/accounts"
                        | "/v1/auth/verify"
                        | "/v1/devices"
                        | "/v1/devices/00000000-0000-0000-0000-000000000000/key-packages"
                        | "/v1/groups/00000000-0000-0000-0000-000000000000/messages"
                ),
                "{name}: unexpected path {path}; new injection points extend this test"
            );
        }
    }

    #[test]
    fn endpoint_probe_bodies_embed_the_canary_where_rejection_is_required() {
        // The registration canary's handle must exceed ADR-0003 §6's 64-byte
        // cap; the publish probe must exceed §4's 100-package cap; the
        // message-path probe's envelope must carry a pre-assigned seq so
        // SubmitMessageRequest::validate rejects it (ADR-0005 §1). If any
        // invariant breaks, the canary could be legitimately stored and the
        // scan would false-positive — fail here instead.
        let points = injection_points(&endpoints(), "test-token");
        let bodies: Vec<serde_json::Value> = points
            .iter()
            .filter_map(|(_, p)| match p {
                Probe::PostJson { body, .. } => Some(body("CITADEL-CANARY-test-0001")),
                Probe::PostJsonAuthed { body, .. } => Some(body("CITADEL-CANARY-test-0001")),
                _ => None,
            })
            .collect();
        assert_eq!(bodies.len(), 6);
        for body in &bodies {
            if let Some(handle) = body.get("handle") {
                assert!(
                    handle.as_str().unwrap().len() > 64,
                    "handle canary must force the ADR-0003 §6 rejection"
                );
            }
            if let Some(packages) = body.get("packages") {
                assert!(
                    packages.as_array().unwrap().len() > 100,
                    "publish canary must force the ADR-0003 §4 rejection"
                );
            }
            if let Some(envelope) = body.get("envelope") {
                assert!(
                    envelope.get("seq").is_some_and(|s| s.is_number()),
                    "submit canary must force the ADR-0005 §1 validate() rejection"
                );
            }
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
