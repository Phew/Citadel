//! Canary plaintext generation, injection bookkeeping, and encoding-aware
//! matching for the no-plaintext scan (PLAN.md §10, §13).
//!
//! A canary is a unique, greppable string that stands in for plaintext
//! message content. The harness pushes canaries through client-facing paths
//! where plaintext must never persist or be logged; the scan then asserts
//! the canaries appear in NO server table or log stream. Any hit is a
//! plaintext-handling bug (INV-1 adjacent).
//!
//! Canary charset is `[A-Za-z0-9-]` on purpose: the value survives JSON,
//! URL, and header transport unchanged, so encoding variants stay exact.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};

/// Every produced canary carries this marker so scan hits are unambiguous.
pub const CANARY_MARKER: &str = "CITADEL-CANARY";

/// One injected canary and where it was pushed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanaryRecord {
    /// The canary plaintext (client-side only; never written to server state
    /// by a correct system).
    pub value: String,
    /// Human-readable injection point, e.g. "auth-service POST /v1/accounts (body)".
    pub injection_point: String,
    /// HTTP status the service returned for the injection request.
    pub http_status: u16,
}

/// Manifest written by `canary-scan inject`, consumed by `verify`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanaryManifest {
    /// Unique run id; embedded in every canary value for per-run isolation.
    pub run_id: String,
    pub canaries: Vec<CanaryRecord>,
}

/// Generate `count` canary values for a run.
pub fn generate(run_id: &str, count: usize) -> Vec<String> {
    (0..count)
        .map(|i| format!("{CANARY_MARKER}-{run_id}-{i:04}"))
        .collect()
}

/// The byte patterns the scan searches for, per canary. A buggy server might
/// store or log the value raw, hex-encoded (PostgreSQL `bytea` renders as
/// `\x<hex>` in JSON dumps), or base64-encoded; all three must be caught.
pub fn encodings(value: &str) -> [String; 3] {
    let hex: String = value.bytes().map(|b| format!("{b:02x}")).collect();
    [value.to_string(), hex, B64.encode(value)]
}

/// One canary match in scanned evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanaryHit {
    pub canary: String,
    /// Which encoding matched: "raw", "hex", or "base64".
    pub encoding: String,
    /// Evidence location: "db table accounts row 3", "log file canary-logs.txt line 412".
    pub location: String,
}

const ENCODING_NAMES: [&str; 3] = ["raw", "hex", "base64"];

/// Scan a block of text for every canary in all encodings.
/// `location_of` maps a 1-based line number to a human location string.
pub fn scan_text(source: &str, text: &str, canaries: &[String], hits: &mut Vec<CanaryHit>) {
    for (line_no, line) in text.lines().enumerate() {
        for canary in canaries {
            for (i, enc) in encodings(canary).iter().enumerate() {
                if line.contains(enc.as_str()) {
                    hits.push(CanaryHit {
                        canary: canary.clone(),
                        encoding: ENCODING_NAMES[i].to_string(),
                        location: format!("{source} line {}", line_no + 1),
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canaries_are_unique_marked_and_transport_safe() {
        let values = generate("runxyz", 3);
        assert_eq!(values.len(), 3);
        for v in &values {
            assert!(v.starts_with(CANARY_MARKER));
            assert!(v.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
        }
        let mut dedup = values.clone();
        dedup.dedup();
        assert_eq!(values, dedup);
    }

    #[test]
    fn encodings_cover_raw_hex_and_base64() {
        let v = "CITADEL-CANARY-run-0000";
        let [raw, hex, b64] = encodings(v);
        assert_eq!(raw, v);
        assert_eq!(
            hex,
            v.bytes().map(|b| format!("{b:02x}")).collect::<String>()
        );
        assert_eq!(B64.decode(&b64).unwrap(), v.as_bytes());
    }

    #[test]
    fn scan_text_finds_each_encoding_once() {
        let canaries = vec!["CITADEL-CANARY-t-0001".to_string()];
        let text = format!(
            "raw log {0}\nbytea dump \\x{1}\nwrapped {2}\n",
            canaries[0],
            canaries[0]
                .bytes()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            B64.encode(&canaries[0]),
        );
        let mut hits = Vec::new();
        scan_text("test.log", &text, &canaries, &mut hits);
        assert_eq!(hits.len(), 3, "one hit per encoding, got {hits:?}");
        assert!(hits
            .iter()
            .any(|h| h.encoding == "raw" && h.location == "test.log line 1"));
        assert!(hits.iter().any(|h| h.encoding == "hex"));
        assert!(hits.iter().any(|h| h.encoding == "base64"));
    }

    #[test]
    fn scan_text_ignores_clean_text_and_other_runs() {
        let canaries = vec!["CITADEL-CANARY-mine-0000".to_string()];
        let mut hits = Vec::new();
        scan_text(
            "clean.log",
            "ordinary ciphertext aGVsbG8= and another run CITADEL-CANARY-other-0000\n",
            &canaries,
            &mut hits,
        );
        assert!(hits.is_empty());
    }

    #[test]
    fn manifest_roundtrips_json() {
        let m = CanaryManifest {
            run_id: "r1".into(),
            canaries: vec![CanaryRecord {
                value: "CITADEL-CANARY-r1-0000".into(),
                injection_point: "auth POST /v1/x (body)".into(),
                http_status: 404,
            }],
        };
        let json = serde_json::to_string(&m).unwrap();
        assert_eq!(serde_json::from_str::<CanaryManifest>(&json).unwrap(), m);
    }
}
