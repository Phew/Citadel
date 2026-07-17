//! Stable API error taxonomy.
//!
//! Error codes are part of the wire contract. Do not renumber without an ADR.
//! Human-readable `message` is for operators/clients; machines key off `code`.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Machine-readable error codes shared by all services.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u16)]
pub enum ErrorCode {
    /// Catch-all for unexpected failures.
    Internal = 1000,
    /// Request body or query failed validation.
    InvalidRequest = 1001,
    /// Authentication missing or failed.
    Unauthorized = 1002,
    /// Authenticated but not permitted (spam hygiene only on server; INV-7).
    Forbidden = 1003,
    /// Resource not found.
    NotFound = 1004,
    /// Commit or other resource conflict (e.g. INV-6 epoch race → 409).
    Conflict = 1005,
    /// Rate limited.
    RateLimited = 1006,
    /// Unsupported wire or protocol version (INV-5: reject, never downgrade).
    UnsupportedVersion = 1007,
    /// KeyPackage already consumed or unavailable.
    KeyPackageUnavailable = 1100,
    /// KT proof verification failed at the client-facing boundary.
    KtProofInvalid = 1101,
    /// Franking proof failed verification (M6).
    FrankingInvalid = 1200,
}

impl ErrorCode {
    /// Suggested HTTP status for REST mapping.
    pub fn http_status(self) -> u16 {
        match self {
            Self::Internal => 500,
            Self::InvalidRequest => 400,
            Self::Unauthorized => 401,
            Self::Forbidden => 403,
            Self::NotFound => 404,
            Self::Conflict => 409,
            Self::RateLimited => 429,
            Self::UnsupportedVersion => 400,
            Self::KeyPackageUnavailable => 409,
            Self::KtProofInvalid => 400,
            Self::FrankingInvalid => 400,
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // serde rename_all is snake_case; keep Display stable for logs.
        let s = match self {
            Self::Internal => "internal",
            Self::InvalidRequest => "invalid_request",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::RateLimited => "rate_limited",
            Self::UnsupportedVersion => "unsupported_version",
            Self::KeyPackageUnavailable => "key_package_unavailable",
            Self::KtProofInvalid => "kt_proof_invalid",
            Self::FrankingInvalid => "franking_invalid",
        };
        write!(f, "{s}")
    }
}

/// JSON error body returned by services.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub code: ErrorCode,
    pub message: String,
    /// Optional opaque details for clients (never secret material).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl ErrorResponse {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            details: None,
        }
    }

    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_response_json_shape() {
        let err = ErrorResponse::new(ErrorCode::Conflict, "commit epoch taken");
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("conflict"));
        let back: ErrorResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back.code, ErrorCode::Conflict);
        assert_eq!(back.code.http_status(), 409);
    }
}
