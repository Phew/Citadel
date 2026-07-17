//! MOCK citadel-core command surface for the Tauri host.
//!
//! This is **not** OpenMLS, **not** a network client, and **not** a real
//! session. It exists so the desktop shell and command bindings can land
//! before M1 services / real citadel-core are available.
//!
//! Labels and status fields are intentionally blunt so the UI cannot
//! silently present encryption, users, or backend availability.

use serde::{Deserialize, Serialize};

pub const MOCK_LABEL: &str = "MOCK — not connected to citadel-core or backend services";
pub const MOCK_CORE_VERSION: &str = "mock-0.1.0 (not citadel-core)";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CoreStatus {
    /// Always `"mock"` in this scaffolding.
    pub mode: String,
    pub mock_label: String,
    /// Always `"unavailable"` — mock never dials services.
    pub backend: String,
    /// Always `None` — no real account.
    pub session: Option<SessionInfo>,
    /// Always `"unavailable"` — never claim E2E on the mock path (INV-5 UI).
    pub encryption_status: String,
    pub core_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionInfo {
    pub account_id: Option<String>,
    pub handle: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConversationSummary {
    pub group_id: String,
    pub title: String,
    pub kind: String,
    pub last_preview: String,
    pub updated_at: Option<String>,
    pub is_mock_fixture: bool,
}

pub fn status() -> CoreStatus {
    CoreStatus {
        mode: "mock".into(),
        mock_label: MOCK_LABEL.into(),
        backend: "unavailable".into(),
        session: None,
        encryption_status: "unavailable".into(),
        core_version: MOCK_CORE_VERSION.into(),
    }
}

/// Scaffolded command surface. Real citadel-core will replace these bodies
/// while keeping the same command names where possible.
pub fn list_conversations() -> Vec<ConversationSummary> {
    // Honest empty default — no fake inbox.
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_is_honest_mock() {
        let s = status();
        assert_eq!(s.mode, "mock");
        assert_eq!(s.backend, "unavailable");
        assert!(s.session.is_none());
        assert_eq!(s.encryption_status, "unavailable");
        assert!(s.mock_label.contains("MOCK"));
    }

    #[test]
    fn conversations_default_empty() {
        assert!(list_conversations().is_empty());
    }
}
