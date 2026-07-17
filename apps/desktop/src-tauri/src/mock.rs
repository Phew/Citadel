//! MOCK citadel-core command surface for the Tauri host.
//!
//! This is **not** OpenMLS, **not** a network client, and **not** a real
//! session. It exists so the desktop shell and command bindings can land
//! before M1 services / real citadel-core are available.
//!
//! Labels and status fields are intentionally blunt so the UI cannot
//! silently present encryption, users, or backend availability.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageViewModel {
    pub local_id: String,
    pub group_id: String,
    pub sender_label: String,
    pub body: String,
    pub sent_at: String,
    pub is_mock: bool,
    pub encryption_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListConversationsResult {
    pub conversations: Vec<ConversationSummary>,
    pub status: CoreStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListMessagesResult {
    pub messages: Vec<MessageViewModel>,
    pub status: CoreStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendMockLocalResult {
    pub message: MessageViewModel,
    pub status: CoreStatus,
}

/// In-process mock store (fixtures + local composer drafts only).
#[derive(Default)]
pub struct MockStore {
    conversations: Vec<ConversationSummary>,
    messages: HashMap<String, Vec<MessageViewModel>>,
    local_seq: u64,
}

impl MockStore {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Process-wide mock state for Tauri commands.
pub struct MockState(pub Mutex<MockStore>);

impl MockState {
    pub fn new() -> Self {
        Self(Mutex::new(MockStore::new()))
    }
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

pub fn list_conversations(store: &MockStore) -> ListConversationsResult {
    ListConversationsResult {
        conversations: store.conversations.clone(),
        status: status(),
    }
}

pub fn list_messages(store: &MockStore, group_id: &str) -> ListMessagesResult {
    let messages = store
        .messages
        .get(group_id)
        .cloned()
        .unwrap_or_default();
    ListMessagesResult {
        messages,
        status: status(),
    }
}

pub fn send_mock_local(
    store: &mut MockStore,
    group_id: &str,
    body: &str,
) -> Result<SendMockLocalResult, String> {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return Err("Mock local send rejected empty body".into());
    }
    if !store.conversations.iter().any(|c| c.group_id == group_id) {
        return Err(
            "No conversation selected. Mock shell has no real groups; load mock fixtures or select a fixture row."
                .into(),
        );
    }

    store.local_seq += 1;
    let sent_at = chrono_like_now();
    let message = MessageViewModel {
        local_id: format!("mock-local-{}", store.local_seq),
        group_id: group_id.into(),
        sender_label: "[MOCK] local-composer".into(),
        body: trimmed.into(),
        sent_at: sent_at.clone(),
        is_mock: true,
        encryption_status: "unavailable".into(),
    };

    store
        .messages
        .entry(group_id.into())
        .or_default()
        .push(message.clone());

    if let Some(conv) = store
        .conversations
        .iter_mut()
        .find(|c| c.group_id == group_id)
    {
        let preview: String = trimmed.chars().take(80).collect();
        conv.last_preview = preview;
        conv.updated_at = Some(sent_at);
    }

    Ok(SendMockLocalResult {
        message,
        status: status(),
    })
}

pub fn load_mock_fixtures(store: &mut MockStore) -> ListConversationsResult {
    let now = chrono_like_now();
    let g1 = "mock-group-fixture-1";
    let g2 = "mock-group-fixture-2";

    store.conversations = vec![
        ConversationSummary {
            group_id: g1.into(),
            title: "[MOCK FIXTURE] Layout DM".into(),
            kind: "dm".into(),
            last_preview: "Mock preview — not a real message".into(),
            updated_at: Some(now.clone()),
            is_mock_fixture: true,
        },
        ConversationSummary {
            group_id: g2.into(),
            title: "[MOCK FIXTURE] Layout channel".into(),
            kind: "channel".into(),
            last_preview: String::new(),
            updated_at: None,
            is_mock_fixture: true,
        },
    ];

    store.messages.clear();
    store.messages.insert(
        g1.into(),
        vec![MessageViewModel {
            local_id: "mock-msg-1".into(),
            group_id: g1.into(),
            sender_label: "[MOCK] fixture-sender".into(),
            body: "This is mock layout copy. It was never encrypted or delivered.".into(),
            sent_at: now,
            is_mock: true,
            encryption_status: "unavailable".into(),
        }],
    );
    store.messages.insert(g2.into(), vec![]);
    store.local_seq = 0;

    list_conversations(store)
}

pub fn clear_mock_fixtures(store: &mut MockStore) -> ListConversationsResult {
    store.conversations.clear();
    store.messages.clear();
    store.local_seq = 0;
    list_conversations(store)
}

/// RFC3339-ish UTC timestamp without pulling chrono into the desktop package.
fn chrono_like_now() -> String {
    // Sufficient for mock fixture labels; not used as a security boundary.
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{secs}")
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
        let store = MockStore::new();
        let result = list_conversations(&store);
        assert!(result.conversations.is_empty());
        assert_eq!(result.status.backend, "unavailable");
        assert!(result.status.session.is_none());
    }

    #[test]
    fn fixtures_are_labeled_mock_not_real_users() {
        let mut store = MockStore::new();
        let listed = load_mock_fixtures(&mut store);
        assert!(!listed.conversations.is_empty());
        for c in &listed.conversations {
            assert!(c.is_mock_fixture);
            assert!(c.title.contains("[MOCK FIXTURE]"));
        }
        let msgs = list_messages(&store, "mock-group-fixture-1");
        for m in msgs.messages {
            assert!(m.is_mock);
            assert_eq!(m.encryption_status, "unavailable");
            assert!(m.sender_label.contains("[MOCK]"));
        }
    }

    #[test]
    fn mock_local_send_tags_unencrypted() {
        let mut store = MockStore::new();
        load_mock_fixtures(&mut store);
        let sent = send_mock_local(&mut store, "mock-group-fixture-1", "hello")
            .expect("send ok");
        assert!(sent.message.is_mock);
        assert_eq!(sent.message.encryption_status, "unavailable");
        assert!(sent.message.sender_label.contains("[MOCK]"));
        assert!(sent.status.session.is_none());
    }

    #[test]
    fn clear_returns_empty() {
        let mut store = MockStore::new();
        load_mock_fixtures(&mut store);
        let cleared = clear_mock_fixtures(&mut store);
        assert!(cleared.conversations.is_empty());
    }
}
