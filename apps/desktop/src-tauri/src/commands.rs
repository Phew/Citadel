//! Tauri command bindings scaffold for the citadel-core API surface.
//!
//! M2: all commands delegate to the labeled mock in `mock.rs`.
//! M3: swap implementations to call real `citadel-core` (never call backend
//! services from the UI process directly).

use crate::mock::{self, ConversationSummary, CoreStatus};

/// Return core/session status. Mock always reports disconnected + no encryption claim.
#[tauri::command]
pub fn core_get_status() -> CoreStatus {
    mock::status()
}

/// List conversations. Mock default is empty (honest empty state).
#[tauri::command]
pub fn core_list_conversations() -> Vec<ConversationSummary> {
    mock::list_conversations()
}

/// Placeholder for real send. Mock rejects with a clear error so callers
/// cannot believe a network encrypt-and-deliver succeeded.
#[tauri::command]
pub fn core_send_message(_group_id: String, _body: String) -> Result<(), String> {
    Err(
        "MOCK: core_send_message is not implemented. \
         Real encrypt-and-deliver requires citadel-core (M3). \
         Use the frontend mock-local composer for UI-only exercise."
            .into(),
    )
}
