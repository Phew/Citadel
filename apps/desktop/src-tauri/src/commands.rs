//! Tauri command bindings scaffold for the citadel-core API surface.
//!
//! M2: all commands delegate to the labeled mock in `mock.rs`.
//! M3: swap implementations to call real `citadel-core` (never call backend
//! services from the UI process directly).

use crate::mock::{
    self, ListConversationsResult, ListMessagesResult, MockState, SendMockLocalResult,
    CoreStatus,
};
use tauri::State;

/// Return core/session status. Mock always reports disconnected + no encryption claim.
#[tauri::command]
pub fn core_get_status() -> CoreStatus {
    mock::status()
}

/// List conversations. Mock default is empty (honest empty state).
#[tauri::command]
pub fn core_list_conversations(state: State<'_, MockState>) -> Result<ListConversationsResult, String> {
    let store = state
        .0
        .lock()
        .map_err(|_| "mock store lock poisoned".to_string())?;
    Ok(mock::list_conversations(&store))
}

/// List messages for a group. Empty when no fixtures / no local drafts.
#[tauri::command]
pub fn core_list_messages(
    state: State<'_, MockState>,
    group_id: String,
) -> Result<ListMessagesResult, String> {
    let store = state
        .0
        .lock()
        .map_err(|_| "mock store lock poisoned".to_string())?;
    Ok(mock::list_messages(&store, &group_id))
}

/// Explicit mock-local composer path. Never encrypts or delivers.
#[tauri::command]
pub fn core_send_mock_local(
    state: State<'_, MockState>,
    group_id: String,
    body: String,
) -> Result<SendMockLocalResult, String> {
    let mut store = state
        .0
        .lock()
        .map_err(|_| "mock store lock poisoned".to_string())?;
    mock::send_mock_local(&mut store, &group_id, &body)
}

/// Load layout-only mock fixtures (labeled). Not real users or houses.
#[tauri::command]
pub fn core_load_mock_fixtures(
    state: State<'_, MockState>,
) -> Result<ListConversationsResult, String> {
    let mut store = state
        .0
        .lock()
        .map_err(|_| "mock store lock poisoned".to_string())?;
    Ok(mock::load_mock_fixtures(&mut store))
}

/// Clear fixtures back to honest empty/disconnected defaults.
#[tauri::command]
pub fn core_clear_mock_fixtures(
    state: State<'_, MockState>,
) -> Result<ListConversationsResult, String> {
    let mut store = state
        .0
        .lock()
        .map_err(|_| "mock store lock poisoned".to_string())?;
    Ok(mock::clear_mock_fixtures(&mut store))
}

/// Placeholder for real send. Mock rejects with a clear error so callers
/// cannot believe a network encrypt-and-deliver succeeded.
#[tauri::command]
pub fn core_send_message(_group_id: String, _body: String) -> Result<(), String> {
    Err(
        "MOCK: core_send_message is not implemented. \
         Real encrypt-and-deliver requires citadel-core (M3). \
         Use core_send_mock_local for UI-only exercise."
            .into(),
    )
}
