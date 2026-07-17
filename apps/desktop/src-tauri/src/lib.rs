//! Citadel desktop Tauri library (M2 mock shell).

mod commands;
mod mock;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![
            commands::core_get_status,
            commands::core_list_conversations,
            commands::core_send_message,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Citadel desktop");
}
