//! Tauri 2 launcher for the Stowe desktop UI.
//!
//! The `stowe ui` subcommand calls `launch_ui()` which blocks until the
//! window is closed.

use anyhow::{Context, Result};

use super::commands;

/// Build the Tauri app and run the event loop. Blocks until the window
/// closes; returns `Ok(())` on clean exit.
pub fn launch_ui() -> Result<()> {
    tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            commands::list_namespaces_cmd,
            commands::list_vars_cmd,
            commands::recent_accesses_cmd,
            commands::reveal_secret_cmd,
            commands::add_secret_cmd,
            commands::delete_secret_cmd,
            commands::export_vault_cmd,
            commands::wipe_all_cmd,
        ])
        .run(tauri::generate_context!())
        .context("running Tauri event loop")?;
    Ok(())
}
