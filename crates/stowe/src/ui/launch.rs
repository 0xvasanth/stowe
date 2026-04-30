//! Tauri 2 launcher for the Stowe desktop UI.
//!
//! The `stowe ui` subcommand calls `launch_ui()` which blocks until the
//! window is closed. Tauri commands (read-only in M5a) are registered in
//! Task 3 (`ui::commands`).

use anyhow::{Context, Result};

/// Build the Tauri app and run the event loop. Blocks until the window
/// closes; returns `Ok(())` on clean exit.
pub fn launch_ui() -> Result<()> {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .context("running Tauri event loop")?;
    Ok(())
}
