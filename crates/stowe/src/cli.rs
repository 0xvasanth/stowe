use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "stowe",
    version,
    about = "Local-first secrets vault (macOS Keychain).",
    long_about = None,
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Add or overwrite a secret. Prompts for the value (hidden).
    Add {
        /// Namespace (e.g. project name).
        namespace: String,
        /// Variable name (e.g. ANTHROPIC_API_KEY).
        var: String,
    },

    /// List namespaces, or variables within a single namespace.
    List {
        /// If provided, list variables in this namespace.
        namespace: Option<String>,
    },

    /// Print a secret to stdout. Use `stowe reveal <ns> <var>`.
    Reveal {
        /// Namespace (e.g. project name).
        namespace: String,
        /// Variable name (e.g. ANTHROPIC_API_KEY).
        var: String,
    },

    /// Open the desktop UI. Not yet implemented (M5).
    Ui,
}
