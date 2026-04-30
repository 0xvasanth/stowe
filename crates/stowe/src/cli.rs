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
        /// Biometric protection: "never" (dev default) or "always" (requires
        /// signed binary; will fail with errSecMissingEntitlement otherwise).
        #[arg(long, default_value = "never", value_parser = ["always", "never"])]
        biometric: String,
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

    /// Run a child command with secrets injected as env vars.
    /// Reads `stowe.toml` from the current dir or any ancestor.
    /// Usage: `stowe run <cmd> [args...]` or `stowe run -- <cmd> [args...]`.
    Run {
        /// Command and arguments. Hyphen-prefixed flags are forwarded to the child.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 1..)]
        argv: Vec<String>,
    },

    /// Open the desktop UI (read-only Vault view). Edit flows land in M5b.
    Ui,
}
