mod binary;
mod cli;
mod commands;
#[allow(dead_code)]
mod ui;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use cli::{Cli, Command};
use dialoguer::Password;
use stowe_core::{Audit, KeychainVault, Manifest, SecretValue};

fn open_vault() -> Result<KeychainVault> {
    KeychainVault::open_default().context("opening Keychain vault")
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Add {
            namespace,
            var,
            biometric,
        } => {
            let value = Password::new()
                .with_prompt(format!("Value for stowe.{}/{}", namespace, var))
                .interact()
                .context("reading value")?;
            let mut vault = open_vault()?;
            let mode = match biometric.as_str() {
                "always" => stowe_core::BiometricMode::Always,
                "never" => stowe_core::BiometricMode::Never,
                other => return Err(anyhow!("unknown --biometric value: {}", other)),
            };
            vault
                .set_with_biometric(&namespace, &var, SecretValue::from_string(value), mode)
                .with_context(|| format!("storing stowe.{}/{}", namespace, var))?;
            println!("stored stowe.{}/{} (biometric: {:?})", namespace, var, mode);
        }

        Command::List { namespace } => {
            let vault = open_vault()?;
            match namespace {
                None => {
                    let summaries = commands::list::namespaces(&vault)?;
                    if summaries.is_empty() {
                        println!("(no namespaces)");
                    } else {
                        for s in summaries {
                            println!("{:<20} {} vars", s.namespace, s.var_count);
                        }
                    }
                }
                Some(ns) => {
                    let vars = commands::list::vars(&vault, &ns)?;
                    if vars.is_empty() {
                        println!("(no vars in namespace '{}')", ns);
                    } else {
                        for v in vars {
                            println!("{}", v);
                        }
                    }
                }
            }
        }

        Command::Reveal { namespace, var } => {
            let vault = open_vault()?;
            let value = commands::reveal::run(&vault, &namespace, &var)
                .with_context(|| format!("reading stowe.{}/{}", namespace, var))?;
            // Write raw bytes to stdout; safe for binary values.
            use std::io::Write;
            let mut out = std::io::stdout().lock();
            out.write_all(value.expose())?;
            out.flush()?;
        }

        Command::Run { argv } => {
            if argv.is_empty() {
                return Err(anyhow!("missing command after `stowe run`"));
            }
            let cwd = std::env::current_dir().context("getting cwd")?;
            let (manifest_path, manifest) = Manifest::find_from_or_err(&cwd)
                .with_context(|| format!("looking for stowe.toml from {}", cwd.display()))?;

            let bin_name = argv[0].clone();
            let resolved = binary::resolve(&bin_name)?;
            let rest_args = argv[1..].to_vec();

            // Verify the resolved binary against manifest.policy. On DenialReason,
            // write an audit row and exit 2.
            let verified = match binary::verify(resolved, rest_args, &manifest.policy)? {
                Ok(v) => v,
                Err(reason) => {
                    let msg = reason.human_message();
                    let audit = Audit::open_default().context("opening audit log")?;
                    let argv_for_audit: Vec<String> = argv.clone();
                    let bin_for_audit = match &reason {
                        binary::DenialReason::ExcludedPath { path, .. } => path.clone(),
                        binary::DenialReason::NotInAllowlist { basename, .. } => basename.clone(),
                        binary::DenialReason::Unsigned { path } => path.clone(),
                    };
                    let _ = audit.write_denial(
                        &manifest.namespace,
                        &bin_for_audit,
                        &argv_for_audit,
                        &msg,
                    );
                    eprintln!("stowe: denied: {}", msg);
                    std::process::exit(2);
                }
            };

            let vault = open_vault()?;
            let audit = Audit::open_default().context("opening audit log")?;
            let binary_info = commands::run::ResolvedBinary {
                path: verified.resolved_path,
                argv: verified.args,
            };
            let outcome =
                commands::run::run(&vault, &audit, &manifest, &binary_info, &manifest_path)
                    .with_context(|| {
                        format!(
                            "running `{}` for namespace `{}`",
                            bin_name, manifest.namespace
                        )
                    })?;
            // Signal-killed (exit_code = None) maps to exit 1.
            std::process::exit(outcome.exit_code.unwrap_or(1));
        }

        Command::Ui => {
            eprintln!("`stowe ui` not yet implemented (planned for M5).");
            std::process::exit(2);
        }
    }

    Ok(())
}
