mod cli;
mod commands;

use anyhow::{Context, Result};
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
        Command::Add { namespace, var } => {
            let value = Password::new()
                .with_prompt(format!("Value for stowe.{}/{}", namespace, var))
                .interact()
                .context("reading value")?;
            let mut vault = open_vault()?;
            commands::add::run(
                &mut vault,
                &namespace,
                &var,
                SecretValue::from_string(value),
            )
            .with_context(|| format!("storing stowe.{}/{}", namespace, var))?;
            println!("stored stowe.{}/{}", namespace, var);
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

        Command::Run {
            manifest: manifest_path,
            binary,
            args,
        } => {
            let path = std::path::PathBuf::from(&manifest_path);
            let manifest = Manifest::load(&path)
                .with_context(|| format!("loading manifest '{}'", manifest_path))?;
            let vault = open_vault()?;
            let audit = Audit::open_default().context("opening audit log")?;
            let binary_info = commands::run::ResolvedBinary {
                path: binary,
                argv: args,
            };
            let outcome = commands::run::run(&vault, &audit, &manifest, &binary_info, &path)
                .context("running child process")?;
            if let Some(code) = outcome.exit_code {
                std::process::exit(code);
            }
        }

        Command::Ui => {
            eprintln!("`stowe ui` not yet implemented (planned for M5).");
            std::process::exit(2);
        }
    }

    Ok(())
}
