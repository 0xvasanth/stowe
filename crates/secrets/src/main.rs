mod cli;
mod commands;

use anyhow::{Context, Result};
use clap::Parser;
use cli::{Cli, Command};
use dialoguer::Password;
use secrets_core::{KeychainVault, SecretValue};

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Add { namespace, var } => {
            let value = Password::new()
                .with_prompt(format!("Value for secrets.{}/{}", namespace, var))
                .interact()
                .context("reading value")?;
            let mut vault = KeychainVault::open_default().context("opening Keychain vault")?;
            commands::add::run(&mut vault, &namespace, &var, SecretValue::from_string(value))
                .with_context(|| format!("storing secrets.{}/{}", namespace, var))?;
            println!("✓ Stored secrets.{}/{}", namespace, var);
        }

        Command::List { namespace } => {
            let vault = KeychainVault::open_default().context("opening Keychain vault")?;
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
            let vault = KeychainVault::open_default().context("opening Keychain vault")?;
            let value = commands::reveal::run(&vault, &namespace, &var)
                .with_context(|| format!("reading secrets.{}/{}", namespace, var))?;
            // Write raw bytes to stdout; safe for binary values.
            use std::io::Write;
            std::io::stdout().write_all(value.expose())?;
        }

        Command::Ui => {
            eprintln!("`secrets ui` not yet implemented (planned for M5).");
            std::process::exit(2);
        }
    }

    Ok(())
}
