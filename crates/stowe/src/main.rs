mod binary;
mod cli;
mod commands;
mod ui;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use cli::{Cli, Command};
use dialoguer::Password;
use stowe_core::{Audit, KeychainVault, Manifest, SecretValue, Vault};

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

        Command::Export {
            output,
            plain,
            namespace,
        } => {
            let format = if plain {
                stowe_core::ExportFormat::EnvPlain
            } else {
                stowe_core::ExportFormat::Encrypted
            };

            let passphrase = if plain {
                None
            } else {
                let pass = dialoguer::Password::new()
                    .with_prompt("Passphrase for encrypted export")
                    .with_confirmation("Confirm passphrase", "Passphrases don't match")
                    .interact()
                    .context("reading passphrase")?;
                Some(pass)
            };

            let vault = open_vault()?;

            match output {
                Some(path) => {
                    stowe_core::export::export_to_path(
                        &vault,
                        &namespace,
                        format,
                        passphrase.as_deref(),
                        std::path::Path::new(&path),
                    )
                    .with_context(|| format!("writing export to {}", path))?;
                    eprintln!("wrote backup to {}", path);
                }
                None => {
                    if !plain {
                        return Err(anyhow!(
                            "encrypted export to stdout would dump binary; pass -o <path> instead"
                        ));
                    }
                    let bytes =
                        stowe_core::export::export_to_bytes(&vault, &namespace, format, None)
                            .context("building export")?;
                    use std::io::Write;
                    std::io::stdout().write_all(&bytes)?;
                }
            }
        }

        Command::Wipe { also_audit } => {
            use std::io::Write;
            eprint!("Type 'WIPE EVERYTHING' to confirm: ");
            std::io::stderr().flush().ok();
            let mut line = String::new();
            std::io::stdin()
                .read_line(&mut line)
                .context("reading confirmation")?;
            if line.trim() != "WIPE EVERYTHING" {
                return Err(anyhow!("confirmation phrase mismatch; aborting"));
            }

            let mut vault = open_vault()?;
            let audit = if also_audit {
                Some(stowe_core::Audit::open_default().context("opening audit log")?)
            } else {
                None
            };
            let report = stowe_core::wipe::wipe_all(&mut vault, audit.as_ref(), also_audit)
                .context("wiping vault")?;
            println!(
                "wiped {} namespaces, {} secrets, {} audit rows",
                report.namespaces_deleted, report.vars_deleted, report.audit_rows_deleted
            );
        }

        Command::Init { namespace, force } => {
            let cwd = std::env::current_dir().context("getting cwd")?;
            let manifest_path = cwd.join("stowe.toml");
            if manifest_path.exists() && !force {
                return Err(anyhow!(
                    "stowe.toml already exists at {}; pass --force to overwrite",
                    manifest_path.display()
                ));
            }

            let default_ns = cwd
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("project")
                .to_string();
            let ns = match namespace {
                Some(n) => n,
                None => dialoguer::Input::<String>::new()
                    .with_prompt("Namespace")
                    .default(default_ns)
                    .interact_text()
                    .context("reading namespace")?,
            };

            eprintln!("Enter required variable names, one per line. Empty line to finish.");
            let mut vars: Vec<String> = Vec::new();
            loop {
                let result = dialoguer::Input::<String>::new()
                    .with_prompt(format!("var #{}", vars.len() + 1))
                    .allow_empty(true)
                    .interact_text();
                match result {
                    Ok(entry) if entry.is_empty() => break,
                    Ok(entry) => vars.push(entry),
                    Err(dialoguer::Error::IO(e))
                        if e.kind() == std::io::ErrorKind::NotConnected =>
                    {
                        break
                    }
                    Err(e) => return Err(anyhow::anyhow!("{}", e)).context("reading var name"),
                }
            }

            let mut body = format!("namespace = \"{}\"\n", ns);
            if !vars.is_empty() {
                body.push_str("\n[vars]\n");
                for v in &vars {
                    body.push_str(&format!("{} = {{ required = true }}\n", v));
                }
            }

            std::fs::write(&manifest_path, body)
                .with_context(|| format!("writing {}", manifest_path.display()))?;
            println!(
                "wrote {} ({} vars declared)",
                manifest_path.display(),
                vars.len()
            );
        }

        Command::Bootstrap { biometric } => {
            let mode = match biometric.as_str() {
                "always" => stowe_core::BiometricMode::Always,
                "never" => stowe_core::BiometricMode::Never,
                other => return Err(anyhow!("unknown --biometric value: {}", other)),
            };

            let cwd = std::env::current_dir().context("getting cwd")?;
            let (manifest_path, manifest) = Manifest::find_from_or_err(&cwd)
                .with_context(|| format!("looking for stowe.toml from {}", cwd.display()))?;

            eprintln!("manifest: {}", manifest_path.display());
            eprintln!("namespace: {}", manifest.namespace);

            let mut vault = open_vault()?;

            let mut missing: Vec<&str> = Vec::new();
            for (name, spec) in &manifest.vars {
                if !spec.required {
                    continue;
                }
                match vault.get(&manifest.namespace, name) {
                    Ok(_) => {}
                    Err(stowe_core::Error::NotFound { .. }) => missing.push(name),
                    Err(e) => return Err(e).context("checking vault"),
                }
            }

            if missing.is_empty() {
                println!("nothing to do — all required vars are present");
                return Ok(());
            }

            eprintln!(
                "{} required var(s) missing; prompting for values:",
                missing.len()
            );
            for var in &missing {
                let value = Password::new()
                    .with_prompt(format!("Value for {}", var))
                    .interact()
                    .with_context(|| format!("reading value for {}", var))?;
                vault
                    .set_with_biometric(
                        &manifest.namespace,
                        var,
                        SecretValue::from_string(value),
                        mode,
                    )
                    .with_context(|| format!("storing {}", var))?;
                println!("stored {}", var);
            }
        }

        Command::Ui => {
            ui::launch::launch_ui().context("launching desktop UI")?;
        }
    }

    Ok(())
}
