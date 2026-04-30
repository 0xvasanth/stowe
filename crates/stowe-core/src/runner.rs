//! Spawns a child process with secrets injected as environment variables.
//!
//! # OsString zeroize gap
//!
//! `std::process::Command` stores env values internally as `OsString`. When we
//! call `.env(name, value_as_str)`, the bytes get copied into Command's
//! internal map, which is NOT zeroized when Command drops. After spawn, the
//! child holds the canonical copy in its address space (which is fine — the
//! child needs the value), but our parent process has a parent-side `OsString`
//! copy that lingers in the heap until Command itself is dropped. The
//! mitigation is twofold: (a) drop our local secret-bearing vector immediately
//! after spawn, (b) the OsString in Command goes out of scope when `cmd` drops
//! at function return.

use std::process::{Command, ExitStatus};
use std::time::Instant;

use zeroize::Zeroizing;

use crate::error::Result;
use crate::secret_value::SecretValue;

/// Inputs for a single `runner::run` invocation.
pub struct RunnerConfig {
    /// Resolved binary to exec (e.g. `/opt/homebrew/bin/cargo`).
    pub binary_path: String,
    /// Arguments after the binary.
    pub args: Vec<String>,
    /// Secret env vars to inject into the child. Order is preserved; later
    /// entries overwrite earlier ones if names collide.
    pub secret_env: Vec<(String, SecretValue)>,
    /// Optional sandbox-exec profile text. When `Some(...)`, runner writes
    /// the profile to a 0600 tempfile and spawns `sandbox-exec -f <path>`.
    pub sandbox_profile: Option<String>,
}

/// Result of a child process run.
#[derive(Debug, Clone, Copy)]
pub struct ChildOutcome {
    /// Exit code of the child, or `None` if it was killed by a signal.
    pub exit_code: Option<i32>,
    /// Wall-clock duration in milliseconds.
    pub duration_ms: i64,
}

/// Execute `config.binary_path` with `config.args`, with `config.secret_env`
/// merged on top of the inherited environment. Blocks until the child exits.
/// Drops and zeroes the local secret-bearing vector after spawn.
pub fn run(mut config: RunnerConfig) -> Result<ChildOutcome> {
    let start = Instant::now();

    // Build the command. If a sandbox profile is set, write it to a 0600
    // tempfile and spawn `sandbox-exec -f <path>` instead. The tempfile is
    // held in `_profile_file` so its drop removes it after the child exits.
    let _profile_file: Option<tempfile::NamedTempFile>;
    let mut cmd = if let Some(profile_text) = &config.sandbox_profile {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let mut tmp = tempfile::Builder::new()
            .prefix("stowe-sandbox-")
            .suffix(".sb")
            .tempfile()
            .map_err(crate::error::Error::Io)?;
        tmp.as_file_mut()
            .write_all(profile_text.as_bytes())
            .map_err(crate::error::Error::Io)?;
        tmp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(crate::error::Error::Io)?;
        let mut sandbox_cmd = Command::new("/usr/bin/sandbox-exec");
        sandbox_cmd.arg("-f").arg(tmp.path());
        sandbox_cmd.arg(&config.binary_path);
        sandbox_cmd.args(&config.args);
        _profile_file = Some(tmp);
        sandbox_cmd
    } else {
        _profile_file = None;
        let mut plain = Command::new(&config.binary_path);
        plain.args(&config.args);
        plain
    };

    // Move secret bytes into a Zeroizing vector while we materialize the env
    // entries Command needs. Each value is wrapped so its heap bytes are
    // zeroed when the local vector drops.
    let mut local: Vec<(String, Zeroizing<Vec<u8>>)> = config
        .secret_env
        .drain(..)
        .map(|(k, v)| (k, Zeroizing::new(v.expose().to_vec())))
        .collect();

    for (key, val) in &local {
        // Command stores env values internally as OsString; the OsString
        // itself is NOT zeroized when Command drops. This is a known gap;
        // the mitigation is that the child holds the ground-truth copy and
        // our local buffer is dropped immediately after spawn.
        let s = std::str::from_utf8(val.as_slice()).map_err(|_| {
            crate::error::Error::Invalid(format!(
                "secret for {} contains non-UTF-8 bytes; binary secrets are not yet supported as env vars",
                key
            ))
        })?;
        cmd.env(key, s);
    }

    let mut child = cmd.spawn().map_err(crate::error::Error::Io)?;

    // Drop the local copy ASAP. clear() runs Drop on each Zeroizing<Vec<u8>>,
    // which is what wipes the secret bytes; the empty vec then deallocates
    // its capacity buffer at end-of-scope (no further secrets to zeroize).
    local.clear();

    let status: ExitStatus = child.wait().map_err(crate::error::Error::Io)?;
    let duration_ms = start.elapsed().as_millis() as i64;
    Ok(ChildOutcome {
        exit_code: status.code(),
        duration_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sv(s: &str) -> SecretValue {
        SecretValue::from_string(s.to_string())
    }

    /// `/bin/sh -c 'exit 0'` — basic happy path with one env var. Verifies
    /// the spawn pipeline survives an injected secret; injection *visibility*
    /// is asserted in `injected_var_is_visible_to_child`.
    #[test]
    fn happy_path_with_secret_env() {
        let outcome = run(RunnerConfig {
            binary_path: "/bin/sh".into(),
            args: vec!["-c".into(), "exit 0".into()],
            secret_env: vec![("FOO".into(), sv("bar"))],
            sandbox_profile: None,
        })
        .unwrap();
        assert_eq!(outcome.exit_code, Some(0));
        assert!(outcome.duration_ms >= 0);
    }

    #[test]
    fn child_exit_code_propagated() {
        let outcome = run(RunnerConfig {
            binary_path: "/bin/sh".into(),
            args: vec!["-c".into(), "exit 42".into()],
            secret_env: vec![],
            sandbox_profile: None,
        })
        .unwrap();
        assert_eq!(outcome.exit_code, Some(42));
    }

    /// sh -c '[ "$STOWE_TEST" = "expected-value" ]' returns 0 if equal.
    /// This is the real assertion: did our env injection reach the child?
    #[test]
    fn injected_var_is_visible_to_child() {
        let outcome = run(RunnerConfig {
            binary_path: "/bin/sh".into(),
            args: vec![
                "-c".into(),
                "[ \"$STOWE_TEST\" = \"expected-value\" ]".into(),
            ],
            secret_env: vec![("STOWE_TEST".into(), sv("expected-value"))],
            sandbox_profile: None,
        })
        .unwrap();
        assert_eq!(outcome.exit_code, Some(0));
    }

    #[test]
    fn missing_binary_returns_io_error() {
        let result = run(RunnerConfig {
            binary_path: "/nonexistent/binary/path".into(),
            args: vec![],
            secret_env: vec![],
            sandbox_profile: None,
        });
        assert!(matches!(result, Err(crate::error::Error::Io(_))));
    }

    #[test]
    fn non_utf8_secret_rejected() {
        // Construct a SecretValue with invalid UTF-8 bytes (a lone 0xFF).
        let bad = SecretValue::new(vec![0xFF, 0xFE, 0xFD]);
        let result = run(RunnerConfig {
            binary_path: "/bin/sh".into(),
            args: vec!["-c".into(), "exit 0".into()],
            secret_env: vec![("BAD".into(), bad)],
            sandbox_profile: None,
        });
        assert!(matches!(result, Err(crate::error::Error::Invalid(_))));
    }

    #[test]
    fn no_sandbox_profile_spawns_directly() {
        let outcome = run(RunnerConfig {
            binary_path: "/bin/sh".into(),
            args: vec!["-c".into(), "exit 0".into()],
            secret_env: vec![],
            sandbox_profile: None,
        })
        .unwrap();
        assert_eq!(outcome.exit_code, Some(0));
    }

    #[test]
    fn sandbox_profile_runs_via_sandbox_exec() {
        let profile = "(version 1)\n\
(deny default)\n\
(allow process-fork)\n\
(allow process-exec)\n\
(allow signal (target self))\n\
(allow mach-lookup)\n\
(allow sysctl-read)\n\
(allow file-read*)\n\
(allow file-write*\n\
  (subpath \"/private/tmp\")\n\
  (subpath \"/private/var/folders\"))\n"
            .to_string();
        let outcome = run(RunnerConfig {
            binary_path: "/bin/sh".into(),
            args: vec!["-c".into(), "exit 0".into()],
            secret_env: vec![],
            sandbox_profile: Some(profile),
        })
        .unwrap();
        assert_eq!(outcome.exit_code, Some(0));
    }

    #[test]
    fn sandbox_blocks_disallowed_file_write() {
        let profile = "(version 1)\n\
(deny default)\n\
(allow process-fork)\n\
(allow process-exec)\n\
(allow signal (target self))\n\
(allow mach-lookup)\n\
(allow sysctl-read)\n\
(allow file-read*)\n\
(allow file-write*\n\
  (subpath \"/private/tmp\")\n\
  (subpath \"/private/var/folders\"))\n"
            .to_string();
        let outcome = run(RunnerConfig {
            binary_path: "/bin/sh".into(),
            args: vec![
                "-c".into(),
                "! (echo blocked > /private/etc/stowe-test 2>/dev/null)".into(),
            ],
            secret_env: vec![],
            sandbox_profile: Some(profile),
        })
        .unwrap();
        assert_eq!(
            outcome.exit_code,
            Some(0),
            "sandbox should block writes to /private/etc"
        );
    }
}
