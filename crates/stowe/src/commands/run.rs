use std::path::Path;
use std::process;

use stowe_core::{
    Audit, ChildOutcome, CloseRun, Manifest, OpenRun, Outcome, Result, RunnerConfig, SecretValue,
    Vault,
};

/// Caller-supplied resolved binary information.
pub struct ResolvedBinary {
    pub path: String,
    pub argv: Vec<String>,
}

/// Run the `stowe run` flow:
///   - read the secrets named in `manifest.vars` from `vault`
///   - record a start row in `audit`
///   - spawn the child via `runner`
///   - close the audit row with the child's exit info
///
/// Returns the child's `ChildOutcome` so the caller can propagate the exit code.
pub fn run(
    vault: &dyn Vault,
    audit: &Audit,
    manifest: &Manifest,
    binary: &ResolvedBinary,
    manifest_path: &Path,
) -> Result<ChildOutcome> {
    let mut secret_env: Vec<(String, SecretValue)> = Vec::with_capacity(manifest.vars.len());
    let mut var_names_loaded: Vec<String> = Vec::with_capacity(manifest.vars.len());
    for (name, spec) in &manifest.vars {
        match vault.get(&manifest.namespace, name) {
            Ok(value) => {
                secret_env.push((name.clone(), value));
                var_names_loaded.push(name.clone());
            }
            Err(stowe_core::Error::NotFound { .. }) if !spec.required => {
                // optional var absent — skip.
            }
            Err(e) => {
                let _ = manifest_path; // hint for callers: useful in error messages
                return Err(e);
            }
        }
    }

    let pid = Some(process::id());
    let open_info = OpenRun {
        namespace: &manifest.namespace,
        var_names: &var_names_loaded,
        binary_path: &binary.path,
        binary_hash: None,
        pid,
        ppid: None,
        argv: &binary.argv,
        outcome: Outcome::Allowed,
        reason: None,
    };
    let audit_id = audit.open_run(&open_info)?;

    let cfg = RunnerConfig {
        binary_path: binary.path.clone(),
        args: binary.argv.clone(),
        secret_env,
        sandbox_profile: None,
    };
    let outcome = stowe_core::runner::run(cfg);

    let (close, propagated) = match outcome {
        Ok(child) => (
            CloseRun {
                duration_ms: Some(child.duration_ms),
                child_exit: child.exit_code,
            },
            Ok(child),
        ),
        Err(e) => (
            CloseRun {
                duration_ms: None,
                child_exit: None,
            },
            Err(e),
        ),
    };
    audit.close_run(audit_id, close)?;
    propagated
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use stowe_core::{InMemoryVault, VarSpec};
    use tempfile::tempdir;

    fn sv(s: &str) -> SecretValue {
        SecretValue::from_string(s.to_string())
    }

    fn populated_vault() -> InMemoryVault {
        let mut v = InMemoryVault::new();
        v.set("ns", "PRESENT", sv("a")).unwrap();
        v.set("ns", "ALSO_PRESENT", sv("b")).unwrap();
        v
    }

    fn make_manifest(required: &[(&str, bool)]) -> Manifest {
        let mut vars = BTreeMap::new();
        for (name, req) in required {
            vars.insert(
                name.to_string(),
                VarSpec {
                    required: *req,
                    description: None,
                },
            );
        }
        Manifest {
            namespace: "ns".into(),
            vars,
            policy: Default::default(),
        }
    }

    fn fresh_audit() -> (Audit, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        (Audit::open_at(dir.path().join("audit.db")).unwrap(), dir)
    }

    #[test]
    fn runs_child_with_present_vars_and_records_audit() {
        let vault = populated_vault();
        let (audit, _d) = fresh_audit();
        let manifest = make_manifest(&[("PRESENT", true), ("ALSO_PRESENT", false)]);
        let binary = ResolvedBinary {
            path: "/bin/sh".into(),
            argv: vec!["-c".into(), "exit 0".into()],
        };
        let outcome = run(
            &vault,
            &audit,
            &manifest,
            &binary,
            std::path::Path::new("./stowe.toml"),
        )
        .unwrap();
        assert_eq!(outcome.exit_code, Some(0));
        assert_eq!(audit.row_count().unwrap(), 1);
    }

    #[test]
    fn missing_required_var_errors_before_spawn() {
        let vault = InMemoryVault::new();
        let (audit, _d) = fresh_audit();
        let manifest = make_manifest(&[("NEEDED", true)]);
        let binary = ResolvedBinary {
            path: "/bin/sh".into(),
            argv: vec!["-c".into(), "exit 0".into()],
        };
        let result = run(
            &vault,
            &audit,
            &manifest,
            &binary,
            std::path::Path::new("./stowe.toml"),
        );
        assert!(matches!(result, Err(stowe_core::Error::NotFound { .. })));
        assert_eq!(audit.row_count().unwrap(), 0);
    }

    #[test]
    fn missing_optional_var_is_silently_skipped() {
        let mut vault = InMemoryVault::new();
        vault.set("ns", "PRESENT", sv("a")).unwrap();
        let (audit, _d) = fresh_audit();
        let manifest = make_manifest(&[("PRESENT", true), ("OPTIONAL_ABSENT", false)]);
        let binary = ResolvedBinary {
            path: "/bin/sh".into(),
            argv: vec!["-c".into(), "exit 0".into()],
        };
        let outcome = run(
            &vault,
            &audit,
            &manifest,
            &binary,
            std::path::Path::new("./stowe.toml"),
        )
        .unwrap();
        assert_eq!(outcome.exit_code, Some(0));
    }

    #[test]
    fn child_failure_still_closes_audit_row() {
        let vault = populated_vault();
        let (audit, _d) = fresh_audit();
        let manifest = make_manifest(&[("PRESENT", true)]);
        let binary = ResolvedBinary {
            path: "/bin/sh".into(),
            argv: vec!["-c".into(), "exit 7".into()],
        };
        let outcome = run(
            &vault,
            &audit,
            &manifest,
            &binary,
            std::path::Path::new("./stowe.toml"),
        )
        .unwrap();
        assert_eq!(outcome.exit_code, Some(7));
        let row_count = audit.row_count().unwrap();
        assert_eq!(row_count, 1);
    }
}
