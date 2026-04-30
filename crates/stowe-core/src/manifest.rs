use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const MANIFEST_FILENAME: &str = "stowe.toml";

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct VarSpec {
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum BiometricMode {
    /// Touch ID required for every read of this item.
    #[default]
    Always,
    /// No biometric guard. Item readable without prompting.
    Never,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SandboxPolicy {
    /// If true, `stowe run` wraps the child via `sandbox-exec`.
    #[serde(default)]
    pub enabled: bool,

    /// Hostnames (with optional ports) the child may connect to.
    /// Examples: "registry.npmjs.org", "github.com:443".
    /// Validated against `^[a-zA-Z0-9.\-*:]+$`.
    #[serde(default)]
    pub network_allow: Vec<String>,

    /// Paths the child may write to, beyond project root + system tempdirs.
    /// `~/...` is expanded against the user's home.
    /// Validated against `^[a-zA-Z0-9._/~-]+$`.
    #[serde(default)]
    pub fs_write_allow: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default)]
    pub biometric: BiometricMode,

    /// Basename allowlist for `stowe run`. Empty list = no restriction.
    #[serde(default)]
    pub allowed_binaries: Vec<String>,

    /// If true, `stowe run` accepts unsigned child binaries. Default: false.
    #[serde(default)]
    pub allow_unsigned: bool,

    #[serde(default)]
    pub sandbox: SandboxPolicy,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            biometric: BiometricMode::Always,
            allowed_binaries: Vec::new(),
            allow_unsigned: false,
            sandbox: Default::default(),
        }
    }
}

/// Per-project manifest. Schema is closed (`deny_unknown_fields`) so future
/// additions (policy, etc.) are explicit version bumps rather than silent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub namespace: String,

    #[serde(default)]
    pub vars: BTreeMap<String, VarSpec>,

    #[serde(default)]
    pub policy: Policy,
}

impl Manifest {
    /// Load and parse a manifest at `path`. Returns `Error::Io` if the file
    /// cannot be read, `Error::Toml` on parse failure, `Error::Invalid` if
    /// the namespace is empty.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let text = std::fs::read_to_string(path.as_ref())?;
        let manifest: Manifest = toml::from_str(&text).map_err(|e| Error::Toml(e.to_string()))?;
        if manifest.namespace.is_empty() {
            return Err(Error::Invalid(
                "manifest namespace must be non-empty".into(),
            ));
        }
        Ok(manifest)
    }

    /// Walk from `start` upward looking for a `stowe.toml` file. Returns the
    /// resolved absolute path and parsed manifest, or `Ok(None)` if no
    /// manifest is found before reaching the filesystem root.
    ///
    /// `start` must exist on disk — `canonicalize` is called immediately
    /// and returns `Error::Io` if the path does not exist.
    pub fn find_from(start: impl AsRef<Path>) -> Result<Option<(PathBuf, Self)>> {
        let start = start.as_ref().canonicalize()?;
        let mut cur: &Path = &start;
        loop {
            let candidate = cur.join(MANIFEST_FILENAME);
            if candidate.is_file() {
                let manifest = Self::load(&candidate)?;
                return Ok(Some((candidate, manifest)));
            }
            match cur.parent() {
                Some(parent) => cur = parent,
                None => return Ok(None),
            }
        }
    }

    /// Convenience: like `find_from` but returns `Error::ManifestNotFound`
    /// instead of `Ok(None)` for the not-found case.
    pub fn find_from_or_err(start: impl AsRef<Path>) -> Result<(PathBuf, Self)> {
        let start_ref = start.as_ref();
        Self::find_from(start_ref)?.ok_or_else(|| Error::ManifestNotFound {
            start: start_ref.display().to_string(),
        })
    }

    /// Names of all variables marked `required = true`.
    pub fn required_vars(&self) -> Vec<&str> {
        self.vars
            .iter()
            .filter(|(_, spec)| spec.required)
            .map(|(name, _)| name.as_str())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write_manifest(dir: &Path, body: &str) -> PathBuf {
        let path = dir.join(MANIFEST_FILENAME);
        std::fs::write(&path, body).unwrap();
        path
    }

    #[test]
    fn parses_minimal_manifest() {
        let dir = tempdir().unwrap();
        write_manifest(dir.path(), "namespace = \"cognis\"\n");
        let m = Manifest::load(dir.path().join(MANIFEST_FILENAME)).unwrap();
        assert_eq!(m.namespace, "cognis");
        assert!(m.vars.is_empty());
    }

    #[test]
    fn parses_full_manifest() {
        let body = r#"
namespace = "cognis"

[vars]
ANTHROPIC_API_KEY = { required = true, description = "Anthropic API key" }
OPENAI_API_KEY    = { required = false }
DATABASE_URL      = { required = true }
"#;
        let dir = tempdir().unwrap();
        write_manifest(dir.path(), body);
        let m = Manifest::load(dir.path().join(MANIFEST_FILENAME)).unwrap();
        assert_eq!(m.namespace, "cognis");
        assert_eq!(m.vars.len(), 3);
        let anthropic = m.vars.get("ANTHROPIC_API_KEY").unwrap();
        assert!(anthropic.required);
        assert_eq!(anthropic.description.as_deref(), Some("Anthropic API key"));
        let openai = m.vars.get("OPENAI_API_KEY").unwrap();
        assert!(!openai.required);
        assert!(openai.description.is_none());
    }

    #[test]
    fn empty_namespace_rejected() {
        let dir = tempdir().unwrap();
        write_manifest(dir.path(), "namespace = \"\"\n");
        let err = Manifest::load(dir.path().join(MANIFEST_FILENAME)).unwrap_err();
        assert!(matches!(err, Error::Invalid(_)));
    }

    #[test]
    fn unknown_top_level_field_rejected() {
        let body = r#"
namespace = "cognis"
unknown_field = "value"
"#;
        let dir = tempdir().unwrap();
        write_manifest(dir.path(), body);
        let err = Manifest::load(dir.path().join(MANIFEST_FILENAME)).unwrap_err();
        assert!(matches!(err, Error::Toml(_)));
    }

    #[test]
    fn missing_file_returns_io_error() {
        let dir = tempdir().unwrap();
        let err = Manifest::load(dir.path().join("nonexistent.toml")).unwrap_err();
        assert!(matches!(err, Error::Io(_)));
    }

    #[test]
    fn required_vars_filters_correctly() {
        let body = r#"
namespace = "cognis"

[vars]
A = { required = true }
B = { required = false }
C = { required = true }
"#;
        let dir = tempdir().unwrap();
        write_manifest(dir.path(), body);
        let m = Manifest::load(dir.path().join(MANIFEST_FILENAME)).unwrap();
        let mut req = m.required_vars();
        req.sort();
        assert_eq!(req, vec!["A", "C"]);
    }

    #[test]
    fn find_from_locates_in_starting_dir() {
        let dir = tempdir().unwrap();
        write_manifest(dir.path(), "namespace = \"cognis\"\n");
        let result = Manifest::find_from(dir.path()).unwrap();
        let (found_path, m) = result.expect("manifest should be found");
        assert_eq!(found_path.file_name().unwrap(), MANIFEST_FILENAME);
        assert_eq!(m.namespace, "cognis");
    }

    #[test]
    fn find_from_walks_up_to_ancestor() {
        let dir = tempdir().unwrap();
        write_manifest(dir.path(), "namespace = \"top\"\n");
        let nested = dir.path().join("sub").join("deeper");
        std::fs::create_dir_all(&nested).unwrap();
        let result = Manifest::find_from(&nested).unwrap();
        let (_, m) = result.expect("manifest should be found in ancestor");
        assert_eq!(m.namespace, "top");
    }

    #[test]
    fn find_from_or_err_returns_error_when_absent() {
        let dir = tempdir().unwrap();
        let nested = dir.path().join("isolated");
        std::fs::create_dir_all(&nested).unwrap();
        // Tolerate the case where some test-environment ancestor of /tmp
        // happens to have a stowe.toml — that's unusual; if it happens,
        // skip the assertion.
        if Manifest::find_from(&nested).unwrap().is_none() {
            let err = Manifest::find_from_or_err(&nested).unwrap_err();
            assert!(matches!(err, Error::ManifestNotFound { .. }));
        }
    }

    #[test]
    fn parses_manifest_with_policy_section() {
        let body = r#"
namespace = "cognis"

[vars]
KEY = { required = true }

[policy]
biometric = "always"
allowed_binaries = ["cargo", "node", "npm"]
allow_unsigned = false
"#;
        let dir = tempdir().unwrap();
        write_manifest(dir.path(), body);
        let m = Manifest::load(dir.path().join(MANIFEST_FILENAME)).unwrap();
        assert_eq!(m.policy.biometric, BiometricMode::Always);
        assert_eq!(m.policy.allowed_binaries, vec!["cargo", "node", "npm"]);
        assert!(!m.policy.allow_unsigned);
    }

    #[test]
    fn manifest_without_policy_uses_defaults() {
        let body = "namespace = \"cognis\"\n";
        let dir = tempdir().unwrap();
        write_manifest(dir.path(), body);
        let m = Manifest::load(dir.path().join(MANIFEST_FILENAME)).unwrap();
        assert_eq!(m.policy.biometric, BiometricMode::Always);
        assert!(m.policy.allowed_binaries.is_empty());
        assert!(!m.policy.allow_unsigned);
    }

    #[test]
    fn biometric_mode_parses_lowercase() {
        let body = r#"
namespace = "cognis"

[policy]
biometric = "never"
"#;
        let dir = tempdir().unwrap();
        write_manifest(dir.path(), body);
        let m = Manifest::load(dir.path().join(MANIFEST_FILENAME)).unwrap();
        assert_eq!(m.policy.biometric, BiometricMode::Never);
    }

    #[test]
    fn unknown_policy_field_rejected() {
        let body = r#"
namespace = "cognis"

[policy]
biometric = "always"
unknown_field = "value"
"#;
        let dir = tempdir().unwrap();
        write_manifest(dir.path(), body);
        let err = Manifest::load(dir.path().join(MANIFEST_FILENAME)).unwrap_err();
        assert!(matches!(err, Error::Toml(_)));
    }

    #[test]
    fn parses_manifest_with_sandbox_policy() {
        let body = r#"
namespace = "cognis"

[policy.sandbox]
enabled = true
network_allow = ["registry.npmjs.org", "github.com:443"]
fs_write_allow = ["~/.npm", "~/Library/Caches"]
"#;
        let dir = tempdir().unwrap();
        write_manifest(dir.path(), body);
        let m = Manifest::load(dir.path().join(MANIFEST_FILENAME)).unwrap();
        assert!(m.policy.sandbox.enabled);
        assert_eq!(
            m.policy.sandbox.network_allow,
            vec!["registry.npmjs.org", "github.com:443"]
        );
        assert_eq!(
            m.policy.sandbox.fs_write_allow,
            vec!["~/.npm", "~/Library/Caches"]
        );
    }

    #[test]
    fn manifest_without_sandbox_section_uses_disabled_default() {
        let body = "namespace = \"cognis\"\n";
        let dir = tempdir().unwrap();
        write_manifest(dir.path(), body);
        let m = Manifest::load(dir.path().join(MANIFEST_FILENAME)).unwrap();
        assert!(!m.policy.sandbox.enabled);
        assert!(m.policy.sandbox.network_allow.is_empty());
        assert!(m.policy.sandbox.fs_write_allow.is_empty());
    }

    #[test]
    fn unknown_sandbox_field_rejected() {
        let body = r#"
namespace = "cognis"

[policy.sandbox]
enabled = true
unknown_field = "value"
"#;
        let dir = tempdir().unwrap();
        write_manifest(dir.path(), body);
        let err = Manifest::load(dir.path().join(MANIFEST_FILENAME)).unwrap_err();
        assert!(matches!(err, Error::Toml(_)));
    }
}
