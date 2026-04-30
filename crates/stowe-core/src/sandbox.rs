//! Generate `sandbox-exec` profiles from a `SandboxPolicy`.
//!
//! Output is Apple's TinyScheme-like `.sb` syntax. Profile uses
//! `(deny default)` then overrides with `(allow ...)` rules.
//! Inputs from the manifest pass through tight character-class validation
//! to prevent profile-syntax injection.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::manifest::SandboxPolicy;

fn is_valid_hostname(host: &str) -> bool {
    !host.is_empty()
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '*' | ':'))
}

fn is_valid_path_entry(p: &str) -> bool {
    !p.is_empty()
        && p.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '/' | '-' | '_' | '~'))
}

fn expand_path(entry: &str, home_dir: &Path) -> Result<PathBuf> {
    if !is_valid_path_entry(entry) {
        return Err(Error::Invalid(format!(
            "fs_write_allow entry contains disallowed characters: {:?}",
            entry
        )));
    }
    let expanded = if let Some(rest) = entry.strip_prefix("~/") {
        home_dir.join(rest)
    } else if entry == "~" {
        home_dir.to_path_buf()
    } else {
        PathBuf::from(entry)
    };
    if !expanded.is_absolute() {
        return Err(Error::Invalid(format!(
            "fs_write_allow entry must resolve to absolute path: {:?}",
            entry
        )));
    }
    Ok(expanded)
}

fn host_to_remote_clause(host: &str) -> String {
    if host.contains(':') {
        format!("(remote tcp \"{}\")", host)
    } else {
        format!("(remote tcp \"{}:443\")", host)
    }
}

/// Generate a sandbox-exec profile from `policy`.
///
/// `project_root` must be absolute (typically the directory containing
/// `stowe.toml`). `home_dir` is used to expand `~/...` entries.
pub fn generate_profile(
    policy: &SandboxPolicy,
    project_root: &Path,
    home_dir: &Path,
) -> Result<String> {
    if !project_root.is_absolute() {
        return Err(Error::Invalid("project_root must be absolute".into()));
    }
    for host in &policy.network_allow {
        if !is_valid_hostname(host) {
            return Err(Error::Invalid(format!(
                "network_allow entry contains disallowed characters: {:?}",
                host
            )));
        }
    }

    let mut out = String::new();
    out.push_str("(version 1)\n");
    out.push_str("(deny default)\n\n");

    out.push_str("(allow process-fork)\n");
    out.push_str("(allow process-exec)\n");
    out.push_str("(allow signal (target self))\n");
    out.push_str("(allow mach-lookup)\n");
    out.push_str("(allow sysctl-read)\n\n");

    out.push_str("(allow file-read*)\n\n");

    out.push_str("(allow file-write*\n");
    out.push_str(&format!("  (subpath \"{}\")\n", project_root.display()));
    out.push_str("  (subpath \"/private/tmp\")\n");
    out.push_str("  (subpath \"/private/var/folders\")\n");
    for entry in &policy.fs_write_allow {
        let expanded = expand_path(entry, home_dir)?;
        out.push_str(&format!("  (subpath \"{}\")\n", expanded.display()));
    }
    out.push_str(")\n\n");

    if policy.network_allow.is_empty() {
        out.push_str(";; no network allowlist; default-deny applies\n");
    } else {
        out.push_str("(allow network-outbound\n");
        for host in &policy.network_allow {
            out.push_str(&format!("  {}\n", host_to_remote_clause(host)));
        }
        out.push_str(")\n");
        out.push_str("(allow network-outbound\n");
        out.push_str("  (remote udp \"*:53\"))\n");
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn home() -> PathBuf {
        PathBuf::from("/Users/testuser")
    }

    fn project() -> PathBuf {
        PathBuf::from("/Users/testuser/proj/cognis")
    }

    #[test]
    fn empty_policy_produces_baseline_profile() {
        let policy = SandboxPolicy {
            enabled: true,
            network_allow: vec![],
            fs_write_allow: vec![],
        };
        let s = generate_profile(&policy, &project(), &home()).unwrap();
        assert!(s.contains("(version 1)"));
        assert!(s.contains("(deny default)"));
        assert!(s.contains("(allow process-fork)"));
        assert!(s.contains("(allow file-read*)"));
        assert!(s.contains("(subpath \"/Users/testuser/proj/cognis\")"));
        assert!(!s.contains("(allow network-outbound"));
    }

    #[test]
    fn network_allow_emits_remote_tcp_clauses() {
        let policy = SandboxPolicy {
            enabled: true,
            network_allow: vec![
                "registry.npmjs.org".to_string(),
                "github.com:8443".to_string(),
            ],
            fs_write_allow: vec![],
        };
        let s = generate_profile(&policy, &project(), &home()).unwrap();
        assert!(s.contains("(remote tcp \"registry.npmjs.org:443\")"));
        assert!(s.contains("(remote tcp \"github.com:8443\")"));
        assert!(s.contains("(remote udp \"*:53\")"));
    }

    #[test]
    fn fs_write_allow_expands_tilde() {
        let policy = SandboxPolicy {
            enabled: true,
            network_allow: vec![],
            fs_write_allow: vec!["~/.npm".to_string(), "~/Library/Caches".to_string()],
        };
        let s = generate_profile(&policy, &project(), &home()).unwrap();
        assert!(s.contains("(subpath \"/Users/testuser/.npm\")"));
        assert!(s.contains("(subpath \"/Users/testuser/Library/Caches\")"));
    }

    #[test]
    fn invalid_hostname_rejected() {
        let policy = SandboxPolicy {
            enabled: true,
            network_allow: vec!["evil\")) (allow".to_string()],
            fs_write_allow: vec![],
        };
        let err = generate_profile(&policy, &project(), &home()).unwrap_err();
        assert!(matches!(err, Error::Invalid(_)));
    }

    #[test]
    fn invalid_path_entry_rejected() {
        let policy = SandboxPolicy {
            enabled: true,
            network_allow: vec![],
            fs_write_allow: vec!["~/with space/bad".to_string()],
        };
        let err = generate_profile(&policy, &project(), &home()).unwrap_err();
        assert!(matches!(err, Error::Invalid(_)));
    }

    #[test]
    fn relative_project_root_rejected() {
        let policy = SandboxPolicy::default();
        let rel = PathBuf::from("relative/path");
        let err = generate_profile(&policy, &rel, &home()).unwrap_err();
        assert!(matches!(err, Error::Invalid(_)));
    }

    #[test]
    fn is_valid_hostname_accepts_wildcards() {
        assert!(is_valid_hostname("*.amazonaws.com"));
        assert!(is_valid_hostname("registry.npmjs.org"));
        assert!(is_valid_hostname("github.com:8443"));
    }

    #[test]
    fn is_valid_hostname_rejects_quotes_and_parens() {
        assert!(!is_valid_hostname("evil.com\""));
        assert!(!is_valid_hostname("foo)bar"));
        assert!(!is_valid_hostname("foo bar"));
        assert!(!is_valid_hostname(""));
    }

    #[test]
    fn is_valid_path_entry_rejects_metachars() {
        assert!(is_valid_path_entry("/Users/me/.npm"));
        assert!(is_valid_path_entry("~/.npm"));
        assert!(!is_valid_path_entry("/path with space"));
        assert!(!is_valid_path_entry("/path;injection"));
    }
}
