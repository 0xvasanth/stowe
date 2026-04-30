//! Export a snapshot of the vault to a file.
//!
//! Two formats:
//! - `Encrypted` — passphrase-protected `age`-encrypted blob containing a
//!   line-delimited representation of every (namespace, var, value) triple.
//! - `EnvPlain` — plaintext `KEY=value` lines per namespace, sectioned by
//!   `# namespace: <ns>` comment headers.

use std::io::Write;
use std::path::Path;

use age::secrecy::SecretString;

use crate::error::{Error, Result};
use crate::vault::Vault;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    /// `age`-encrypted, passphrase-protected.
    Encrypted,
    /// Plaintext `.env`-format dump. Insecure; opt-in only.
    EnvPlain,
}

/// Produce the export bytes for `vault`. Caller writes them to disk.
pub fn export_to_bytes(
    vault: &dyn Vault,
    namespaces: &[String],
    format: ExportFormat,
    passphrase: Option<&str>,
) -> Result<Vec<u8>> {
    let mut text = String::new();
    let mut use_namespaces: Vec<String> = if namespaces.is_empty() {
        vault.list_namespaces()?
    } else {
        namespaces.to_vec()
    };
    use_namespaces.sort();
    use_namespaces.dedup();

    for ns in &use_namespaces {
        text.push_str(&format!("# namespace: {}\n", ns));
        let mut vars = vault.list_vars(ns)?;
        vars.sort();
        for var in vars {
            let value = vault.get(ns, &var)?;
            let s = std::str::from_utf8(value.expose()).map_err(|_| {
                Error::Invalid(format!(
                    "non-UTF-8 value at {}/{} cannot be exported",
                    ns, var
                ))
            })?;
            text.push_str(&format!("{}={}\n", var, s));
        }
        text.push('\n');
    }

    match format {
        ExportFormat::EnvPlain => Ok(text.into_bytes()),
        ExportFormat::Encrypted => {
            let pass = passphrase
                .ok_or_else(|| Error::Invalid("Encrypted export requires a passphrase".into()))?;
            if pass.is_empty() {
                return Err(Error::Invalid("passphrase must be non-empty".into()));
            }
            let encryptor =
                age::Encryptor::with_user_passphrase(SecretString::new(pass.to_owned()));
            let mut out = Vec::new();
            let mut writer = encryptor
                .wrap_output(&mut out)
                .map_err(|e| Error::Invalid(format!("age encrypt setup: {}", e)))?;
            writer.write_all(text.as_bytes()).map_err(Error::Io)?;
            writer
                .finish()
                .map_err(|e| Error::Invalid(format!("age encrypt finish: {}", e)))?;
            Ok(out)
        }
    }
}

/// Convenience wrapper: export to `path`. The file is created with
/// permissions 0600 (POSIX). Existing files are overwritten.
pub fn export_to_path(
    vault: &dyn Vault,
    namespaces: &[String],
    format: ExportFormat,
    passphrase: Option<&str>,
    path: &Path,
) -> Result<()> {
    let bytes = export_to_bytes(vault, namespaces, format, passphrase)?;
    std::fs::write(path, &bytes).map_err(Error::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(Error::Io)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret_value::SecretValue;
    use crate::vault::InMemoryVault;

    fn populated() -> InMemoryVault {
        let mut v = InMemoryVault::new();
        v.set("alpha", "A1", SecretValue::from_string("a-one".into()))
            .unwrap();
        v.set("alpha", "A2", SecretValue::from_string("a-two".into()))
            .unwrap();
        v.set("beta", "B1", SecretValue::from_string("b-one".into()))
            .unwrap();
        v
    }

    #[test]
    fn env_plain_dumps_all_namespaces_sorted() {
        let v = populated();
        let bytes = export_to_bytes(&v, &[], ExportFormat::EnvPlain, None).unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        let alpha_pos = s.find("# namespace: alpha").unwrap();
        let beta_pos = s.find("# namespace: beta").unwrap();
        assert!(alpha_pos < beta_pos);
        assert!(s.contains("A1=a-one"));
        assert!(s.contains("A2=a-two"));
        assert!(s.contains("B1=b-one"));
    }

    #[test]
    fn env_plain_namespace_filter() {
        let v = populated();
        let bytes =
            export_to_bytes(&v, &["beta".to_string()], ExportFormat::EnvPlain, None).unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(!s.contains("namespace: alpha"));
        assert!(s.contains("namespace: beta"));
        assert!(s.contains("B1=b-one"));
    }

    #[test]
    fn encrypted_round_trip_via_decrypt() {
        let v = populated();
        let bytes = export_to_bytes(&v, &[], ExportFormat::Encrypted, Some("hunter2")).unwrap();
        let decryptor = match age::Decryptor::new_buffered(&bytes[..]).unwrap() {
            age::Decryptor::Passphrase(d) => d,
            _ => panic!("expected passphrase decryptor"),
        };
        let mut reader = decryptor
            .decrypt(&SecretString::new("hunter2".to_owned()), None)
            .unwrap();
        let mut decrypted = Vec::new();
        std::io::Read::read_to_end(&mut reader, &mut decrypted).unwrap();
        let s = String::from_utf8(decrypted).unwrap();
        assert!(s.contains("A1=a-one"));
        assert!(s.contains("B1=b-one"));
    }

    #[test]
    fn encrypted_requires_passphrase() {
        let v = populated();
        let err = export_to_bytes(&v, &[], ExportFormat::Encrypted, None).unwrap_err();
        assert!(matches!(err, Error::Invalid(_)));
    }

    #[test]
    fn encrypted_rejects_empty_passphrase() {
        let v = populated();
        let err = export_to_bytes(&v, &[], ExportFormat::Encrypted, Some("")).unwrap_err();
        assert!(matches!(err, Error::Invalid(_)));
    }

    #[test]
    fn export_to_path_writes_file_with_0600() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("backup.env");
        let v = populated();
        export_to_path(&v, &[], ExportFormat::EnvPlain, None, &path).unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(meta.mode() & 0o777, 0o600);
    }
}
