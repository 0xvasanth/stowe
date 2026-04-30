use security_framework::passwords::{
    delete_generic_password, get_generic_password, set_generic_password,
};

use crate::{
    error::{Error, Result},
    index::Index,
    secret_value::SecretValue,
    vault::Vault,
};

const SERVICE_PREFIX: &str = "stowe.";

/// `errSecItemNotFound` from Apple's `Security.framework`. Not re-exported
/// by the `security-framework` crate; we use the numeric value directly.
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;

/// macOS Keychain-backed Vault. Stores values as Generic Password items
/// under service `stowe.<namespace>` and account `<VAR>`.
///
/// Listing operations read from a local `Index` because Keychain search
/// has an awkward Rust API surface; the Index is updated on every
/// `set`/`delete` and persisted to disk.
pub struct KeychainVault {
    index: Index,
}

impl KeychainVault {
    /// Open with the default index location:
    /// `~/Library/Application Support/stowe/index.toml`.
    pub fn open_default() -> Result<Self> {
        let path = Index::default_path()?;
        let index = Index::load(&path)?;
        Ok(Self { index })
    }

    /// Open with a custom index path. Used in tests only.
    #[cfg(test)]
    pub fn open_with_index(index: Index) -> Self {
        Self { index }
    }

    fn service(namespace: &str) -> String {
        format!("{}{}", SERVICE_PREFIX, namespace)
    }

    fn map_sf_err(e: security_framework::base::Error, namespace: &str, var: &str) -> Error {
        if e.code() == ERR_SEC_ITEM_NOT_FOUND {
            return Error::NotFound {
                namespace: namespace.to_string(),
                var: var.to_string(),
            };
        }
        Error::Keychain(match e.message() {
            Some(msg) => format!("{msg} (code {})", e.code()),
            None => format!("keychain error code {}", e.code()),
        })
    }
}

impl Vault for KeychainVault {
    fn set(&mut self, namespace: &str, var: &str, value: SecretValue) -> Result<()> {
        if namespace.is_empty() || var.is_empty() {
            return Err(Error::Invalid("namespace and var must be non-empty".into()));
        }
        let service = Self::service(namespace);
        set_generic_password(&service, var, value.expose())
            .map_err(|e| Self::map_sf_err(e, namespace, var))?;
        self.index.add(namespace, var);
        self.index.save()?;
        Ok(())
    }

    fn get(&self, namespace: &str, var: &str) -> Result<SecretValue> {
        let service = Self::service(namespace);
        let bytes =
            get_generic_password(&service, var).map_err(|e| Self::map_sf_err(e, namespace, var))?;
        Ok(SecretValue::new(bytes))
    }

    fn delete(&mut self, namespace: &str, var: &str) -> Result<()> {
        let service = Self::service(namespace);
        match delete_generic_password(&service, var) {
            Ok(()) => {
                self.index.remove(namespace, var);
                self.index.save()?;
                Ok(())
            }
            Err(e) => Err(Self::map_sf_err(e, namespace, var)),
        }
    }

    fn list_vars(&self, namespace: &str) -> Result<Vec<String>> {
        Ok(self.index.vars_in(namespace))
    }

    fn list_namespaces(&self) -> Result<Vec<String>> {
        Ok(self.index.namespaces())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret_value::SecretValue;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tempfile::tempdir;

    fn unique_namespace() -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("test.stowe.m1.{}", nanos)
    }

    fn fresh_vault() -> (KeychainVault, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let idx_path = dir.path().join("index.toml");
        let index = Index::load(&idx_path).unwrap();
        (KeychainVault::open_with_index(index), dir)
    }

    fn cleanup(v: &mut KeychainVault, ns: &str, vars: &[&str]) {
        for var in vars {
            match v.delete(ns, var) {
                Ok(()) | Err(Error::NotFound { .. }) => {}
                Err(e) => panic!("cleanup failed for {var}: {e}"),
            }
        }
    }

    #[test]
    #[ignore = "writes to real Keychain; run with --ignored"]
    fn set_get_roundtrip_in_real_keychain() {
        let (mut v, _d) = fresh_vault();
        let ns = unique_namespace();

        v.set(&ns, "FOO", SecretValue::from_string("bar".into()))
            .expect("set");
        let got = v.get(&ns, "FOO").expect("get");
        assert_eq!(got.expose(), b"bar");

        cleanup(&mut v, &ns, &["FOO"]);
    }

    #[test]
    #[ignore = "writes to real Keychain; run with --ignored"]
    fn get_missing_returns_not_found() {
        let (v, _d) = fresh_vault();
        let ns = unique_namespace();
        let result = v.get(&ns, "MISSING");
        assert!(
            matches!(result, Err(Error::NotFound { .. })),
            "got {:?}",
            result.err()
        );
    }

    #[test]
    #[ignore = "writes to real Keychain; run with --ignored"]
    fn set_overwrites_value() {
        let (mut v, _d) = fresh_vault();
        let ns = unique_namespace();

        v.set(&ns, "K", SecretValue::from_string("v1".into()))
            .unwrap();
        v.set(&ns, "K", SecretValue::from_string("v2".into()))
            .unwrap();
        assert_eq!(v.get(&ns, "K").unwrap().expose(), b"v2");

        cleanup(&mut v, &ns, &["K"]);
    }

    #[test]
    #[ignore = "writes to real Keychain; run with --ignored"]
    fn delete_removes_then_get_is_not_found() {
        let (mut v, _d) = fresh_vault();
        let ns = unique_namespace();

        v.set(&ns, "K", SecretValue::from_string("v".into()))
            .unwrap();
        v.delete(&ns, "K").unwrap();
        let result = v.get(&ns, "K");
        assert!(matches!(result, Err(Error::NotFound { .. })));
    }

    #[test]
    #[ignore = "writes to real Keychain; run with --ignored"]
    fn list_via_index_after_set() {
        let (mut v, _d) = fresh_vault();
        let ns = unique_namespace();

        v.set(&ns, "Z", SecretValue::from_string("z".into()))
            .unwrap();
        v.set(&ns, "A", SecretValue::from_string("a".into()))
            .unwrap();

        assert_eq!(v.list_vars(&ns).unwrap(), vec!["A", "Z"]);
        assert!(v.list_namespaces().unwrap().contains(&ns));

        cleanup(&mut v, &ns, &["A", "Z"]);
    }

    #[test]
    fn empty_inputs_rejected() {
        let (mut v, _d) = fresh_vault();
        let err1 = v.set("", "X", SecretValue::from_string("v".into()));
        assert!(matches!(err1, Err(Error::Invalid(_))));
        let err2 = v.set("ns", "", SecretValue::from_string("v".into()));
        assert!(matches!(err2, Err(Error::Invalid(_))));
    }
}
