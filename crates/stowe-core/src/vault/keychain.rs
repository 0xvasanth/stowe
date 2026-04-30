use core_foundation::base::TCFType;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::string::CFString;
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::passwords::{
    delete_generic_password, get_generic_password, set_generic_password,
};
use security_framework::passwords_options::{AccessControlOptions, PasswordOptions};
use security_framework_sys::base::errSecSuccess;
use security_framework_sys::item::{kSecAttrAccessControl, kSecValueData};
use security_framework_sys::keychain_item::SecItemAdd;

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

    /// Reject namespace/var names with characters that confuse the Keychain
    /// service-name format (whitespace, slashes, control bytes) or are empty.
    fn validate_name(label: &str, value: &str) -> Result<()> {
        if value.is_empty() {
            return Err(Error::Invalid(format!("{} must be non-empty", label)));
        }
        for ch in value.chars() {
            if ch.is_whitespace() || ch.is_control() || ch == '/' {
                return Err(Error::Invalid(format!(
                    "{} contains disallowed character: {:?}",
                    label, ch
                )));
            }
        }
        Ok(())
    }

    /// Create a Keychain item with the given biometric policy. When
    /// `mode == BiometricMode::Always`, the item is created with
    /// `SecAccessControl` requiring biometric or device-passcode auth on
    /// each read. When `mode == BiometricMode::Never`, this is equivalent
    /// to plain `set`.
    pub fn set_with_biometric(
        &mut self,
        namespace: &str,
        var: &str,
        value: SecretValue,
        mode: crate::manifest::BiometricMode,
    ) -> Result<()> {
        Self::validate_name("namespace", namespace)?;
        Self::validate_name("var", var)?;

        match mode {
            crate::manifest::BiometricMode::Never => {
                let service = Self::service(namespace);
                set_generic_password(&service, var, value.expose())
                    .map_err(|e| Self::map_sf_err(e, namespace, var))?;
            }
            crate::manifest::BiometricMode::Always => {
                let service = Self::service(namespace);
                let flags = AccessControlOptions::BIOMETRY_ANY
                    | AccessControlOptions::OR
                    | AccessControlOptions::DEVICE_PASSCODE;

                // Build SecAccessControl with explicit protection mode.
                // AccessibleWhenPasscodeSetThisDeviceOnly: item is not
                // eligible for iCloud Keychain sync AND requires a device
                // passcode to be set (which is the precondition for the
                // DEVICE_PASSCODE fallback in `flags` to be meaningful).
                let access_control = SecAccessControl::create_with_protection(
                    Some(ProtectionMode::AccessibleWhenPasscodeSetThisDeviceOnly),
                    flags.bits(),
                )
                .map_err(|e| Error::Keychain(format!("creating access control: {}", e)))?;

                // Delete-then-add to handle the "overwrite with new ACL" case.
                // TOCTOU note: if delete succeeds but SecItemAdd below fails
                // (e.g. a racing process), the secret is lost for this call.
                // The Err return propagates; deferred to a post-M3 follow-up.
                let _ = delete_generic_password(&service, var);

                let mut opts = PasswordOptions::new_generic_password(&service, var);
                // Append kSecAttrAccessControl with our protection-mode-bearing
                // SecAccessControl (replaces set_access_control_options which
                // hardcodes a null protection).
                opts.query.push((
                    unsafe { CFString::wrap_under_get_rule(kSecAttrAccessControl) },
                    access_control.into_CFType(),
                ));
                // Append the secret value. NOTE: CF allocates a non-zeroized
                // copy of these bytes on the heap; CF does not wipe on drop.
                // This matches set_generic_password's behavior; revisit if a
                // future zeroize-after-SecItemAdd pass is warranted.
                opts.query.push((
                    unsafe { CFString::wrap_under_get_rule(kSecValueData) },
                    CFData::from_buffer(value.expose()).into_CFType(),
                ));
                let dict = CFDictionary::from_CFType_pairs(&opts.query);
                let status =
                    unsafe { SecItemAdd(dict.as_concrete_TypeRef().cast(), std::ptr::null_mut()) };
                if status != errSecSuccess {
                    return Err(Self::map_sf_err(
                        security_framework::base::Error::from_code(status),
                        namespace,
                        var,
                    ));
                }
            }
        }
        self.index.add(namespace, var);
        self.index.save()?;
        Ok(())
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
        Self::validate_name("namespace", namespace)?;
        Self::validate_name("var", var)?;
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

    #[test]
    #[ignore = "writes to real Keychain; run with --ignored"]
    fn set_with_biometric_never_round_trips() {
        let (mut v, _d) = fresh_vault();
        let ns = unique_namespace();
        v.set_with_biometric(
            &ns,
            "BIO_NEVER",
            SecretValue::from_string("plain".into()),
            crate::manifest::BiometricMode::Never,
        )
        .expect("set_with_biometric Never");
        let got = v.get(&ns, "BIO_NEVER").expect("get");
        assert_eq!(got.expose(), b"plain");
        cleanup(&mut v, &ns, &["BIO_NEVER"]);
    }

    /// Verify that biometric=Always actually persists an ACL on the item.
    /// This uses `SecItemCopyMatching` with `kSecReturnAttributes: true`
    /// and `kSecReturnData: false` — querying attributes does NOT trigger
    /// the ACL evaluation, so this won't prompt for Touch ID.
    #[test]
    #[ignore = "writes to real Keychain; run with --ignored"]
    fn set_with_biometric_always_persists_acl() {
        use core_foundation::base::TCFType;
        use core_foundation::boolean::CFBoolean;
        use core_foundation::dictionary::CFDictionary;
        use core_foundation::number::CFNumber;
        use core_foundation::string::CFString;
        use security_framework_sys::item::{
            kSecAttrAccessControl, kSecAttrAccount, kSecAttrService, kSecClass,
            kSecClassGenericPassword, kSecMatchLimit, kSecReturnAttributes,
        };
        use security_framework_sys::keychain_item::SecItemCopyMatching;

        let (mut v, _d) = fresh_vault();
        let ns = unique_namespace();

        v.set_with_biometric(
            &ns,
            "BIO_ALWAYS",
            SecretValue::from_string("doesnt-matter".into()),
            crate::manifest::BiometricMode::Always,
        )
        .expect("set_with_biometric Always");

        // Build a query: class=GenericPassword, service=stowe.<ns>, account=BIO_ALWAYS,
        // returnAttributes=true, matchLimit=1. NO returnData, so no ACL prompt.
        let service = format!("stowe.{}", ns);
        let pairs: Vec<(CFString, core_foundation::base::CFType)> = vec![
            (
                unsafe { CFString::wrap_under_get_rule(kSecClass) },
                unsafe { CFString::wrap_under_get_rule(kSecClassGenericPassword).into_CFType() },
            ),
            (
                unsafe { CFString::wrap_under_get_rule(kSecAttrService) },
                CFString::new(&service).into_CFType(),
            ),
            (
                unsafe { CFString::wrap_under_get_rule(kSecAttrAccount) },
                CFString::new("BIO_ALWAYS").into_CFType(),
            ),
            (
                unsafe { CFString::wrap_under_get_rule(kSecMatchLimit) },
                CFNumber::from(1i64).into_CFType(),
            ),
            (
                unsafe { CFString::wrap_under_get_rule(kSecReturnAttributes) },
                CFBoolean::true_value().into_CFType(),
            ),
        ];
        let query = CFDictionary::from_CFType_pairs(&pairs);
        let mut result: core_foundation::base::CFTypeRef = std::ptr::null();
        let status =
            unsafe { SecItemCopyMatching(query.as_concrete_TypeRef().cast(), &mut result) };
        assert_eq!(
            status, 0,
            "SecItemCopyMatching should succeed for an item we just created; status={}",
            status
        );
        assert!(!result.is_null(), "result dict should not be null");

        // The returned CFDictionary should contain a kSecAttrAccessControl key,
        // proving the ACL was persisted on the item.
        let result_dict: CFDictionary<
            core_foundation::base::CFType,
            core_foundation::base::CFType,
        > = unsafe { CFDictionary::wrap_under_create_rule(result.cast()) };
        let access_control_key: CFString =
            unsafe { CFString::wrap_under_get_rule(kSecAttrAccessControl) };
        assert!(
            result_dict.find(access_control_key.into_CFType()).is_some(),
            "expected kSecAttrAccessControl on item, got {} keys",
            result_dict.len()
        );

        cleanup(&mut v, &ns, &["BIO_ALWAYS"]);
    }

    #[test]
    fn disallowed_characters_rejected() {
        let (mut v, _d) = fresh_vault();
        let cases = vec![
            ("ns with space", "X"),
            ("ns/slash", "X"),
            ("ns", "var with space"),
            ("ns", "var/slash"),
            ("ns", "var\twith\ttab"),
        ];
        for (ns, var) in cases {
            let result = v.set(ns, var, SecretValue::from_string("v".into()));
            assert!(
                matches!(result, Err(Error::Invalid(_))),
                "expected Invalid for ({:?}, {:?}), got {:?}",
                ns,
                var,
                result
            );
        }
    }
}
