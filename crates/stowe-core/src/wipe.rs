//! Wipe all secrets from a vault, optionally truncating the audit log.

use crate::audit::Audit;
use crate::error::Result;
use crate::vault::Vault;

#[derive(Debug, Clone, Copy)]
pub struct WipeReport {
    pub namespaces_deleted: usize,
    pub vars_deleted: usize,
    pub audit_rows_deleted: i64,
}

/// Delete every (namespace, var) tracked by `vault`. If `also_audit` is
/// true, also truncate the audit log via `audit`.
pub fn wipe_all(
    vault: &mut dyn Vault,
    audit: Option<&Audit>,
    also_audit: bool,
) -> Result<WipeReport> {
    let mut vars_deleted = 0usize;
    let namespaces = vault.list_namespaces()?;
    let namespaces_count = namespaces.len();

    for ns in &namespaces {
        let vars = vault.list_vars(ns)?;
        for v in vars {
            if vault.delete(ns, &v).is_ok() {
                vars_deleted += 1;
            }
        }
    }

    let audit_rows_deleted = if also_audit {
        if let Some(a) = audit {
            a.truncate().unwrap_or(0)
        } else {
            0
        }
    } else {
        0
    };

    Ok(WipeReport {
        namespaces_deleted: namespaces_count,
        vars_deleted,
        audit_rows_deleted,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret_value::SecretValue;
    use crate::vault::InMemoryVault;

    #[test]
    fn wipes_all_secrets_no_audit() {
        let mut v = InMemoryVault::new();
        v.set("ns1", "A", SecretValue::from_string("v".into()))
            .unwrap();
        v.set("ns1", "B", SecretValue::from_string("v".into()))
            .unwrap();
        v.set("ns2", "C", SecretValue::from_string("v".into()))
            .unwrap();
        let report = wipe_all(&mut v, None, false).unwrap();
        assert_eq!(report.namespaces_deleted, 2);
        assert_eq!(report.vars_deleted, 3);
        assert_eq!(report.audit_rows_deleted, 0);
        assert!(v.list_namespaces().unwrap().is_empty());
    }

    #[test]
    fn wipes_empty_vault_is_noop() {
        let mut v = InMemoryVault::new();
        let report = wipe_all(&mut v, None, false).unwrap();
        assert_eq!(report.namespaces_deleted, 0);
        assert_eq!(report.vars_deleted, 0);
    }
}
