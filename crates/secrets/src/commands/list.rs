use secrets_core::{Result, Vault};

pub struct NamespaceSummary {
    pub namespace: String,
    pub var_count: usize,
}

/// Summary of every namespace with at least one variable.
pub fn namespaces(vault: &dyn Vault) -> Result<Vec<NamespaceSummary>> {
    let nses = vault.list_namespaces()?;
    let mut out = Vec::with_capacity(nses.len());
    for ns in nses {
        let count = vault.list_vars(&ns)?.len();
        out.push(NamespaceSummary {
            namespace: ns,
            var_count: count,
        });
    }
    Ok(out)
}

/// Variables within a single namespace. Sorted by the underlying vault.
pub fn vars(vault: &dyn Vault, namespace: &str) -> Result<Vec<String>> {
    vault.list_vars(namespace)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrets_core::{InMemoryVault, SecretValue};

    fn sv(s: &str) -> SecretValue {
        SecretValue::from_string(s.to_string())
    }

    fn populated() -> InMemoryVault {
        let mut v = InMemoryVault::new();
        v.set("cognis", "API_KEY", sv("k1")).unwrap();
        v.set("cognis", "DB_URL", sv("k2")).unwrap();
        v.set("shopify", "TOKEN", sv("k3")).unwrap();
        v
    }

    #[test]
    fn namespaces_returns_each_namespace_with_count() {
        let vault = populated();
        let summaries = namespaces(&vault).unwrap();
        assert_eq!(summaries.len(), 2);
        let cognis = summaries.iter().find(|s| s.namespace == "cognis").unwrap();
        assert_eq!(cognis.var_count, 2);
        let shopify = summaries.iter().find(|s| s.namespace == "shopify").unwrap();
        assert_eq!(shopify.var_count, 1);
    }

    #[test]
    fn namespaces_empty_vault_returns_empty() {
        let vault = InMemoryVault::new();
        assert!(namespaces(&vault).unwrap().is_empty());
    }

    #[test]
    fn vars_returns_sorted_names_in_namespace() {
        let vault = populated();
        let v = vars(&vault, "cognis").unwrap();
        assert_eq!(v, vec!["API_KEY", "DB_URL"]);
    }

    #[test]
    fn vars_unknown_namespace_returns_empty() {
        let vault = populated();
        let v = vars(&vault, "ghost").unwrap();
        assert!(v.is_empty());
    }
}
