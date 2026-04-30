use std::collections::HashMap;

use zeroize::Zeroizing;

use crate::{
    error::{Error, Result},
    secret_value::SecretValue,
    vault::Vault,
};

/// Pure in-memory implementation. Used for unit tests and as a reference
/// against which `KeychainVault` behavior is verified.
#[derive(Default)]
pub struct InMemoryVault {
    items: HashMap<(String, String), Zeroizing<Vec<u8>>>,
}

impl InMemoryVault {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Vault for InMemoryVault {
    fn set(&mut self, namespace: &str, var: &str, value: SecretValue) -> Result<()> {
        self.items.insert(
            (namespace.to_string(), var.to_string()),
            Zeroizing::new(value.expose().to_vec()),
        );
        Ok(())
    }

    fn get(&self, namespace: &str, var: &str) -> Result<SecretValue> {
        self.items
            .get(&(namespace.to_string(), var.to_string()))
            .map(|z| SecretValue::new(z.to_vec()))
            .ok_or_else(|| Error::NotFound {
                namespace: namespace.to_string(),
                var: var.to_string(),
            })
    }

    fn delete(&mut self, namespace: &str, var: &str) -> Result<()> {
        self.items
            .remove(&(namespace.to_string(), var.to_string()))
            .ok_or_else(|| Error::NotFound {
                namespace: namespace.to_string(),
                var: var.to_string(),
            })?;
        Ok(())
    }

    fn list_vars(&self, namespace: &str) -> Result<Vec<String>> {
        let mut vars: Vec<String> = self
            .items
            .keys()
            .filter(|(ns, _)| ns == namespace)
            .map(|(_, v)| v.clone())
            .collect();
        vars.sort();
        Ok(vars)
    }

    fn list_namespaces(&self) -> Result<Vec<String>> {
        use std::collections::BTreeSet;
        let nses: BTreeSet<String> = self.items.keys().map(|(ns, _)| ns.clone()).collect();
        Ok(nses.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sv(s: &str) -> SecretValue {
        SecretValue::from_string(s.to_string())
    }

    #[test]
    fn set_then_get_roundtrips() {
        let mut v = InMemoryVault::new();
        v.set("cognis", "API_KEY", sv("k1")).unwrap();
        let got = v.get("cognis", "API_KEY").unwrap();
        assert_eq!(got.expose(), b"k1");
    }

    #[test]
    fn get_missing_returns_not_found() {
        let v = InMemoryVault::new();
        let result = v.get("ghost", "X");
        assert!(matches!(result, Err(Error::NotFound { .. })));
    }

    #[test]
    fn set_overwrites_existing() {
        let mut v = InMemoryVault::new();
        v.set("ns", "K", sv("a")).unwrap();
        v.set("ns", "K", sv("b")).unwrap();
        assert_eq!(v.get("ns", "K").unwrap().expose(), b"b");
    }

    #[test]
    fn delete_removes_and_returns_not_found_after() {
        let mut v = InMemoryVault::new();
        v.set("ns", "K", sv("a")).unwrap();
        v.delete("ns", "K").unwrap();
        let result = v.get("ns", "K");
        assert!(matches!(result, Err(Error::NotFound { .. })));
    }

    #[test]
    fn delete_missing_returns_not_found() {
        let mut v = InMemoryVault::new();
        let result = v.delete("ns", "K");
        assert!(matches!(result, Err(Error::NotFound { .. })));
    }

    #[test]
    fn list_vars_sorted_and_scoped_to_namespace() {
        let mut v = InMemoryVault::new();
        v.set("ns1", "Z", sv("z")).unwrap();
        v.set("ns1", "A", sv("a")).unwrap();
        v.set("ns2", "M", sv("m")).unwrap();
        let vars = v.list_vars("ns1").unwrap();
        assert_eq!(vars, vec!["A".to_string(), "Z".to_string()]);
    }

    #[test]
    fn list_vars_empty_namespace_returns_empty() {
        let v = InMemoryVault::new();
        assert_eq!(v.list_vars("nothing").unwrap(), Vec::<String>::new());
    }

    #[test]
    fn list_namespaces_sorted_and_unique() {
        let mut v = InMemoryVault::new();
        v.set("b", "X", sv("x")).unwrap();
        v.set("a", "X", sv("x")).unwrap();
        v.set("a", "Y", sv("y")).unwrap();
        assert_eq!(v.list_namespaces().unwrap(), vec!["a", "b"]);
    }
}
