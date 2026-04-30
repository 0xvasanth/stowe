use stowe_core::{Result, SecretValue, Vault};

/// Read the secret at `(namespace, var)` and return its value.
/// `Error::NotFound` if absent.
pub fn run(vault: &dyn Vault, namespace: &str, var: &str) -> Result<SecretValue> {
    vault.get(namespace, var)
}

#[cfg(test)]
mod tests {
    use super::*;
    use stowe_core::{Error, InMemoryVault};

    fn sv(s: &str) -> SecretValue {
        SecretValue::from_string(s.to_string())
    }

    #[test]
    fn returns_stored_value() {
        let mut vault = InMemoryVault::new();
        vault.set("cognis", "API_KEY", sv("sk-abc")).unwrap();
        let got = run(&vault, "cognis", "API_KEY").unwrap();
        assert_eq!(got.expose(), b"sk-abc");
    }

    #[test]
    fn missing_returns_not_found() {
        let vault = InMemoryVault::new();
        let result = run(&vault, "ghost", "X");
        assert!(matches!(result, Err(Error::NotFound { .. })));
    }
}
