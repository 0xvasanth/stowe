use stowe_core::{Result, SecretValue, Vault};

/// Store `value` at `(namespace, var)`. Overwrites existing.
pub fn run(vault: &mut dyn Vault, namespace: &str, var: &str, value: SecretValue) -> Result<()> {
    vault.set(namespace, var, value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use stowe_core::InMemoryVault;

    #[test]
    fn stores_value_in_vault() {
        let mut vault = InMemoryVault::new();
        run(
            &mut vault,
            "cognis",
            "API_KEY",
            SecretValue::from_string("k1".into()),
        )
        .unwrap();
        let got = vault.get("cognis", "API_KEY").unwrap();
        assert_eq!(got.expose(), b"k1");
    }

    #[test]
    fn overwrites_existing() {
        let mut vault = InMemoryVault::new();
        run(&mut vault, "ns", "K", SecretValue::from_string("v1".into())).unwrap();
        run(&mut vault, "ns", "K", SecretValue::from_string("v2".into())).unwrap();
        assert_eq!(vault.get("ns", "K").unwrap().expose(), b"v2");
    }
}
