use crate::{error::Result, secret_value::SecretValue};

pub mod memory;

// pub mod keychain;  // re-enabled in Task 6

/// Storage abstraction. Implementations: `InMemoryVault` (tests) and
/// `KeychainVault` (real macOS Keychain — added in Task 6).
pub trait Vault {
    /// Set or overwrite a secret.
    fn set(&mut self, namespace: &str, var: &str, value: SecretValue) -> Result<()>;

    /// Read a secret. Returns `Error::NotFound` if missing.
    fn get(&self, namespace: &str, var: &str) -> Result<SecretValue>;

    /// Delete a secret. Returns `Error::NotFound` if missing.
    fn delete(&mut self, namespace: &str, var: &str) -> Result<()>;

    /// Variable names within `namespace`. Sorted. Empty list if namespace has no entries.
    fn list_vars(&self, namespace: &str) -> Result<Vec<String>>;

    /// All namespaces with at least one stored secret. Sorted.
    fn list_namespaces(&self) -> Result<Vec<String>>;
}

pub use memory::InMemoryVault;

// pub use keychain::KeychainVault;  // re-enabled in Task 6
