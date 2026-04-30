use crate::{error::Result, secret_value::SecretValue};

pub mod memory;

#[cfg(target_os = "macos")]
pub mod keychain;

/// Storage abstraction. Implementations: `InMemoryVault` (tests) and
/// `KeychainVault` (real macOS Keychain).
pub trait Vault {
    fn set(&mut self, namespace: &str, var: &str, value: SecretValue) -> Result<()>;
    fn get(&self, namespace: &str, var: &str) -> Result<SecretValue>;
    fn delete(&mut self, namespace: &str, var: &str) -> Result<()>;
    fn list_vars(&self, namespace: &str) -> Result<Vec<String>>;
    fn list_namespaces(&self) -> Result<Vec<String>>;
}

pub use memory::InMemoryVault;

#[cfg(target_os = "macos")]
pub use keychain::KeychainVault;
