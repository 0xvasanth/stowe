use secrets_core::{Result, Vault};

pub struct NamespaceSummary {
    pub namespace: String,
    pub var_count: usize,
}

pub fn namespaces(_vault: &dyn Vault) -> Result<Vec<NamespaceSummary>> {
    unimplemented!("Task 9")
}

pub fn vars(_vault: &dyn Vault, _namespace: &str) -> Result<Vec<String>> {
    unimplemented!("Task 9")
}
