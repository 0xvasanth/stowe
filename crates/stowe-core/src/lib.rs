pub mod audit;
pub mod error;
pub mod index;
pub mod manifest;
pub mod secret_value;
pub mod vault;

pub use audit::{Audit, AuditRowId, CloseRun, OpenRun, Outcome};
pub use error::{Error, Result};
pub use index::Index;
pub use manifest::{Manifest, VarSpec};
pub use secret_value::SecretValue;
pub use vault::{InMemoryVault, Vault};

#[cfg(target_os = "macos")]
pub use vault::KeychainVault;
