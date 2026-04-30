pub mod audit;
pub mod codesign;
pub mod error;
pub mod index;
pub mod manifest;
pub mod runner;
pub mod sandbox;
pub mod secret_value;
pub mod vault;

pub use audit::{Audit, AuditRowId, CloseRun, OpenRun, Outcome};
pub use codesign::CodesignInfo;
pub use error::{Error, Result};
pub use index::Index;
pub use manifest::{BiometricMode, Manifest, Policy, SandboxPolicy, VarSpec};
pub use runner::{ChildOutcome, RunnerConfig};
pub use secret_value::SecretValue;
pub use vault::{InMemoryVault, Vault};

#[cfg(target_os = "macos")]
pub use vault::KeychainVault;
