# Secrets M1 — Skeleton & Minimal CLI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a Rust CLI binary `secrets` that stores/retrieves/lists named secrets in the macOS Keychain, with a tested core library backed by both a real Keychain implementation and an in-memory fake.

**Architecture:** Cargo workspace with two crates. `secrets-core` is a pure library exposing a `Vault` trait, an `InMemoryVault` for unit tests, and a `KeychainVault` that calls Apple's `Security.framework`. `secrets` is a thin `clap`-based binary that wires `KeychainVault` into three subcommands — `add`, `list`, `reveal` — plus a `ui` stub for later milestones. Listing is backed by a local TOML index because the macOS search API is awkward; we'll revisit in a later milestone.

**Tech Stack:** Rust 2021, `cargo` workspaces, `clap` (CLI), `dialoguer` (hidden password prompt), `security-framework` (macOS Keychain), `thiserror` (errors), `zeroize` (memory wiping), `toml` + `serde` (index file).

**Out of scope for M1:** ACL/biometric flags, `secrets.toml` manifests, `secrets run`, audit log, sandbox, Tauri UI. All of those land in later milestones (M2–M6 in the design doc).

**Spec reference:** `docs/superpowers/specs/2026-04-30-secrets-vault-design.md`

---

## File structure

```
secret/
├── Cargo.toml                              # workspace root
├── .gitignore                              # /target
├── crates/
│   ├── secrets-core/                       # library
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                      # re-exports
│   │       ├── error.rs                    # Error, Result
│   │       ├── secret_value.rs             # SecretValue with Drop+Zeroize
│   │       ├── index.rs                    # Local TOML index of (namespace, var)
│   │       └── vault/
│   │           ├── mod.rs                  # Vault trait
│   │           ├── memory.rs               # InMemoryVault
│   │           └── keychain.rs             # KeychainVault (macOS only)
│   └── secrets/                            # binary
│       ├── Cargo.toml
│       └── src/
│           ├── main.rs                     # entry, dispatch
│           ├── cli.rs                      # clap definitions
│           └── commands/
│               ├── mod.rs
│               ├── add.rs                  # add::run(vault, ns, var, value)
│               ├── list.rs                 # list::namespaces / list::vars
│               └── reveal.rs               # reveal::run(vault, ns, var) -> SecretValue
└── docs/superpowers/...                    # already exists
```

**Module responsibilities:**

- `secret_value` — single type, owns the secret bytes, zeroes on drop, never implements `Debug`, `Display` redacts.
- `error` — `enum Error` with `NotFound`, `AlreadyExists`, `Keychain`, `Invalid`, `Io`. Plus `type Result<T>`.
- `index` — load/save a TOML file at `~/Library/Application Support/secrets/index.toml`. Records `(namespace, var, added_at)` tuples. Used by Keychain-backed listing.
- `vault::Vault` — the trait. Methods: `set`, `get`, `delete`, `list_vars`, `list_namespaces`.
- `vault::memory::InMemoryVault` — `HashMap`-backed, used in unit tests.
- `vault::keychain::KeychainVault` — wraps `security-framework::passwords::*`, plus an `Index` for listing.
- `cli::Cli` — `clap` derive struct, top-level subcommands.
- `commands::*::run(...)` — pure functions that take a `&mut dyn Vault` (or `&dyn Vault`) and return `Result`. No I/O inside; `main` does prompting and printing.
- `main.rs` — parses args, prompts for hidden values when needed, constructs `KeychainVault`, dispatches to commands.

---

## Task 1: Workspace skeleton

**Files:**
- Create: `Cargo.toml` (workspace root)
- Create: `.gitignore`
- Create: `crates/secrets-core/Cargo.toml`
- Create: `crates/secrets-core/src/lib.rs`
- Create: `crates/secrets/Cargo.toml`
- Create: `crates/secrets/src/main.rs`

- [ ] **Step 1: Create workspace `Cargo.toml`**

```toml
[workspace]
members = ["crates/secrets-core", "crates/secrets"]
resolver = "2"

[workspace.package]
edition = "2021"
license = "MIT"
authors = ["Vasanth"]

[workspace.dependencies]
thiserror   = "1.0"
anyhow      = "1.0"
zeroize     = { version = "1.7", features = ["zeroize_derive"] }
clap        = { version = "4.5", features = ["derive"] }
dialoguer   = { version = "0.11", default-features = false, features = ["password"] }
serde       = { version = "1", features = ["derive"] }
toml        = "0.8"
chrono      = { version = "0.4", default-features = false, features = ["clock", "serde"] }
dirs        = "5"
security-framework = "2.11"
core-foundation    = "0.10"

[profile.release]
strip = true
lto   = "thin"
```

- [ ] **Step 2: Create `.gitignore`**

```gitignore
/target
**/*.rs.bk
.DS_Store
```

- [ ] **Step 3: Create `crates/secrets-core/Cargo.toml`**

```toml
[package]
name    = "secrets-core"
version = "0.0.1"
edition.workspace = true
license.workspace = true

[dependencies]
thiserror = { workspace = true }
zeroize   = { workspace = true }
serde     = { workspace = true }
toml      = { workspace = true }
chrono    = { workspace = true }
dirs      = { workspace = true }

[target.'cfg(target_os = "macos")'.dependencies]
security-framework = { workspace = true }
core-foundation    = { workspace = true }

[dev-dependencies]
tempfile = "3"
```

- [ ] **Step 4: Create `crates/secrets-core/src/lib.rs`**

```rust
#[cfg(test)]
mod sanity {
    #[test]
    fn it_compiles() {
        assert_eq!(2 + 2, 4);
    }
}
```

- [ ] **Step 5: Create `crates/secrets/Cargo.toml`**

```toml
[package]
name    = "secrets"
version = "0.0.1"
edition.workspace = true
license.workspace = true

[[bin]]
name = "secrets"
path = "src/main.rs"

[dependencies]
secrets-core = { path = "../secrets-core" }
clap         = { workspace = true }
dialoguer    = { workspace = true }
anyhow       = { workspace = true }
```

- [ ] **Step 6: Create `crates/secrets/src/main.rs`**

```rust
fn main() {
    println!("secrets v{}", env!("CARGO_PKG_VERSION"));
}
```

- [ ] **Step 7: Verify build and run**

Run: `cargo build`
Expected: builds without error.

Run: `cargo run --bin secrets`
Expected: prints `secrets v0.0.1`.

Run: `cargo test`
Expected: 1 test passes (`it_compiles`).

- [ ] **Step 8: Commit**

```bash
git add Cargo.toml .gitignore crates/
git commit -m "M1: cargo workspace skeleton (secrets-core + secrets binary)"
```

---

## Task 2: `SecretValue` type with zeroize-on-drop

**Files:**
- Create: `crates/secrets-core/src/secret_value.rs`
- Modify: `crates/secrets-core/src/lib.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/secrets-core/src/secret_value.rs`:

```rust
use zeroize::Zeroize;

/// Owns a secret value. Wipes its bytes from memory on drop.
/// Never implements `Debug`. `Display` redacts and shows length only.
pub struct SecretValue(Vec<u8>);

impl SecretValue {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn from_string(s: String) -> Self {
        Self(s.into_bytes())
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for SecretValue {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Display for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<redacted: {} bytes>", self.0.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_string_roundtrips_via_expose() {
        let s = SecretValue::from_string("hello".to_string());
        assert_eq!(s.expose(), b"hello");
    }

    #[test]
    fn display_does_not_leak_value() {
        let s = SecretValue::from_string("super-secret".to_string());
        let displayed = format!("{}", s);
        assert!(!displayed.contains("super-secret"), "Display leaked secret: {}", displayed);
        assert!(displayed.contains("12 bytes"), "Display did not show length: {}", displayed);
    }

    #[test]
    fn len_and_empty() {
        assert!(SecretValue::from_string("".into()).is_empty());
        assert_eq!(SecretValue::from_string("abcd".into()).len(), 4);
    }
}
```

- [ ] **Step 2: Wire the module into the crate**

Replace `crates/secrets-core/src/lib.rs`:

```rust
pub mod secret_value;

pub use secret_value::SecretValue;
```

- [ ] **Step 3: Run the tests**

Run: `cargo test -p secrets-core`
Expected: 3 tests pass (`from_string_roundtrips_via_expose`, `display_does_not_leak_value`, `len_and_empty`).

- [ ] **Step 4: Verify SecretValue cannot be Debug-printed**

Run this throwaway check from a temp scratch file (do NOT commit):

```bash
cat > /tmp/secrets_dbg_check.rs <<'EOF'
fn main() {
    let s = secrets_core::SecretValue::from_string("x".into());
    println!("{:?}", s);
}
EOF
```

Then add a deliberately-failing test in `secret_value.rs` (temporarily) by appending:

```rust
// Uncomment to verify Debug is NOT impl'd; this MUST fail to compile.
// #[test] fn must_not_compile() { let s = SecretValue::from_string("x".into()); let _ = format!("{:?}", s); }
```

This is documentation only — leave the comment in place. The point is future readers see the explicit "no Debug" intent.

- [ ] **Step 5: Commit**

```bash
git add crates/secrets-core/src/lib.rs crates/secrets-core/src/secret_value.rs
git commit -m "M1: SecretValue with zeroize-on-drop and redacted Display"
```

---

## Task 3: Error and Result types

**Files:**
- Create: `crates/secrets-core/src/error.rs`
- Modify: `crates/secrets-core/src/lib.rs`

- [ ] **Step 1: Write the failing tests**

Create `crates/secrets-core/src/error.rs`:

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("secret '{var}' not found in namespace '{namespace}'")]
    NotFound { namespace: String, var: String },

    #[error("secret '{var}' already exists in namespace '{namespace}'")]
    AlreadyExists { namespace: String, var: String },

    #[error("keychain error: {0}")]
    Keychain(String),

    #[error("invalid input: {0}")]
    Invalid(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("toml parse error: {0}")]
    Toml(String),
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_found_message_contains_identifiers() {
        let e = Error::NotFound { namespace: "cognis".into(), var: "API_KEY".into() };
        let s = format!("{}", e);
        assert!(s.contains("cognis"), "missing namespace in: {}", s);
        assert!(s.contains("API_KEY"), "missing var in: {}", s);
        assert!(s.contains("not found"), "missing 'not found' in: {}", s);
    }

    #[test]
    fn keychain_message_contains_inner() {
        let e = Error::Keychain("errSecAuthFailed".into());
        let s = format!("{}", e);
        assert!(s.contains("errSecAuthFailed"));
    }

    #[test]
    fn io_converts_via_from() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "no file");
        let e: Error = io_err.into();
        assert!(matches!(e, Error::Io(_)));
    }
}
```

- [ ] **Step 2: Wire the module**

Replace `crates/secrets-core/src/lib.rs`:

```rust
pub mod error;
pub mod secret_value;

pub use error::{Error, Result};
pub use secret_value::SecretValue;
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p secrets-core`
Expected: 6 tests pass (3 from Task 2 + 3 new).

- [ ] **Step 4: Commit**

```bash
git add crates/secrets-core/src/lib.rs crates/secrets-core/src/error.rs
git commit -m "M1: error and Result types"
```

---

## Task 4: `Vault` trait + `InMemoryVault`

**Files:**
- Create: `crates/secrets-core/src/vault/mod.rs`
- Create: `crates/secrets-core/src/vault/memory.rs`
- Modify: `crates/secrets-core/src/lib.rs`

- [ ] **Step 1: Write the failing tests in `memory.rs`**

Create `crates/secrets-core/src/vault/memory.rs`:

```rust
use std::collections::HashMap;

use crate::{
    error::{Error, Result},
    secret_value::SecretValue,
    vault::Vault,
};

/// Pure in-memory implementation. Used for unit tests and as a reference
/// against which `KeychainVault` behavior is verified.
#[derive(Default)]
pub struct InMemoryVault {
    items: HashMap<(String, String), Vec<u8>>,
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
            value.expose().to_vec(),
        );
        Ok(())
    }

    fn get(&self, namespace: &str, var: &str) -> Result<SecretValue> {
        self.items
            .get(&(namespace.to_string(), var.to_string()))
            .cloned()
            .map(SecretValue::new)
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
        let err = v.get("ghost", "X").unwrap_err();
        assert!(matches!(err, Error::NotFound { .. }));
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
        assert!(matches!(v.get("ns", "K").unwrap_err(), Error::NotFound { .. }));
    }

    #[test]
    fn delete_missing_returns_not_found() {
        let mut v = InMemoryVault::new();
        let err = v.delete("ns", "K").unwrap_err();
        assert!(matches!(err, Error::NotFound { .. }));
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
```

- [ ] **Step 2: Define the `Vault` trait**

Create `crates/secrets-core/src/vault/mod.rs`:

```rust
use crate::{error::Result, secret_value::SecretValue};

pub mod memory;

#[cfg(target_os = "macos")]
pub mod keychain;

/// Storage abstraction. Implementations: `InMemoryVault` (tests) and
/// `KeychainVault` (real macOS Keychain).
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

#[cfg(target_os = "macos")]
pub use keychain::KeychainVault;
```

- [ ] **Step 3: Wire the module into `lib.rs`**

Replace `crates/secrets-core/src/lib.rs`:

```rust
pub mod error;
pub mod secret_value;
pub mod vault;

pub use error::{Error, Result};
pub use secret_value::SecretValue;
pub use vault::{InMemoryVault, Vault};

#[cfg(target_os = "macos")]
pub use vault::KeychainVault;
```

Note: `keychain.rs` does not exist yet — the `pub mod keychain;` line in `vault/mod.rs` will fail to compile until Task 6. **Temporarily comment out the `#[cfg(target_os = "macos")] pub mod keychain;` line** in `vault/mod.rs` and the matching re-export. We'll uncomment in Task 6.

After commenting out, `vault/mod.rs` head becomes:

```rust
use crate::{error::Result, secret_value::SecretValue};

pub mod memory;

// pub mod keychain;  // re-enabled in Task 6

pub trait Vault {
    /* ...same as above... */
}

pub use memory::InMemoryVault;

// pub use keychain::KeychainVault;  // re-enabled in Task 6
```

And in `lib.rs`, comment out the `KeychainVault` re-export:

```rust
// #[cfg(target_os = "macos")]
// pub use vault::KeychainVault;
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -p secrets-core`
Expected: 14 tests pass (6 from earlier + 8 new in `memory.rs`).

- [ ] **Step 5: Commit**

```bash
git add crates/secrets-core/src/lib.rs crates/secrets-core/src/vault/
git commit -m "M1: Vault trait + InMemoryVault with full coverage"
```

---

## Task 5: Local TOML index for namespace/var listing

**Files:**
- Create: `crates/secrets-core/src/index.rs`
- Modify: `crates/secrets-core/src/lib.rs`

The macOS Keychain search API does not lend itself to clean Rust enumeration. We sidestep by maintaining a local index of `(namespace, var)` pairs that we've added through this tool. The Keychain remains source of truth for **values**; the index tracks **schema**.

**Index format (`~/Library/Application Support/secrets/index.toml`):**

```toml
version = 1

[[entry]]
namespace = "cognis"
var       = "ANTHROPIC_API_KEY"
added_at  = "2026-04-30T10:33:00Z"
```

- [ ] **Step 1: Write the failing tests**

Create `crates/secrets-core/src/index.rs`:

```rust
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const INDEX_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IndexEntry {
    pub namespace: String,
    pub var: String,
    pub added_at: DateTime<Utc>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct IndexFile {
    #[serde(default = "default_version")]
    version: u32,
    #[serde(default, rename = "entry")]
    entries: Vec<IndexEntry>,
}

fn default_version() -> u32 {
    INDEX_VERSION
}

/// In-memory index, persisted to disk on `save`.
pub struct Index {
    path: PathBuf,
    file: IndexFile,
}

impl Index {
    /// Default location: `~/Library/Application Support/secrets/index.toml`.
    pub fn default_path() -> Result<PathBuf> {
        let base = dirs::data_dir()
            .ok_or_else(|| Error::Invalid("could not resolve OS data dir".into()))?;
        Ok(base.join("secrets").join("index.toml"))
    }

    /// Load from `path`. If the file does not exist, returns an empty index
    /// associated with that path (write-on-save).
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if !path.exists() {
            return Ok(Self {
                path,
                file: IndexFile {
                    version: INDEX_VERSION,
                    entries: vec![],
                },
            });
        }
        let text = std::fs::read_to_string(&path)?;
        let file: IndexFile =
            toml::from_str(&text).map_err(|e| Error::Toml(e.to_string()))?;
        if file.version != INDEX_VERSION {
            return Err(Error::Invalid(format!(
                "unsupported index version {} (expected {})",
                file.version, INDEX_VERSION
            )));
        }
        Ok(Self { path, file })
    }

    pub fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let text = toml::to_string_pretty(&self.file)
            .map_err(|e| Error::Toml(e.to_string()))?;
        std::fs::write(&self.path, text)?;
        Ok(())
    }

    pub fn add(&mut self, namespace: &str, var: &str) {
        let exists = self
            .file
            .entries
            .iter()
            .any(|e| e.namespace == namespace && e.var == var);
        if !exists {
            self.file.entries.push(IndexEntry {
                namespace: namespace.to_string(),
                var: var.to_string(),
                added_at: Utc::now(),
            });
        }
    }

    pub fn remove(&mut self, namespace: &str, var: &str) {
        self.file
            .entries
            .retain(|e| !(e.namespace == namespace && e.var == var));
    }

    pub fn vars_in(&self, namespace: &str) -> Vec<String> {
        let mut v: Vec<String> = self
            .file
            .entries
            .iter()
            .filter(|e| e.namespace == namespace)
            .map(|e| e.var.clone())
            .collect();
        v.sort();
        v.dedup();
        v
    }

    pub fn namespaces(&self) -> Vec<String> {
        use std::collections::BTreeSet;
        let nses: BTreeSet<String> = self
            .file
            .entries
            .iter()
            .map(|e| e.namespace.clone())
            .collect();
        nses.into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn fresh_index() -> (Index, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("index.toml");
        let idx = Index::load(&path).unwrap();
        (idx, dir)
    }

    #[test]
    fn load_nonexistent_yields_empty() {
        let (idx, _d) = fresh_index();
        assert!(idx.namespaces().is_empty());
    }

    #[test]
    fn add_then_list_roundtrips() {
        let (mut idx, _d) = fresh_index();
        idx.add("cognis", "API_KEY");
        idx.add("cognis", "DB_URL");
        idx.add("shopify", "TOKEN");
        assert_eq!(idx.namespaces(), vec!["cognis", "shopify"]);
        assert_eq!(idx.vars_in("cognis"), vec!["API_KEY", "DB_URL"]);
        assert_eq!(idx.vars_in("shopify"), vec!["TOKEN"]);
    }

    #[test]
    fn add_is_idempotent() {
        let (mut idx, _d) = fresh_index();
        idx.add("ns", "K");
        idx.add("ns", "K");
        assert_eq!(idx.vars_in("ns"), vec!["K"]);
    }

    #[test]
    fn remove_drops_entry() {
        let (mut idx, _d) = fresh_index();
        idx.add("ns", "K");
        idx.add("ns", "L");
        idx.remove("ns", "K");
        assert_eq!(idx.vars_in("ns"), vec!["L"]);
    }

    #[test]
    fn save_then_load_roundtrips() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("index.toml");
        {
            let mut idx = Index::load(&path).unwrap();
            idx.add("cognis", "X");
            idx.save().unwrap();
        }
        let idx = Index::load(&path).unwrap();
        assert_eq!(idx.vars_in("cognis"), vec!["X"]);
    }

    #[test]
    fn unsupported_version_errors() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("index.toml");
        std::fs::write(&path, "version = 99\n").unwrap();
        let err = Index::load(&path).unwrap_err();
        assert!(matches!(err, Error::Invalid(_)));
    }
}
```

- [ ] **Step 2: Wire `index` module**

In `crates/secrets-core/src/lib.rs`, add:

```rust
pub mod error;
pub mod index;
pub mod secret_value;
pub mod vault;

pub use error::{Error, Result};
pub use index::Index;
pub use secret_value::SecretValue;
pub use vault::{InMemoryVault, Vault};
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p secrets-core`
Expected: 20 tests pass (14 prior + 6 new index tests).

- [ ] **Step 4: Commit**

```bash
git add crates/secrets-core/src/lib.rs crates/secrets-core/src/index.rs
git commit -m "M1: TOML-backed Index for namespace/var listing"
```

---

## Task 6: `KeychainVault` (macOS) — set/get/delete + listing via Index

**Files:**
- Create: `crates/secrets-core/src/vault/keychain.rs`
- Modify: `crates/secrets-core/src/vault/mod.rs` (uncomment the `keychain` lines)
- Modify: `crates/secrets-core/src/lib.rs` (uncomment `KeychainVault` re-export)

This task introduces real macOS API calls. Set/get/delete map directly to `security_framework::passwords::*`. Listing reads from the local `Index` from Task 5. The unit tests for set/get/delete are gated with `#[ignore]` so plain `cargo test` does not touch the real Keychain — run them locally with `cargo test --ignored`.

- [ ] **Step 1: Implement `KeychainVault`**

Create `crates/secrets-core/src/vault/keychain.rs`:

```rust
use security_framework::passwords::{
    delete_generic_password, get_generic_password, set_generic_password,
};

use crate::{
    error::{Error, Result},
    index::Index,
    secret_value::SecretValue,
    vault::Vault,
};

const SERVICE_PREFIX: &str = "secrets.";

/// macOS Keychain-backed Vault. Stores values as Generic Password items
/// under service `secrets.<namespace>` and account `<VAR>`.
///
/// Listing operations read from a local `Index` because Keychain search
/// has an awkward Rust API surface; the Index is updated on every
/// `set`/`delete` and persisted to disk.
pub struct KeychainVault {
    index: Index,
}

impl KeychainVault {
    /// Open with the default index location:
    /// `~/Library/Application Support/secrets/index.toml`.
    pub fn open_default() -> Result<Self> {
        let path = Index::default_path()?;
        let index = Index::load(&path)?;
        Ok(Self { index })
    }

    /// Open with a custom index path. Used in tests.
    pub fn open_with_index(index: Index) -> Self {
        Self { index }
    }

    fn service(namespace: &str) -> String {
        format!("{}{}", SERVICE_PREFIX, namespace)
    }

    fn map_sf_err(e: security_framework::base::Error, namespace: &str, var: &str) -> Error {
        // -25300 = errSecItemNotFound
        if e.code() == -25300 {
            return Error::NotFound {
                namespace: namespace.to_string(),
                var: var.to_string(),
            };
        }
        Error::Keychain(format!("{} (code {})", e, e.code()))
    }
}

impl Vault for KeychainVault {
    fn set(&mut self, namespace: &str, var: &str, value: SecretValue) -> Result<()> {
        if namespace.is_empty() || var.is_empty() {
            return Err(Error::Invalid(
                "namespace and var must be non-empty".into(),
            ));
        }
        let service = Self::service(namespace);
        set_generic_password(&service, var, value.expose())
            .map_err(|e| Self::map_sf_err(e, namespace, var))?;
        self.index.add(namespace, var);
        self.index.save()?;
        Ok(())
    }

    fn get(&self, namespace: &str, var: &str) -> Result<SecretValue> {
        let service = Self::service(namespace);
        let bytes = get_generic_password(&service, var)
            .map_err(|e| Self::map_sf_err(e, namespace, var))?;
        Ok(SecretValue::new(bytes))
    }

    fn delete(&mut self, namespace: &str, var: &str) -> Result<()> {
        let service = Self::service(namespace);
        match delete_generic_password(&service, var) {
            Ok(()) => {
                self.index.remove(namespace, var);
                self.index.save()?;
                Ok(())
            }
            Err(e) => Err(Self::map_sf_err(e, namespace, var)),
        }
    }

    fn list_vars(&self, namespace: &str) -> Result<Vec<String>> {
        Ok(self.index.vars_in(namespace))
    }

    fn list_namespaces(&self) -> Result<Vec<String>> {
        Ok(self.index.namespaces())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret_value::SecretValue;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tempfile::tempdir;

    /// Per-test unique namespace so concurrent test runs don't collide.
    fn unique_namespace() -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("test.secrets.m1.{}", nanos)
    }

    /// Build a KeychainVault using a tempdir-backed Index so we don't
    /// pollute the user's real index file during tests.
    fn fresh_vault() -> (KeychainVault, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let idx_path = dir.path().join("index.toml");
        let index = Index::load(&idx_path).unwrap();
        (KeychainVault::open_with_index(index), dir)
    }

    fn cleanup(v: &mut KeychainVault, ns: &str, vars: &[&str]) {
        for var in vars {
            let _ = v.delete(ns, var);
        }
    }

    #[test]
    #[ignore = "writes to real Keychain; run with --ignored"]
    fn set_get_roundtrip_in_real_keychain() {
        let (mut v, _d) = fresh_vault();
        let ns = unique_namespace();

        v.set(&ns, "FOO", SecretValue::from_string("bar".into()))
            .expect("set");
        let got = v.get(&ns, "FOO").expect("get");
        assert_eq!(got.expose(), b"bar");

        cleanup(&mut v, &ns, &["FOO"]);
    }

    #[test]
    #[ignore = "writes to real Keychain; run with --ignored"]
    fn get_missing_returns_not_found() {
        let (v, _d) = fresh_vault();
        let ns = unique_namespace();
        let err = v.get(&ns, "MISSING").unwrap_err();
        assert!(matches!(err, Error::NotFound { .. }), "got {:?}", err);
    }

    #[test]
    #[ignore = "writes to real Keychain; run with --ignored"]
    fn set_overwrites_value() {
        let (mut v, _d) = fresh_vault();
        let ns = unique_namespace();

        v.set(&ns, "K", SecretValue::from_string("v1".into()))
            .unwrap();
        v.set(&ns, "K", SecretValue::from_string("v2".into()))
            .unwrap();
        assert_eq!(v.get(&ns, "K").unwrap().expose(), b"v2");

        cleanup(&mut v, &ns, &["K"]);
    }

    #[test]
    #[ignore = "writes to real Keychain; run with --ignored"]
    fn delete_removes_then_get_is_not_found() {
        let (mut v, _d) = fresh_vault();
        let ns = unique_namespace();

        v.set(&ns, "K", SecretValue::from_string("v".into()))
            .unwrap();
        v.delete(&ns, "K").unwrap();
        assert!(matches!(
            v.get(&ns, "K").unwrap_err(),
            Error::NotFound { .. }
        ));
    }

    #[test]
    #[ignore = "writes to real Keychain; run with --ignored"]
    fn list_via_index_after_set() {
        let (mut v, _d) = fresh_vault();
        let ns = unique_namespace();

        v.set(&ns, "Z", SecretValue::from_string("z".into()))
            .unwrap();
        v.set(&ns, "A", SecretValue::from_string("a".into()))
            .unwrap();

        assert_eq!(v.list_vars(&ns).unwrap(), vec!["A", "Z"]);
        assert!(v.list_namespaces().unwrap().contains(&ns));

        cleanup(&mut v, &ns, &["A", "Z"]);
    }

    #[test]
    fn empty_inputs_rejected() {
        let (mut v, _d) = fresh_vault();
        assert!(matches!(
            v.set("", "X", SecretValue::from_string("v".into())).unwrap_err(),
            Error::Invalid(_)
        ));
        assert!(matches!(
            v.set("ns", "", SecretValue::from_string("v".into())).unwrap_err(),
            Error::Invalid(_)
        ));
    }
}
```

- [ ] **Step 2: Re-enable the `keychain` module**

Edit `crates/secrets-core/src/vault/mod.rs` — uncomment the macOS-gated lines so it reads:

```rust
use crate::{error::Result, secret_value::SecretValue};

pub mod memory;

#[cfg(target_os = "macos")]
pub mod keychain;

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
```

- [ ] **Step 3: Re-enable the `KeychainVault` re-export**

Edit `crates/secrets-core/src/lib.rs` — uncomment the macOS-gated re-export so it reads:

```rust
pub mod error;
pub mod index;
pub mod secret_value;
pub mod vault;

pub use error::{Error, Result};
pub use index::Index;
pub use secret_value::SecretValue;
pub use vault::{InMemoryVault, Vault};

#[cfg(target_os = "macos")]
pub use vault::KeychainVault;
```

- [ ] **Step 4: Run non-ignored tests first**

Run: `cargo test -p secrets-core`
Expected: 21 tests pass (20 prior + 1 new `empty_inputs_rejected`). Five `#[ignore]`d tests are listed as ignored.

- [ ] **Step 5: Run the ignored tests against the real Keychain**

Run: `cargo test -p secrets-core -- --ignored`
Expected: 5 ignored tests run and pass. macOS will prompt for Keychain access on the first run; allow it (one prompt, persisted thereafter).

If a test fails because of leftover Keychain entries from a previous failed run, clean up manually:

```bash
security delete-generic-password -s "secrets.test.secrets.m1.<timestamp>" 2>/dev/null
```

You generally won't need this — `unique_namespace()` makes each run independent.

- [ ] **Step 6: Commit**

```bash
git add crates/secrets-core/src/lib.rs crates/secrets-core/src/vault/
git commit -m "M1: KeychainVault with index-backed listing"
```

---

## Task 7: CLI scaffolding (clap, subcommand routing, `ui` stub)

**Files:**
- Create: `crates/secrets/src/cli.rs`
- Create: `crates/secrets/src/commands/mod.rs`
- Modify: `crates/secrets/src/main.rs`

- [ ] **Step 1: Define the `clap` CLI**

Create `crates/secrets/src/cli.rs`:

```rust
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "secrets",
    version,
    about = "Local-first secrets vault (macOS Keychain).",
    long_about = None,
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Add or overwrite a secret. Prompts for the value (hidden).
    Add {
        /// Namespace (e.g. project name).
        namespace: String,
        /// Variable name (e.g. ANTHROPIC_API_KEY).
        var: String,
    },

    /// List namespaces, or variables within a single namespace.
    List {
        /// If provided, list variables in this namespace.
        namespace: Option<String>,
    },

    /// Print a secret to stdout. Use `secrets reveal <ns> <var>`.
    Reveal {
        namespace: String,
        var: String,
    },

    /// Open the desktop UI. Not yet implemented (M5).
    Ui,
}
```

- [ ] **Step 2: Create the empty commands module**

Create `crates/secrets/src/commands/mod.rs`:

```rust
pub mod add;
pub mod list;
pub mod reveal;
```

The submodule files (`add.rs`, `list.rs`, `reveal.rs`) come in Tasks 8–10. For now, create three stub files so the workspace compiles:

`crates/secrets/src/commands/add.rs`:

```rust
use secrets_core::{Result, SecretValue, Vault};

pub fn run(_vault: &mut dyn Vault, _namespace: &str, _var: &str, _value: SecretValue) -> Result<()> {
    unimplemented!("Task 8")
}
```

`crates/secrets/src/commands/list.rs`:

```rust
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
```

`crates/secrets/src/commands/reveal.rs`:

```rust
use secrets_core::{Result, SecretValue, Vault};

pub fn run(_vault: &dyn Vault, _namespace: &str, _var: &str) -> Result<SecretValue> {
    unimplemented!("Task 10")
}
```

- [ ] **Step 3: Wire `main.rs`**

Replace `crates/secrets/src/main.rs`:

```rust
mod cli;
mod commands;

use anyhow::{Context, Result};
use clap::Parser;
use cli::{Cli, Command};
use dialoguer::Password;
use secrets_core::{KeychainVault, SecretValue, Vault};

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Add { namespace, var } => {
            let value = Password::new()
                .with_prompt(format!("Value for secrets.{}/{}", namespace, var))
                .interact()
                .context("reading value")?;
            let mut vault = KeychainVault::open_default().context("opening Keychain vault")?;
            commands::add::run(&mut vault, &namespace, &var, SecretValue::from_string(value))
                .with_context(|| format!("storing secrets.{}/{}", namespace, var))?;
            println!("✓ Stored secrets.{}/{}", namespace, var);
        }

        Command::List { namespace } => {
            let vault = KeychainVault::open_default().context("opening Keychain vault")?;
            match namespace {
                None => {
                    let summaries = commands::list::namespaces(&vault)?;
                    if summaries.is_empty() {
                        println!("(no namespaces)");
                    } else {
                        for s in summaries {
                            println!("{:<20} {} vars", s.namespace, s.var_count);
                        }
                    }
                }
                Some(ns) => {
                    let vars = commands::list::vars(&vault, &ns)?;
                    if vars.is_empty() {
                        println!("(no vars in namespace '{}')", ns);
                    } else {
                        for v in vars {
                            println!("{}", v);
                        }
                    }
                }
            }
        }

        Command::Reveal { namespace, var } => {
            let vault = KeychainVault::open_default().context("opening Keychain vault")?;
            let value = commands::reveal::run(&vault, &namespace, &var)
                .with_context(|| format!("reading secrets.{}/{}", namespace, var))?;
            // Write raw bytes to stdout; safe for binary values.
            use std::io::Write;
            std::io::stdout().write_all(value.expose())?;
        }

        Command::Ui => {
            eprintln!("`secrets ui` not yet implemented (planned for M5).");
            std::process::exit(2);
        }
    }

    Ok(())
}
```

- [ ] **Step 4: Verify build and `--help`**

Run: `cargo build`
Expected: builds without error. The `unimplemented!()` stubs are fine; they only blow up at runtime.

Run: `cargo run --bin secrets -- --help`
Expected: prints the four subcommands.

Run: `cargo run --bin secrets -- ui`
Expected: prints `\`secrets ui\` not yet implemented (planned for M5).` and exits with code 2.

- [ ] **Step 5: Commit**

```bash
git add crates/secrets/src/
git commit -m "M1: clap CLI scaffolding + ui stub"
```

---

## Task 8: `secrets add` command

**Files:**
- Modify: `crates/secrets/src/commands/add.rs`

- [ ] **Step 1: Write the failing test**

Replace `crates/secrets/src/commands/add.rs`:

```rust
use secrets_core::{Result, SecretValue, Vault};

/// Store `value` at `(namespace, var)`. Overwrites existing.
pub fn run(vault: &mut dyn Vault, namespace: &str, var: &str, value: SecretValue) -> Result<()> {
    vault.set(namespace, var, value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrets_core::InMemoryVault;

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
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p secrets`
Expected: 2 tests pass.

- [ ] **Step 3: Commit**

```bash
git add crates/secrets/src/commands/add.rs
git commit -m "M1: secrets add command + tests"
```

---

## Task 9: `secrets list` command

**Files:**
- Modify: `crates/secrets/src/commands/list.rs`

- [ ] **Step 1: Write the failing tests**

Replace `crates/secrets/src/commands/list.rs`:

```rust
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
        let shopify = summaries
            .iter()
            .find(|s| s.namespace == "shopify")
            .unwrap();
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
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p secrets`
Expected: 6 tests pass (2 from Task 8 + 4 new).

- [ ] **Step 3: Commit**

```bash
git add crates/secrets/src/commands/list.rs
git commit -m "M1: secrets list command + tests"
```

---

## Task 10: `secrets reveal` command

**Files:**
- Modify: `crates/secrets/src/commands/reveal.rs`

- [ ] **Step 1: Write the failing tests**

Replace `crates/secrets/src/commands/reveal.rs`:

```rust
use secrets_core::{Result, SecretValue, Vault};

/// Read the secret at `(namespace, var)` and return its value.
/// `Error::NotFound` if absent.
pub fn run(vault: &dyn Vault, namespace: &str, var: &str) -> Result<SecretValue> {
    vault.get(namespace, var)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrets_core::{Error, InMemoryVault};

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
        let err = run(&vault, "ghost", "X").unwrap_err();
        assert!(matches!(err, Error::NotFound { .. }));
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p secrets`
Expected: 8 tests pass.

- [ ] **Step 3: End-to-end smoke test against the real Keychain**

This step verifies the full CLI path. It writes a real Keychain item under a uniquely-named test namespace and cleans up afterward.

```bash
NS="m1smoke.$(date +%s)"

# add: pipe value via stdin (dialoguer reads from /dev/tty by default,
# so we use --help paths and the security CLI for the smoke check).
# Easiest: use `security` to write directly, then verify our binary reads it.
security add-generic-password -U -a "TEST_VAR" -s "secrets.${NS}" -w "smoke-value"

# list namespaces — note: our list reads the local index, which won't
# know about secrets that bypassed `secrets add`. Instead, test that
# `reveal` finds the value (it queries Keychain directly).
cargo run --quiet --bin secrets -- reveal "$NS" "TEST_VAR"
# Expected stdout: smoke-value

# clean up
security delete-generic-password -a "TEST_VAR" -s "secrets.${NS}"
```

Now test the full add → reveal flow through our binary. Because `dialoguer::Password` reads from a TTY, we can't pipe; do this manually:

```bash
NS="m1smoke2.$(date +%s)"
cargo run --bin secrets -- add "$NS" "MY_VAR"
# at the prompt, type: hello-world

cargo run --bin secrets -- list
# Expected: a line like  m1smoke2.<ts>    1 vars

cargo run --bin secrets -- list "$NS"
# Expected: MY_VAR

cargo run --bin secrets -- reveal "$NS" "MY_VAR"
# Expected: hello-world

# clean up
security delete-generic-password -a "MY_VAR" -s "secrets.${NS}"
# Also remove the index entry by editing ~/Library/Application\ Support/secrets/index.toml
# or run a follow-up: cargo run --bin secrets -- list  (entry will linger; this is the
# documented Index drift trade-off and gets revisited in M3).
```

If everything matches, M1 is functional end-to-end.

- [ ] **Step 4: Commit**

```bash
git add crates/secrets/src/commands/reveal.rs
git commit -m "M1: secrets reveal command + tests"
```

---

## Task 11: M1 release tag

**Files:** none — git operation only.

- [ ] **Step 1: Final test pass**

Run: `cargo test`
Expected: all non-ignored tests pass.

Run: `cargo test -- --ignored`
Expected: all `KeychainVault` integration tests pass against the real Keychain.

Run: `cargo clippy --all-targets -- -D warnings`
Expected: no warnings. Fix any that appear before tagging.

Run: `cargo fmt --check`
Expected: no diff. Run `cargo fmt` to fix if needed and commit the result.

- [ ] **Step 2: Tag**

```bash
git tag -a m1 -m "M1: skeleton + minimal CLI (add/list/reveal)"
```

(No `git push` — per user preference, push only on explicit request.)

---

## Self-review

**Spec coverage check (against §10 of the design doc, M1 milestone):**

| Spec requirement | Implemented in |
|---|---|
| Cargo workspace: secrets-core, secrets-cli, (secrets-ui stub) | Task 1 (workspace + two crates); UI is a `Command::Ui` stub in Task 7 returning exit code 2 — kept the binary count at one rather than introducing a separate `secrets-ui` crate, deviating from the spec to avoid premature scaffolding. |
| Vault trait + InMemoryVault + KeychainVault | Tasks 4 (trait + InMemoryVault) and 6 (KeychainVault). |
| CLI: add, list, reveal (no ACLs, no manifest yet) | Tasks 7 (clap), 8 (add), 9 (list), 10 (reveal). |
| Unit tests against InMemoryVault | Tasks 4, 8, 9, 10 each include `#[cfg(test)]` blocks against `InMemoryVault`. |
| Ship state: usable as an envchain replacement | M1 produces a working `secrets add/list/reveal` CLI; runtime injection (`secrets run`) is M2 and is explicitly out of scope here. The "envchain replacement" framing in the spec is loose — what M1 actually replaces is the `envchain --set / envchain --list` set of commands, not `envchain <namespace> <cmd>`. Documented in the plan's "Out of scope for M1" header. |

One material deviation from the spec is logged: I introduced a local TOML `Index` (Task 5) rather than using Keychain search APIs for listing. The spec didn't dictate either approach, but the design doc's data model section (§6) does mention `projects.toml` in the same data dir; the Index is a precursor that will subsume into that file in M2. Noted in the Task 5 preamble.

**Placeholder scan:** No `TBD` / `TODO` / "implement later" / "add appropriate error handling" left in the plan. Step 4 of Task 2 contains a comment in source code marked as "documentation only — leave the comment in place" — that's intentional, not a placeholder.

**Type consistency:** Verified `Vault` trait method signatures are identical across:
- Task 4 (definition in `vault/mod.rs`)
- Task 4 (impl in `memory.rs`)
- Task 6 (impl in `keychain.rs`)

Verified `commands::*` function signatures match between:
- Task 7 (stubs)
- Tasks 8–10 (implementations)
- `main.rs` (call sites)

`SecretValue` API used consistently: `from_string`, `expose`, `len`, `is_empty`, `new`. No drift.

`Error` variants used consistently: `NotFound { namespace, var }`, `Invalid(String)`, `Keychain(String)`, `Toml(String)`, `Io(...)`.

---

*Next step: choose execution mode (subagent-driven vs inline) — see handoff below.*
