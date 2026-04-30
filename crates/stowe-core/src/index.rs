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

#[derive(Debug, Serialize, Deserialize)]
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
#[derive(Debug)]
pub struct Index {
    path: PathBuf,
    file: IndexFile,
}

impl Index {
    /// Default location: `~/Library/Application Support/stowe/index.toml`.
    pub fn default_path() -> Result<PathBuf> {
        let base = dirs::data_dir()
            .ok_or_else(|| Error::Invalid("could not resolve OS data dir".into()))?;
        Ok(base.join("stowe").join("index.toml"))
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
        let file: IndexFile = toml::from_str(&text).map_err(|e| Error::Toml(e.to_string()))?;
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
        let text = toml::to_string_pretty(&self.file).map_err(|e| Error::Toml(e.to_string()))?;
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
