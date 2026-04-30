use std::path::{Path, PathBuf};

use chrono::Utc;
use rusqlite::{params, Connection};

use crate::error::{Error, Result};

const SCHEMA_VERSION: i64 = 1;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY NOT NULL
);

CREATE TABLE IF NOT EXISTS accesses (
    id           INTEGER PRIMARY KEY,
    ts           TEXT    NOT NULL,
    namespace    TEXT    NOT NULL,
    var_names    TEXT    NOT NULL,
    binary_path  TEXT    NOT NULL,
    binary_hash  TEXT,
    pid          INTEGER,
    ppid         INTEGER,
    argv         TEXT,
    outcome      TEXT    NOT NULL,
    reason       TEXT,
    duration_ms  INTEGER,
    child_exit   INTEGER
);
CREATE INDEX IF NOT EXISTS idx_accesses_ts        ON accesses(ts);
CREATE INDEX IF NOT EXISTS idx_accesses_namespace ON accesses(namespace);
"#;

pub type AuditRowId = i64;

/// Outcome of a single `stowe run` invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Allowed,
    Denied,
    BiometricFailed,
}

impl Outcome {
    fn as_str(&self) -> &'static str {
        match self {
            Outcome::Allowed => "allowed",
            Outcome::Denied => "denied",
            Outcome::BiometricFailed => "biometric_failed",
        }
    }
}

/// Information captured at run start.
#[derive(Debug, Clone)]
pub struct OpenRun<'a> {
    pub namespace: &'a str,
    pub var_names: &'a [String],
    pub binary_path: &'a str,
    pub binary_hash: Option<&'a str>,
    pub pid: Option<u32>,
    pub ppid: Option<u32>,
    pub argv: &'a [String],
    pub outcome: Outcome,
    pub reason: Option<&'a str>,
}

/// Information captured at run close.
#[derive(Debug, Clone, Copy, Default)]
pub struct CloseRun {
    pub duration_ms: Option<i64>,
    pub child_exit: Option<i32>,
}

/// SQLite-backed audit log.
pub struct Audit {
    conn: Connection,
}

impl Audit {
    /// Default location: `~/Library/Application Support/stowe/audit.db`.
    pub fn default_path() -> Result<PathBuf> {
        let base = dirs::data_dir()
            .ok_or_else(|| Error::Invalid("could not resolve OS data dir".into()))?;
        Ok(base.join("stowe").join("audit.db"))
    }

    pub fn open_default() -> Result<Self> {
        let path = Self::default_path()?;
        Self::open_at(path)
    }

    pub fn open_at(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)
            .map_err(|e| Error::Database(format!("opening audit db: {}", e)))?;

        // WAL mode: better write throughput, readers don't block writers.
        // Set BEFORE first INSERT for it to apply.
        conn.pragma_update(None, "journal_mode", "wal")
            .map_err(|e| Error::Database(format!("setting WAL mode: {}", e)))?;

        conn.execute_batch(SCHEMA)
            .map_err(|e| Error::Database(format!("creating audit schema: {}", e)))?;

        // Schema version: insert v1 if absent; reject if a newer version is recorded.
        let existing_version: Option<i64> = conn
            .query_row("SELECT version FROM schema_version", [], |row| row.get(0))
            .ok();
        match existing_version {
            None => {
                conn.execute(
                    "INSERT INTO schema_version (version) VALUES (?1)",
                    params![SCHEMA_VERSION],
                )
                .map_err(|e| Error::Database(format!("recording schema version: {}", e)))?;
            }
            Some(v) if v == SCHEMA_VERSION => { /* same version — OK */ }
            Some(v) => {
                return Err(Error::Database(format!(
                    "audit DB schema version {} is newer than supported version {}",
                    v, SCHEMA_VERSION
                )));
            }
        }

        Ok(Self { conn })
    }

    /// Insert a row marking the start of a run. Returns the row id, which
    /// must be passed to `close_run` after the child exits.
    pub fn open_run(&self, info: &OpenRun<'_>) -> Result<AuditRowId> {
        let ts = Utc::now().to_rfc3339();
        let var_names_json = serde_json::to_string(info.var_names)
            .map_err(|e| Error::Database(format!("serializing var_names: {}", e)))?;
        let argv_json = serde_json::to_string(info.argv)
            .map_err(|e| Error::Database(format!("serializing argv: {}", e)))?;
        self.conn
            .execute(
                "INSERT INTO accesses
                 (ts, namespace, var_names, binary_path, binary_hash,
                  pid, ppid, argv, outcome, reason)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    ts,
                    info.namespace,
                    var_names_json,
                    info.binary_path,
                    info.binary_hash,
                    info.pid,
                    info.ppid,
                    argv_json,
                    info.outcome.as_str(),
                    info.reason,
                ],
            )
            .map_err(|e| Error::Database(format!("inserting audit row: {}", e)))?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Update an existing row with run-completion info.
    pub fn close_run(&self, id: AuditRowId, close: CloseRun) -> Result<()> {
        let updated = self
            .conn
            .execute(
                "UPDATE accesses SET duration_ms = ?1, child_exit = ?2 WHERE id = ?3",
                params![close.duration_ms, close.child_exit, id],
            )
            .map_err(|e| Error::Database(format!("updating audit row: {}", e)))?;
        if updated == 0 {
            return Err(Error::Database(format!(
                "audit row {} not found for close",
                id
            )));
        }
        Ok(())
    }

    /// Convenience: open and immediately close a row marking a denial.
    /// Used when binary verification rejects an invocation before any
    /// child process is spawned.
    pub fn write_denial(
        &self,
        namespace: &str,
        binary_path: &str,
        argv: &[String],
        reason: &str,
    ) -> Result<AuditRowId> {
        let info = OpenRun {
            namespace,
            var_names: &[],
            binary_path,
            binary_hash: None,
            pid: Some(std::process::id()),
            ppid: None,
            argv,
            outcome: Outcome::Denied,
            reason: Some(reason),
        };
        let id = self.open_run(&info)?;
        // Close immediately — denial means no child was spawned.
        self.close_run(
            id,
            CloseRun {
                duration_ms: Some(0),
                child_exit: None,
            },
        )?;
        Ok(id)
    }

    /// Total number of rows. Used in tests across crates; hidden from rustdoc.
    #[doc(hidden)]
    pub fn row_count(&self) -> Result<i64> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM accesses", [], |row| row.get(0))
            .map_err(|e| Error::Database(format!("counting audit rows: {}", e)))?;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn fresh_audit() -> (Audit, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.db");
        (Audit::open_at(&path).unwrap(), dir)
    }

    fn sample_open<'a>(vars: &'a [String], argv: &'a [String]) -> OpenRun<'a> {
        OpenRun {
            namespace: "cognis",
            var_names: vars,
            binary_path: "/bin/echo",
            binary_hash: None,
            pid: Some(42),
            ppid: Some(41),
            argv,
            outcome: Outcome::Allowed,
            reason: None,
        }
    }

    #[test]
    fn open_creates_schema_idempotently() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.db");
        let _a1 = Audit::open_at(&path).unwrap();
        let a2 = Audit::open_at(&path).unwrap();
        assert_eq!(a2.row_count().unwrap(), 0);
    }

    #[test]
    fn open_run_inserts_row_and_returns_id() {
        let (a, _d) = fresh_audit();
        let vars = vec!["FOO".to_string(), "BAR".to_string()];
        let argv = vec!["echo".to_string(), "hi".to_string()];
        let id = a.open_run(&sample_open(&vars, &argv)).unwrap();
        assert!(id > 0);
        assert_eq!(a.row_count().unwrap(), 1);
    }

    #[test]
    fn close_run_updates_row() {
        let (a, _d) = fresh_audit();
        let vars = vec!["FOO".to_string()];
        let argv = vec!["echo".to_string()];
        let id = a.open_run(&sample_open(&vars, &argv)).unwrap();
        a.close_run(
            id,
            CloseRun {
                duration_ms: Some(123),
                child_exit: Some(0),
            },
        )
        .unwrap();
        let (dur, exit): (i64, i32) = a
            .conn
            .query_row(
                "SELECT duration_ms, child_exit FROM accesses WHERE id = ?1",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(dur, 123);
        assert_eq!(exit, 0);
    }

    #[test]
    fn close_run_unknown_id_errors() {
        let (a, _d) = fresh_audit();
        let err = a.close_run(9999, CloseRun::default()).unwrap_err();
        assert!(matches!(err, Error::Database(msg) if msg.contains("not found")));
    }

    #[test]
    fn outcome_as_str() {
        assert_eq!(Outcome::Allowed.as_str(), "allowed");
        assert_eq!(Outcome::Denied.as_str(), "denied");
        assert_eq!(Outcome::BiometricFailed.as_str(), "biometric_failed");
    }

    #[test]
    fn json_columns_round_trip() {
        let (a, _d) = fresh_audit();
        let vars = vec!["A".to_string(), "B".to_string()];
        let argv = vec!["x".to_string(), "y".to_string(), "z".to_string()];
        let id = a.open_run(&sample_open(&vars, &argv)).unwrap();
        let (vn, av): (String, String) = a
            .conn
            .query_row(
                "SELECT var_names, argv FROM accesses WHERE id = ?1",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let parsed_vn: Vec<String> = serde_json::from_str(&vn).unwrap();
        let parsed_av: Vec<String> = serde_json::from_str(&av).unwrap();
        assert_eq!(parsed_vn, vars);
        assert_eq!(parsed_av, argv);
    }

    #[test]
    fn write_denial_creates_closed_denied_row() {
        let (a, _d) = fresh_audit();
        let argv = vec!["evil".to_string(), "--steal".to_string()];
        let id = a
            .write_denial("ns", "/tmp/evil", &argv, "binary not allowed")
            .unwrap();
        assert!(id > 0);
        assert_eq!(a.row_count().unwrap(), 1);
        let (outcome, reason, child_exit): (String, String, Option<i32>) = a
            .conn
            .query_row(
                "SELECT outcome, reason, child_exit FROM accesses WHERE id = ?1",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(outcome, "denied");
        assert_eq!(reason, "binary not allowed");
        assert_eq!(child_exit, None);
    }
}
