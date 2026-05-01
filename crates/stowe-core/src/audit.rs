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

#[derive(Debug, Clone, Default)]
pub struct AuditFilter {
    pub namespace: Option<String>,
    pub outcome: Option<String>,
    pub limit: i64,
}

#[derive(Debug, Clone)]
pub struct AccessRow {
    pub id: i64,
    pub ts: String,
    pub namespace: String,
    pub var_names: Vec<String>,
    pub binary_path: String,
    pub binary_hash: Option<String>,
    pub pid: Option<i64>,
    pub argv: Vec<String>,
    pub outcome: String,
    pub reason: Option<String>,
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

    /// Delete every row in the audit log. Returns the number of rows deleted.
    /// Used by `wipe::wipe_all` when `also_audit` is true.
    pub fn truncate(&self) -> Result<i64> {
        let n = self.row_count()?;
        self.conn
            .execute("DELETE FROM accesses", [])
            .map_err(|e| Error::Database(format!("truncating accesses: {}", e)))?;
        Ok(n)
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

    /// Query the audit log with optional filters. Returns rows in
    /// descending id order (most recent first).
    pub fn list_filtered(&self, filter: &AuditFilter) -> Result<Vec<AccessRow>> {
        let limit = filter.limit.clamp(1, 1000);
        let mut sql = String::from(
            "SELECT id, ts, namespace, var_names, binary_path, binary_hash,
                    pid, argv, outcome, reason, duration_ms, child_exit
             FROM accesses WHERE 1=1",
        );
        let mut bound: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        if let Some(ns) = &filter.namespace {
            sql.push_str(" AND namespace = ?");
            bound.push(Box::new(ns.clone()));
        }
        if let Some(out) = &filter.outcome {
            sql.push_str(" AND outcome = ?");
            bound.push(Box::new(out.clone()));
        }
        sql.push_str(" ORDER BY id DESC LIMIT ?");
        bound.push(Box::new(limit));

        let mut stmt = self
            .conn
            .prepare(&sql)
            .map_err(|e| Error::Database(format!("preparing audit query: {}", e)))?;
        let param_refs: Vec<&dyn rusqlite::ToSql> = bound.iter().map(|p| p.as_ref()).collect();
        let rows = stmt
            .query_map(rusqlite::params_from_iter(param_refs), |row| {
                let var_names_json: String = row.get(3)?;
                let argv_json: String = row.get(7)?;
                Ok(AccessRow {
                    id: row.get(0)?,
                    ts: row.get(1)?,
                    namespace: row.get(2)?,
                    var_names: serde_json::from_str(&var_names_json).unwrap_or_default(),
                    binary_path: row.get(4)?,
                    binary_hash: row.get(5)?,
                    pid: row.get(6)?,
                    argv: serde_json::from_str(&argv_json).unwrap_or_default(),
                    outcome: row.get(8)?,
                    reason: row.get(9)?,
                    duration_ms: row.get(10)?,
                    child_exit: row.get(11)?,
                })
            })
            .map_err(|e| Error::Database(format!("running audit query: {}", e)))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| Error::Database(format!("decoding audit row: {}", e)))?);
        }
        Ok(out)
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

    #[test]
    fn list_filtered_returns_all_with_no_filters() {
        let (a, _d) = fresh_audit();
        let vars = vec!["X".to_string()];
        let argv = vec!["echo".to_string()];
        for _ in 0..3 {
            a.open_run(&sample_open(&vars, &argv)).unwrap();
        }
        let rows = a
            .list_filtered(&AuditFilter {
                namespace: None,
                outcome: None,
                limit: 100,
            })
            .unwrap();
        assert_eq!(rows.len(), 3);
    }

    #[test]
    fn list_filtered_namespace_filter() {
        let (a, _d) = fresh_audit();
        let vars = vec!["X".to_string()];
        let argv = vec!["echo".to_string()];
        for _ in 0..2 {
            a.open_run(&OpenRun {
                namespace: "alpha",
                var_names: &vars,
                binary_path: "/bin/echo",
                binary_hash: None,
                pid: Some(1),
                ppid: None,
                argv: &argv,
                outcome: Outcome::Allowed,
                reason: None,
            })
            .unwrap();
        }
        a.open_run(&OpenRun {
            namespace: "beta",
            var_names: &vars,
            binary_path: "/bin/echo",
            binary_hash: None,
            pid: Some(1),
            ppid: None,
            argv: &argv,
            outcome: Outcome::Allowed,
            reason: None,
        })
        .unwrap();

        let alpha = a
            .list_filtered(&AuditFilter {
                namespace: Some("alpha".into()),
                outcome: None,
                limit: 100,
            })
            .unwrap();
        assert_eq!(alpha.len(), 2);
        assert!(alpha.iter().all(|r| r.namespace == "alpha"));
    }

    #[test]
    fn list_filtered_outcome_filter() {
        let (a, _d) = fresh_audit();
        let vars = vec!["X".to_string()];
        let argv = vec!["echo".to_string()];
        a.open_run(&sample_open(&vars, &argv)).unwrap();
        a.write_denial("ns", "/tmp/bad", &argv, "test").unwrap();

        let denied = a
            .list_filtered(&AuditFilter {
                namespace: None,
                outcome: Some("denied".into()),
                limit: 100,
            })
            .unwrap();
        assert_eq!(denied.len(), 1);
        assert_eq!(denied[0].outcome, "denied");
    }

    #[test]
    fn list_filtered_limit_clamps() {
        let (a, _d) = fresh_audit();
        let vars = vec!["X".to_string()];
        let argv = vec!["echo".to_string()];
        for _ in 0..5 {
            a.open_run(&sample_open(&vars, &argv)).unwrap();
        }
        let rows = a
            .list_filtered(&AuditFilter {
                namespace: None,
                outcome: None,
                limit: 2,
            })
            .unwrap();
        assert_eq!(rows.len(), 2);
    }
}
