//! Tauri commands invoked by the frontend. Read-only in M5a.

use serde::Serialize;
use stowe_core::{Audit, KeychainVault};

#[derive(Serialize)]
pub struct NamespaceSummary {
    pub namespace: String,
    pub var_count: usize,
}

#[derive(Serialize)]
pub struct AuditRow {
    pub id: i64,
    pub ts: String,
    pub namespace: String,
    pub var_names: Vec<String>,
    pub binary_path: String,
    pub argv: Vec<String>,
    pub outcome: String,
    pub reason: Option<String>,
    pub child_exit: Option<i32>,
}

#[tauri::command]
pub fn list_namespaces_cmd() -> Result<Vec<NamespaceSummary>, String> {
    let vault = KeychainVault::open_default().map_err(|e| e.to_string())?;
    let nses = stowe_core::Vault::list_namespaces(&vault).map_err(|e| e.to_string())?;
    let mut out = Vec::with_capacity(nses.len());
    for ns in nses {
        let count = stowe_core::Vault::list_vars(&vault, &ns)
            .map_err(|e| e.to_string())?
            .len();
        out.push(NamespaceSummary {
            namespace: ns,
            var_count: count,
        });
    }
    Ok(out)
}

#[tauri::command]
pub fn list_vars_cmd(namespace: String) -> Result<Vec<String>, String> {
    let vault = KeychainVault::open_default().map_err(|e| e.to_string())?;
    stowe_core::Vault::list_vars(&vault, &namespace).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn recent_accesses_cmd(limit: i64) -> Result<Vec<AuditRow>, String> {
    // Ensure the audit DB exists / schema is migrated.
    let _audit = Audit::open_default().map_err(|e| e.to_string())?;
    let limit = limit.clamp(1, 1000);
    let path = stowe_core::Audit::default_path().map_err(|e| e.to_string())?;
    let conn = rusqlite::Connection::open(&path).map_err(|e| e.to_string())?;
    let mut stmt = conn
        .prepare(
            "SELECT id, ts, namespace, var_names, binary_path, argv,
                    outcome, reason, child_exit
             FROM accesses
             ORDER BY id DESC
             LIMIT ?1",
        )
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([limit], |row| {
            let var_names_json: String = row.get(3)?;
            let argv_json: String = row.get(5)?;
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                var_names_json,
                row.get::<_, String>(4)?,
                argv_json,
                row.get::<_, String>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, Option<i32>>(8)?,
            ))
        })
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for r in rows {
        let (id, ts, namespace, vn_json, binary_path, argv_json, outcome, reason, child_exit) =
            r.map_err(|e| e.to_string())?;
        let var_names: Vec<String> = serde_json::from_str(&vn_json).unwrap_or_default();
        let argv: Vec<String> = serde_json::from_str(&argv_json).unwrap_or_default();
        out.push(AuditRow {
            id,
            ts,
            namespace,
            var_names,
            binary_path,
            argv,
            outcome,
            reason,
            child_exit,
        });
    }
    Ok(out)
}

#[tauri::command]
pub fn reveal_secret_cmd(namespace: String, var: String) -> Result<String, String> {
    let vault = KeychainVault::open_default().map_err(|e| e.to_string())?;
    let value = stowe_core::Vault::get(&vault, &namespace, &var).map_err(|e| e.to_string())?;
    // The frontend treats this as a string. UTF-8-only secrets are supported
    // (matches the runner's existing constraint).
    std::str::from_utf8(value.expose())
        .map(|s| s.to_string())
        .map_err(|_| {
            "secret contains non-UTF-8 bytes; binary secrets cannot be revealed in the UI"
                .to_string()
        })
}

#[tauri::command]
pub fn add_secret_cmd(
    namespace: String,
    var: String,
    value: String,
    biometric: String,
) -> Result<(), String> {
    let mode = match biometric.as_str() {
        "always" => stowe_core::BiometricMode::Always,
        "never" => stowe_core::BiometricMode::Never,
        other => return Err(format!("unknown biometric mode: {}", other)),
    };
    let mut vault = KeychainVault::open_default().map_err(|e| e.to_string())?;
    vault
        .set_with_biometric(
            &namespace,
            &var,
            stowe_core::SecretValue::from_string(value),
            mode,
        )
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn delete_secret_cmd(namespace: String, var: String) -> Result<(), String> {
    let mut vault = KeychainVault::open_default().map_err(|e| e.to_string())?;
    stowe_core::Vault::delete(&mut vault, &namespace, &var).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn export_vault_cmd(
    namespaces: Vec<String>,
    format: String,
    passphrase: Option<String>,
    path: String,
) -> Result<(), String> {
    let format = match format.as_str() {
        "encrypted" => stowe_core::ExportFormat::Encrypted,
        "env" => stowe_core::ExportFormat::EnvPlain,
        other => return Err(format!("unknown export format: {}", other)),
    };
    let vault = KeychainVault::open_default().map_err(|e| e.to_string())?;
    stowe_core::export::export_to_path(
        &vault,
        &namespaces,
        format,
        passphrase.as_deref(),
        std::path::Path::new(&path),
    )
    .map_err(|e| e.to_string())
}

#[derive(Serialize)]
pub struct WipeReportDto {
    pub namespaces_deleted: usize,
    pub vars_deleted: usize,
    pub audit_rows_deleted: i64,
}

#[tauri::command]
pub fn wipe_all_cmd(also_audit: bool) -> Result<WipeReportDto, String> {
    let mut vault = KeychainVault::open_default().map_err(|e| e.to_string())?;
    let audit = if also_audit {
        Some(Audit::open_default().map_err(|e| e.to_string())?)
    } else {
        None
    };
    let report = stowe_core::wipe::wipe_all(&mut vault, audit.as_ref(), also_audit)
        .map_err(|e| e.to_string())?;
    Ok(WipeReportDto {
        namespaces_deleted: report.namespaces_deleted,
        vars_deleted: report.vars_deleted,
        audit_rows_deleted: report.audit_rows_deleted,
    })
}

#[derive(Serialize)]
pub struct AccessRowDto {
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

#[tauri::command]
pub fn audit_query_cmd(
    namespace: Option<String>,
    outcome: Option<String>,
    limit: i64,
) -> Result<Vec<AccessRowDto>, String> {
    let audit = Audit::open_default().map_err(|e| e.to_string())?;
    let filter = stowe_core::AuditFilter {
        namespace,
        outcome,
        limit,
    };
    let rows = audit.list_filtered(&filter).map_err(|e| e.to_string())?;
    Ok(rows
        .into_iter()
        .map(|r| AccessRowDto {
            id: r.id,
            ts: r.ts,
            namespace: r.namespace,
            var_names: r.var_names,
            binary_path: r.binary_path,
            binary_hash: r.binary_hash,
            pid: r.pid,
            argv: r.argv,
            outcome: r.outcome,
            reason: r.reason,
            duration_ms: r.duration_ms,
            child_exit: r.child_exit,
        })
        .collect())
}
