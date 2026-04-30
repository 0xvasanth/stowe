import { invoke } from "@tauri-apps/api/core";

export interface NamespaceSummary {
  namespace: string;
  var_count: number;
}

export interface AuditRow {
  id: number;
  ts: string;
  namespace: string;
  var_names: string[];
  binary_path: string;
  argv: string[];
  outcome: string;
  reason: string | null;
  child_exit: number | null;
}

export async function listNamespaces(): Promise<NamespaceSummary[]> {
  return invoke<NamespaceSummary[]>("list_namespaces_cmd");
}

export async function listVars(namespace: string): Promise<string[]> {
  return invoke<string[]>("list_vars_cmd", { namespace });
}

export async function recentAccesses(limit = 25): Promise<AuditRow[]> {
  return invoke<AuditRow[]>("recent_accesses_cmd", { limit });
}
