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

import { writeText } from "@tauri-apps/plugin-clipboard-manager";

export type BiometricMode = "always" | "never";

export async function revealSecret(
  namespace: string,
  variable: string,
): Promise<string> {
  return invoke<string>("reveal_secret_cmd", { namespace, var: variable });
}

export async function addSecret(
  namespace: string,
  variable: string,
  value: string,
  biometric: BiometricMode,
): Promise<void> {
  return invoke<void>("add_secret_cmd", {
    namespace,
    var: variable,
    value,
    biometric,
  });
}

export async function deleteSecret(
  namespace: string,
  variable: string,
): Promise<void> {
  return invoke<void>("delete_secret_cmd", { namespace, var: variable });
}

/**
 * Copy a string to the clipboard, then schedule a clear after `clearAfterMs`.
 * Returns a cancel function that, if called before timeout, prevents the clear.
 */
export function copyWithAutoClear(
  text: string,
  clearAfterMs = 30_000,
): () => void {
  void writeText(text);
  const id = window.setTimeout(() => {
    void writeText("");
  }, clearAfterMs);
  return () => window.clearTimeout(id);
}

/** Show only the last 4 characters of `value`, masking the rest with bullets. */
export function lastFour(value: string): string {
  if (value.length <= 4) return "•".repeat(value.length);
  return "•".repeat(value.length - 4) + value.slice(-4);
}
