import { useEffect, useState } from "react";
import { recentAccesses, type AuditRow } from "../tauri";

export function AuditFeed() {
  const [rows, setRows] = useState<AuditRow[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    recentAccesses(25)
      .then(setRows)
      .catch((e) => setError(String(e)));
    const id = setInterval(() => {
      recentAccesses(25)
        .then(setRows)
        .catch(() => {});
    }, 5000);
    return () => clearInterval(id);
  }, []);

  if (error) return <div className="audit-feed error">Error: {error}</div>;
  if (rows === null) return <div className="audit-feed loading">Loading…</div>;
  if (rows.length === 0)
    return <div className="audit-feed empty">No recent activity.</div>;

  return (
    <div className="audit-feed">
      <h3>Recent activity</h3>
      <ul>
        {rows.map((r) => (
          <li
            key={r.id}
            className={r.outcome === "denied" ? "denied" : "allowed"}
          >
            <span className="ts">{shortTs(r.ts)}</span>
            <span className="bin">{shortPath(r.binary_path)}</span>
            <span className="ns">{r.namespace}</span>
            <span className="vars">
              {r.var_names.length === 0 ? "—" : r.var_names.join(", ")}
            </span>
            <span className="outcome">{r.outcome}</span>
            {r.reason && <span className="reason">{r.reason}</span>}
          </li>
        ))}
      </ul>
    </div>
  );
}

function shortTs(iso: string): string {
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  return d.toLocaleTimeString();
}

function shortPath(path: string): string {
  const parts = path.split("/");
  return parts[parts.length - 1] || path;
}
